package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/mailer"
)

type verifiedCall struct {
	userHash string
	kind     alerts.ChannelKind
	source   alerts.ChannelSource
	address  string
}

type disabledCall struct {
	userHash string
	kind     alerts.ChannelKind
	source   alerts.ChannelSource
	reason   string
}

type parkedCall struct{ userHash, reason string }

// fakeLinkStore is the store behind the mail link pages and the webhook.
type fakeLinkStore struct {
	channels []alerts.Channel
	err      error
	verified []verifiedCall
	disabled []disabledCall
	parked   []parkedCall
}

func (f *fakeLinkStore) Channels(_ context.Context, userHash string) ([]alerts.Channel, error) {
	var out []alerts.Channel
	for _, c := range f.channels {
		if c.UserHash == userHash {
			out = append(out, c)
		}
	}
	return out, f.err
}

func (f *fakeLinkStore) SetChannelVerified(_ context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource, address string, at time.Time) (bool, error) {
	f.verified = append(f.verified, verifiedCall{userHash, kind, source, address})
	for i, c := range f.channels {
		if c.UserHash == userHash && c.Kind == kind && c.Source == source && strings.EqualFold(c.Address, address) {
			f.channels[i].VerifiedAt, f.channels[i].DisabledAt, f.channels[i].DisabledReason = &at, nil, ""
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeLinkStore) DisableChannel(_ context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource, reason string, at time.Time) error {
	f.disabled = append(f.disabled, disabledCall{userHash, kind, source, reason})
	for i, c := range f.channels {
		if c.UserHash == userHash && c.Kind == kind && c.Source == source {
			f.channels[i].DisabledAt, f.channels[i].DisabledReason = &at, reason
		}
	}
	return nil
}

func (f *fakeLinkStore) ParkEmailAlerts(_ context.Context, userHash, reason string) (int64, error) {
	f.parked = append(f.parked, parkedCall{userHash, reason})
	return 1, nil
}

// ChannelFor is the user's working email row, a verified user one first.
func (f *fakeLinkStore) ChannelFor(_ context.Context, userHash string, kind alerts.ChannelKind) (alerts.Channel, bool, error) {
	var best alerts.Channel
	found := false
	for _, c := range f.channels {
		if c.UserHash != userHash || c.Kind != kind || c.DisabledAt != nil || (c.Source == alerts.SourceUser && c.VerifiedAt == nil) {
			continue
		}
		if !found || c.Source == alerts.SourceUser {
			best, found = c, true
		}
	}
	return best, found, nil
}

func (f *fakeLinkStore) ChannelByAddress(_ context.Context, kind alerts.ChannelKind, address string) ([]alerts.Channel, error) {
	var out []alerts.Channel
	for _, c := range f.channels {
		if c.Kind == kind && strings.EqualFold(c.Address, address) {
			out = append(out, c)
		}
	}
	return out, nil
}

// mailLinkSetup renders pages from disk and keys tokens with a known secret.
func mailLinkSetup(t *testing.T) {
	t.Helper()
	withSigMode(t, true, false)
	t.Setenv("BAN_SECRET", "test-secret")
}

func confirmToken(userHash, address string, expires time.Time) string {
	return alerts.MintToken(alertTokenSecret(), alerts.Token{Kind: alerts.TokenConfirm, UserHash: userHash, Address: address, Expires: expires})
}

func pendingEmail(userHash, address string) alerts.Channel {
	at := time.Now()
	return alerts.Channel{UserHash: userHash, Kind: alerts.ChannelEmail, Address: address, Source: alerts.SourceUser, DisabledAt: &at, DisabledReason: "bounced"}
}

func TestAlertsConfirmVerifiesAndRenders(t *testing.T) {
	mailLinkSetup(t)
	store := &fakeLinkStore{channels: []alerts.Channel{pendingEmail("u1", "bob@example.com")}}
	token := confirmToken("u1", "Bob@Example.com", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/alerts/confirm?token="+url.QueryEscape(token), nil)
	rec := httptest.NewRecorder()
	testSite.alertsConfirm(rec, req, store)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), alertsConfirmedText) || !strings.Contains(rec.Body.String(), `href="/alerts"`) {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	if len(store.verified) != 1 || store.verified[0] != (verifiedCall{"u1", alerts.ChannelEmail, alerts.SourceUser, "bob@example.com"}) {
		t.Fatalf("verified %+v", store.verified)
	}
	if !store.channels[0].Active() {
		t.Fatalf("row not verified and enabled: %+v", store.channels[0])
	}
	// The same link again is still a success.
	rec = httptest.NewRecorder()
	testSite.alertsConfirm(rec, req, store)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), alertsConfirmedText) {
		t.Fatalf("second confirm = %d", rec.Code)
	}
}

func TestAlertsConfirmRefusesBadLinks(t *testing.T) {
	mailLinkSetup(t)
	future := time.Now().Add(time.Hour)
	good := confirmToken("u1", "bob@example.com", future)
	unsub := alerts.MintToken(alertTokenSecret(), alerts.Token{Kind: alerts.TokenUnsubscribe, UserHash: "u1", Address: "bob@example.com"})
	for _, tc := range []struct{ name, token, rowAddress string }{
		{"tampered", good[:len(good)-2] + "xx", "bob@example.com"},
		{"expired", confirmToken("u1", "bob@example.com", time.Now().Add(-time.Hour)), "bob@example.com"},
		{"wrong kind", unsub, "bob@example.com"},
		{"mismatched address", good, "new@example.com"},
		{"no user row", good, ""},
		{"missing", "", "bob@example.com"},
	} {
		store := &fakeLinkStore{}
		if tc.rowAddress != "" {
			store.channels = []alerts.Channel{pendingEmail("u1", tc.rowAddress)}
		}
		req := httptest.NewRequest(http.MethodGet, "/alerts/confirm?token="+url.QueryEscape(tc.token), nil)
		rec := httptest.NewRecorder()
		testSite.alertsConfirm(rec, req, store)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), alertsConfirmFailedText) {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
		if len(store.verified) != 0 {
			t.Errorf("%s: verified %+v", tc.name, store.verified)
		}
	}
}

// With no BAN_SECRET nothing verifies, not even a token signed with no key.
func TestAlertTokensRefusedWithoutSecret(t *testing.T) {
	store := &fakeLinkStore{channels: []alerts.Channel{pendingEmail("u1", "bob@example.com")}}
	token := alerts.MintToken(nil, alerts.Token{Kind: alerts.TokenConfirm, UserHash: "u1", Address: "bob@example.com"})
	err := confirmAlertEmail(context.Background(), store, nil, token, time.Now())
	if !errors.Is(err, alerts.ErrBadToken) {
		t.Fatalf("confirm without a secret = %v", err)
	}
	unsub := alerts.MintToken(nil, alerts.Token{Kind: alerts.TokenUnsubscribe, UserHash: "u1"})
	err = unsubscribeAlertEmail(context.Background(), store, []byte{}, unsub, time.Now())
	if !errors.Is(err, alerts.ErrBadToken) || len(store.parked) != 0 {
		t.Fatalf("unsubscribe without a secret = %v, parked %+v", err, store.parked)
	}
}

func TestAlertsUnsubscribeAsksOnGetActsOnPost(t *testing.T) {
	mailLinkSetup(t)
	at := time.Now()
	store := &fakeLinkStore{channels: []alerts.Channel{
		{UserHash: "u1", Kind: alerts.ChannelEmail, Address: "bob@example.com", Source: alerts.SourceUser, VerifiedAt: &at},
		{UserHash: "u1", Kind: alerts.ChannelEmail, Address: "bob@patreon.example", Source: alerts.SourcePatreon, VerifiedAt: &at},
		{UserHash: "u1", Kind: alerts.ChannelDiscord, Address: "77", Source: alerts.SourcePatreon, VerifiedAt: &at},
	}}
	link := alertUnsubscribeURL("https://lorcana.mtgban.com", "u1")
	if !strings.HasPrefix(link, "https://lorcana.mtgban.com/alerts/unsubscribe?token=") {
		t.Fatalf("link = %q", link)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("token")
	page := noSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { testSite.alertsUnsubscribe(w, r, store) }))

	// GET, as a link scanner would: the button, nothing changed.
	rec := httptest.NewRecorder()
	page.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, alertsUnsubscribeAskText) ||
		!strings.Contains(body, `action="/alerts/unsubscribe"`) || !strings.Contains(body, `value="`+token+`"`) {
		t.Fatalf("GET = %d %s", rec.Code, body)
	}
	if len(store.disabled) != 0 || len(store.parked) != 0 {
		t.Fatalf("GET acted: disabled %+v parked %+v", store.disabled, store.parked)
	}

	// One-click: a form POST to the List-Unsubscribe URL, no cookie, no CSRF token.
	req := httptest.NewRequest(http.MethodPost, u.RequestURI(), strings.NewReader("List-Unsubscribe=One-Click"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	page.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), alertsUnsubscribedText) {
		t.Fatalf("one-click POST = %d %s", rec.Code, rec.Body)
	}
	want := []disabledCall{
		{"u1", alerts.ChannelEmail, alerts.SourceUser, alerts.ReasonUnsubscribed},
		{"u1", alerts.ChannelEmail, alerts.SourcePatreon, alerts.ReasonUnsubscribed},
	}
	if !slices.Equal(store.disabled, want) {
		t.Fatalf("disabled %+v", store.disabled)
	}
	if len(store.parked) != 1 || store.parked[0] != (parkedCall{"u1", alerts.ParkUnsubscribed}) {
		t.Fatalf("parked %+v", store.parked)
	}

	// The button's POST, token in the body: nothing left to disable, still done.
	req = httptest.NewRequest(http.MethodPost, "/alerts/unsubscribe", strings.NewReader("token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	page.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), alertsUnsubscribedText) {
		t.Fatalf("second POST = %d", rec.Code)
	}
	if len(store.disabled) != 2 || len(store.parked) != 2 {
		t.Fatalf("second POST disabled %+v parked %+v", store.disabled, store.parked)
	}

	// A confirm token is not an unsubscribe token, by GET or POST.
	bad := url.QueryEscape(confirmToken("u1", "bob@example.com", time.Now().Add(time.Hour)))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec = httptest.NewRecorder()
		page.ServeHTTP(rec, httptest.NewRequest(method, "/alerts/unsubscribe?token="+bad, nil))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), alertsUnsubFailedText) {
			t.Fatalf("%s with a confirm token = %d", method, rec.Code)
		}
	}
	if len(store.parked) != 2 {
		t.Fatalf("bad token parked: %+v", store.parked)
	}
}

// Through the real mount: the token pages answer anonymous readers with
// their own handlers, and /alerts itself still demands a signature.
func TestAlertsMountServesTokenPagesUnsigned(t *testing.T) {
	signingEnabled(t, true)
	s := newSite()
	s.alerts.SetStore(&alerts.Store{})
	mux := http.NewServeMux()
	s.mountNav(mux, ExtraNavs["Alerts"])

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts/confirm?token=bad", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), alertsConfirmFailedText) {
		t.Fatalf("unsigned confirm = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts/unsubscribe?token=bad", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), alertsUnsubFailedText) {
		t.Fatalf("unsigned unsubscribe = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	if !strings.Contains(rec.Body.String(), ErrMsg) || strings.Contains(rec.Body.String(), "/js/alerts.js") {
		t.Fatalf("unsigned /alerts served the alerts page: %d", rec.Code)
	}
}

// Every registered page mounts, and an unsigned sub-page without a Handle
// of its own stops startup rather than serving its parent unsigned.
func TestMountNavRefusesUnsignedSubPageWithoutHandle(t *testing.T) {
	s := newSite()
	mux := http.NewServeMux()
	for _, nav := range ExtraNavs {
		s.mountNav(mux, nav)
	}
	bad := &NavElem{Name: "Bad", Link: "/bad", Handle: (*site).Alerts, SubPages: []NavElem{
		{Name: "BadSub", Link: "/bad/sub", NoSigning: true},
	}}
	defer func() {
		if recover() == nil {
			t.Fatal("an unsigned sub-page without a Handle was mounted")
		}
	}()
	s.mountNav(http.NewServeMux(), bad)
}

func svixRequest(secret []byte, body string, ts time.Time) *http.Request {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("msg_1." + tsStr + "." + body))
	req := httptest.NewRequest(http.MethodPost, "/alerts/mail-events", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("svix-id", "msg_1")
	req.Header.Set("svix-timestamp", tsStr)
	req.Header.Set("svix-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return req
}

func TestAlertsMailEventsReachTheStore(t *testing.T) {
	key := []byte("webhook-key")
	s := newSite()
	s.mailEventsSecret = decodeMailEventsSecret("whsec_" + base64.StdEncoding.EncodeToString(key))
	if !bytes.Equal(s.mailEventsSecret, key) {
		t.Fatalf("decoded secret = %q", s.mailEventsSecret)
	}
	at := time.Now()
	store := &fakeLinkStore{channels: []alerts.Channel{
		{UserHash: "u1", Kind: alerts.ChannelEmail, Address: "bob@example.com", Source: alerts.SourcePatreon, VerifiedAt: &at},
	}}
	body := `{"type":"email.bounced","data":{"email_id":"m1","to":["bob@example.com"]}}`

	rec := httptest.NewRecorder()
	unsigned := httptest.NewRequest(http.MethodPost, "/alerts/mail-events", strings.NewReader(body))
	s.alertsMailEvents(rec, unsigned, store)
	if rec.Code != http.StatusUnauthorized || len(store.disabled) != 0 {
		t.Fatalf("unsigned = %d, disabled %+v", rec.Code, store.disabled)
	}

	// Through noSigning, as routes.go mounts it: the JSON body survives its form read.
	rec = httptest.NewRecorder()
	hook := noSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.alertsMailEvents(w, r, store) }))
	hook.ServeHTTP(rec, svixRequest(key, body, time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed = %d", rec.Code)
	}
	if len(store.disabled) != 1 || store.disabled[0].reason != "bounced" || len(store.parked) != 1 {
		t.Fatalf("signed bounce: disabled %+v parked %+v", store.disabled, store.parked)
	}

	// No secret configured: every event is refused.
	if decodeMailEventsSecret("") != nil || decodeMailEventsSecret("whsec_!!") != nil {
		t.Fatal("unusable secret decoded")
	}
	rec = httptest.NewRecorder()
	(&site{}).alertsMailEvents(rec, svixRequest(key, body, time.Now()), store)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no secret = %d", rec.Code)
	}
}

// capturedMail records what the deliverer sends.
type capturedMail struct{ sent []mailer.Message }

func (c *capturedMail) Send(_ context.Context, m mailer.Message) (string, error) {
	c.sent = append(c.sent, m)
	return "id-1", nil
}

// The unsubscribe header points at the site the alert was saved on and
// carries a token the unsubscribe page accepts.
func TestAlertMailDelivererUnsubscribesOnTheAlertsSite(t *testing.T) {
	t.Setenv("BAN_SECRET", "test-secret")
	tpl, err := alerts.LoadMailTemplates("templates/mail")
	if err != nil {
		t.Fatal(err)
	}
	sink := &capturedMail{}
	d := originMailDeliverer{mail: alerts.MailDeliverer{Mailer: sink, Templates: tpl}}
	if d.Kind() != alerts.ChannelEmail {
		t.Fatalf("kind = %v", d.Kind())
	}
	a := alerts.Alert{
		ID: 1, UserHash: "u1", CardID: "c1", Side: alerts.SideBuylist, Condition: "NM",
		Card:  alerts.Card{Name: "Sol Ring", Set: "C21", Number: "263", Finish: "nonfoil"},
		Above: alerts.Threshold{Kind: alerts.KindAbs, Value: 1}, Origin: "https://lorcana.mtgban.com",
	}
	dg := alerts.Digest{UserHash: "u1", Firings: []alerts.Firing{{
		Alert: a, Origin: a.Origin, Decision: alerts.Decision{FireAbove: true, AboveHits: []alerts.Quote{{Store: "CK", Price: 1.5}}},
	}}}
	out := d.Deliver(context.Background(), dg, alerts.Channel{Address: "bob@example.com"}, func(s string) string { return s })
	if len(out) != 1 || out[0].Err != nil || len(sink.sent) != 1 {
		t.Fatalf("deliver = %+v, sent %d", out, len(sink.sent))
	}
	header := sink.sent[0].Headers["List-Unsubscribe"]
	link := strings.TrimSuffix(strings.TrimPrefix(header, "<"), ">")
	if !strings.HasPrefix(link, "https://lorcana.mtgban.com/alerts/unsubscribe?token=") {
		t.Fatalf("List-Unsubscribe = %q", header)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := verifyAlertToken(alertTokenSecret(), u.Query().Get("token"), alerts.TokenUnsubscribe, time.Now().Add(365*24*time.Hour))
	if err != nil || tok.UserHash != "u1" || !tok.Expires.IsZero() {
		t.Fatalf("unsubscribe token = %+v %v", tok, err)
	}
}

// A firing with no saved origin links to the site's own address, and a
// card with no image gets no empty img tag.
func TestAlertMailDelivererFillsAMissingOrigin(t *testing.T) {
	t.Setenv("BAN_SECRET", "test-secret")
	tpl, err := alerts.LoadMailTemplates("templates/mail")
	if err != nil {
		t.Fatal(err)
	}
	sink := &capturedMail{}
	d := originMailDeliverer{mail: alerts.MailDeliverer{Mailer: sink, Templates: tpl, Image: func(string) string { return "" }}}
	a := alerts.Alert{
		ID: 1, UserHash: "u1", CardID: "c1", Side: alerts.SideBuylist, Condition: "NM",
		Card:  alerts.Card{Name: "Sol Ring", Set: "C21", Number: "263", Finish: "nonfoil"},
		Above: alerts.Threshold{Kind: alerts.KindAbs, Value: 1},
	}
	firings := []alerts.Firing{{Alert: a, Decision: alerts.Decision{FireAbove: true, AboveHits: []alerts.Quote{{Store: "CK", Price: 1.5}}}}}
	out := d.Deliver(context.Background(), alerts.Digest{UserHash: "u1", Firings: firings}, alerts.Channel{Address: "bob@example.com"}, func(s string) string { return s })
	if len(out) != 1 || out[0].Err != nil || len(sink.sent) != 1 {
		t.Fatalf("deliver = %+v, sent %d", out, len(sink.sent))
	}
	html := sink.sent[0].HTML
	if !strings.Contains(html, `href="`+DefaultExternalURL+`/alerts"`) || strings.Contains(html, `<img src=""`) {
		t.Fatalf("html links or image wrong:\n%s", html)
	}
	if firings[0].Origin != "" {
		t.Fatal("the caller's firings were changed")
	}
}

func TestAlertConfirmMailCarriesTheLink(t *testing.T) {
	link := "https://mtgban.com/alerts/confirm?token=a.b&x=1"
	text, html := alertConfirmMail(link)
	if !strings.Contains(text, link) || !strings.Contains(html, `href="https://mtgban.com/alerts/confirm?token=a.b&amp;x=1"`) {
		t.Fatalf("text %q html %q", text, html)
	}
}
