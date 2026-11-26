package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/invites"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

const inviteTestACL = `{
	"Any": {"Search": {}},
	"Pioneer": {"Search": {"SearchDownloadCSV": "false"}},
	"Root": {"Search": {}, "Admin": {}}
}`

// fakeInviteStore keeps invites in memory, spending uses as the real store
// does and answering a repeated nonce from its first redemption.
type fakeInviteStore struct {
	invites   map[string]userstate.Invite
	redeemed  map[string]userstate.Redemption
	lookups   int
	redeems   int
	lastTiers []string
}

func newFakeInviteStore(invs ...userstate.Invite) *fakeInviteStore {
	f := &fakeInviteStore{invites: map[string]userstate.Invite{}, redeemed: map[string]userstate.Redemption{}}
	for _, inv := range invs {
		f.invites[inv.Code] = inv
	}
	return f
}

func (f *fakeInviteStore) InviteByCode(_ context.Context, code string) (userstate.Invite, error) {
	f.lookups++
	inv, ok := f.invites[code]
	if !ok {
		return userstate.Invite{}, userstate.ErrInviteNotFound
	}
	return inv, nil
}

func (f *fakeInviteStore) RedeemInvite(_ context.Context, in userstate.Redeem) (userstate.Redemption, error) {
	f.redeems++
	f.lastTiers = in.Tiers
	red, ok := f.redeemed[in.Code+"/"+in.Nonce]
	if ok {
		red.Repeat = true
		return red, nil
	}
	inv, ok := f.invites[in.Code]
	if !ok || inv.Uses >= inv.MaxUses || !slices.Contains(in.Tiers, inv.Tier) || !inv.RevokedAt.IsZero() || !time.Now().Before(inv.OpenUntil) {
		return userstate.Redemption{}, userstate.ErrInviteClosed
	}
	inv.Uses++
	f.invites[in.Code] = inv
	red = userstate.Redemption{
		ExpiresAt: time.Now().Add(time.Duration(inv.AccessDays) * 24 * time.Hour).Truncate(time.Second),
		Tier:      inv.Tier, Overrides: inv.Overrides, IP: in.IP, SignedIn: in.SignedIn,
	}
	f.redeemed[in.Code+"/"+in.Nonce] = red
	return red, nil
}

func testInvite(code string, maxUses int) userstate.Invite {
	return userstate.Invite{
		Code: code, Game: "magic", Tier: "Pioneer", MaxUses: maxUses, AccessDays: 7,
		OpenUntil: time.Now().Add(time.Hour),
		Overrides: map[string]map[string]string{"Newspaper": {"NewsLarge": "true"}},
	}
}

// inviteTestEnv signs with a test secret against inviteTestACL, in dev mode
// so pages render from disk, gives the page a fresh limiter, and captures
// the Admin log.
func inviteTestEnv(t *testing.T) *bytes.Buffer {
	t.Helper()
	signingEnabled(t, true)
	withACL(t, inviteTestACL)
	savedLimiter := inviteLimiter
	t.Cleanup(func() { inviteLimiter = savedLimiter })
	inviteLimiter = ratelimit.NewLimiter(1000, 1000)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	var logged bytes.Buffer
	LogPages["Admin"] = log.New(&logged, "", 0)
	return &logged
}

// serveInvite runs req through the wrapper mountNav puts an unsigned
// sub-page behind, with store standing in for the database.
func serveInvite(s *site, store inviteStore, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	noSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.invite(w, r, store)
	})).ServeHTTP(rec, req)
	return rec
}

func acceptRequest(code, nonce string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/invite/"+code, strings.NewReader(url.Values{"nonce": {nonce}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}

func signatureCookieOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var sig string
	n := 0
	for _, c := range rec.Result().Cookies() {
		if c.Name == signatureCookie {
			sig = c.Value
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d %s cookies set, want 1", n, signatureCookie)
	}
	return sig
}

func TestInviteRoutesAsAnUnsignedPrefix(t *testing.T) {
	s := newSite()
	mux := http.NewServeMux()
	s.mountNav(mux, ExtraNavs["Admin"])
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/invite/abcdefgh", nil))
	if pattern != "/invite/" {
		t.Fatalf("/invite/abcdefgh routes to %q", pattern)
	}
	if got := pageLabel("/invite/abcdefgh", ""); got != "invite" {
		t.Errorf("pageLabel = %q, want invite: the label must not carry the code", got)
	}
}

// Unfurlers and prefetchers open the link: a GET shows the invite and
// spends nothing, whatever state the invite is in.
func TestInviteGetSpendsNothing(t *testing.T) {
	inviteTestEnv(t)
	s := newSite()
	used := testInvite("bcdefghj", 1)
	used.Uses = 1
	store := newFakeInviteStore(testInvite("abcdefgh", 1), used)

	rec := serveInvite(s, store, httptest.NewRequest(http.MethodGet, "/invite/ABCDEFGH", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Accept invite") || !strings.Contains(body, "Pioneer") || !strings.Contains(body, "NewsLarge: true") {
		t.Fatalf("open invite = %d\n%s", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", rec.Header())
	}
	if strings.Contains(body, "You are signed in") {
		t.Error("an anonymous visitor was told they are signed in")
	}

	for _, path := range []string{"/invite/bcdefghj", "/invite/cdefghjk"} {
		rec = serveInvite(s, store, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), inviteClosedText) || strings.Contains(rec.Body.String(), "Accept invite") {
			t.Errorf("%s = %d", path, rec.Code)
		}
	}
	lookups := store.lookups
	rec = serveInvite(s, store, httptest.NewRequest(http.MethodGet, "/invite/not-a-code", nil))
	if rec.Code != http.StatusNotFound || store.lookups != lookups {
		t.Errorf("malformed code = %d, %d store lookups", rec.Code, store.lookups-lookups)
	}
	if store.redeems != 0 {
		t.Errorf("GETs redeemed %d times", store.redeems)
	}
}

func TestInviteWarnsASignedInVisitor(t *testing.T) {
	inviteTestEnv(t)
	s := newSite()
	store := newFakeInviteStore(testInvite("abcdefgh", 1))
	req := httptest.NewRequest(http.MethodGet, "/invite/abcdefgh", nil)
	req.AddCookie(&http.Cookie{Name: signatureCookie, Value: sign("Pioneer", &pledge.User{FullName: "Member", Email: "member@example.com", EmailVerified: true}, nil, time.Hour)})
	rec := serveInvite(s, store, req)
	if !strings.Contains(rec.Body.String(), "You are signed in") {
		t.Fatalf("no sign-out warning:\n%s", rec.Body)
	}
}

// Accepting signs the visitor in with the tier and the invite's extra
// pages, under no name, and a second visitor finds the invite used up.
func TestInviteAcceptSignsTheInvite(t *testing.T) {
	logged := inviteTestEnv(t)
	s := newSite()
	store := newFakeInviteStore(testInvite("abcdefgh", 1))
	nonce, _ := invites.NewNonce()

	rec := serveInvite(s, store, acceptRequest("abcdefgh", nonce))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("accept = %d %s", rec.Code, rec.Body)
	}
	sig := signatureCookieOf(t, rec)
	v, ok := signatureIsValid(sig)
	if !ok {
		t.Fatalf("minted signature does not verify: %s", sig)
	}
	if v.Get("Search") != "true" || v.Get("Newspaper") != "true" || v.Get("NewsLarge") != "true" || v.Get("UserEmail") != "" || v.Get("Admin") != "" {
		t.Errorf("signed %v", v)
	}
	expires, _ := strconv.ParseInt(v.Get("Expires"), 10, 64)
	if d := time.Until(time.Unix(expires, 0)); d < 6*24*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Errorf("signature lasts %v, want 7 days", d)
	}
	if want := []string{"Pioneer"}; !slices.Equal(store.lastTiers, want) {
		t.Errorf("allowed tiers %v, want %v", store.lastTiers, want)
	}
	if !strings.Contains(logged.String(), "Invite abc… accepted") || strings.Contains(logged.String(), "abcdefgh") {
		t.Errorf("admin log %q", logged)
	}

	other, _ := invites.NewNonce()
	rec = serveInvite(s, store, acceptRequest("abcdefgh", other))
	if rec.Code != http.StatusGone || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("second visitor = %d, cookies %v", rec.Code, rec.Result().Cookies())
	}
	if !strings.Contains(logged.String(), "Invite abc… refused") {
		t.Errorf("refusal not logged: %q", logged)
	}
}

// A double click posts the form twice: the second press signs the visitor
// in to the same expiry and spends nothing.
func TestInviteRepeatedPressReissues(t *testing.T) {
	logged := inviteTestEnv(t)
	s := newSite()
	store := newFakeInviteStore(testInvite("abcdefgh", 1))
	nonce, _ := invites.NewNonce()

	first := signatureCookieOf(t, serveInvite(s, store, acceptRequest("abcdefgh", nonce)))
	logged.Reset()
	rec := serveInvite(s, store, acceptRequest("abcdefgh", nonce))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("repeat = %d %s", rec.Code, rec.Body)
	}
	second := signatureCookieOf(t, rec)
	a, _ := strconv.ParseInt(GetParamFromSig(first, "Expires"), 10, 64)
	b, _ := strconv.ParseInt(GetParamFromSig(second, "Expires"), 10, 64)
	if a == 0 || b-a > 1 || a-b > 1 {
		t.Errorf("expires %d then %d", a, b)
	}
	if store.invites["abcdefgh"].Uses != 1 {
		t.Errorf("uses = %d, want 1", store.invites["abcdefgh"].Uses)
	}
	if logged.Len() != 0 {
		t.Errorf("a repeat was logged: %q", logged)
	}
}

func TestInviteRefuses(t *testing.T) {
	logged := inviteTestEnv(t)
	s := newSite()
	admin := testInvite("bcdefghj", 5)
	admin.Tier = "Root"
	store := newFakeInviteStore(testInvite("abcdefgh", 5), admin)
	nonce, _ := invites.NewNonce()

	crossSite := acceptRequest("abcdefgh", nonce)
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serveInvite(s, store, crossSite); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST = %d", rec.Code)
	}
	if rec := serveInvite(s, store, httptest.NewRequest(http.MethodPut, "/invite/abcdefgh", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d", rec.Code)
	}
	if rec := serveInvite(s, store, acceptRequest("abcdefgh", "bad")); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed nonce = %d", rec.Code)
	}
	// A tier given Admin since minting is not one an invite may sign.
	if rec := serveInvite(s, store, acceptRequest("bcdefghj", nonce)); rec.Code != http.StatusGone {
		t.Errorf("admin tier = %d", rec.Code)
	}
	logged.Reset()
	if rec := serveInvite(s, store, acceptRequest("cdefghjk", nonce)); rec.Code != http.StatusGone || logged.Len() != 0 {
		t.Errorf("unknown code = %d, logged %q", rec.Code, logged)
	}
	if store.invites["abcdefgh"].Uses != 0 {
		t.Errorf("refusals spent %d uses", store.invites["abcdefgh"].Uses)
	}
	if rec := serveInvite(s, nil, httptest.NewRequest(http.MethodGet, "/invite/abcdefgh", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("no store = %d", rec.Code)
	}

	inviteLimiter = ratelimit.NewLimiter(0, 1)
	for i, method := range []string{http.MethodGet, http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/invite/abcdefgh", nil)
		if method == http.MethodPost {
			req = acceptRequest("abcdefgh", nonce)
		}
		rec := serveInvite(s, store, req)
		if want := i == 0; (rec.Code != http.StatusTooManyRequests) != want {
			t.Errorf("press %d (%s) = %d", i, method, rec.Code)
		}
	}
}

// A phone gets the mobile shell around the invite's body.
func TestInvitePageOnAPhone(t *testing.T) {
	inviteTestEnv(t)
	s := newSite()
	store := newFakeInviteStore(testInvite("abcdefgh", 1))
	req := httptest.NewRequest(http.MethodGet, "/invite/abcdefgh", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")
	rec := serveInvite(s, store, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Accept invite") || !strings.Contains(rec.Body.String(), `class="light-theme mobile`) {
		t.Fatalf("phone = %d\n%s", rec.Code, rec.Body)
	}
}
