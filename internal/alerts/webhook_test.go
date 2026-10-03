package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signedHeaders builds the svix-id/svix-timestamp/svix-signature headers
// Resend sends, the way Svix signs them.
func signedHeaders(secret []byte, id string, ts time.Time, body []byte) http.Header {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + tsStr + "."))
	mac.Write(body)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	h := http.Header{}
	h.Set("svix-id", id)
	h.Set("svix-timestamp", tsStr)
	h.Set("svix-signature", "v1,"+sig)
	return h
}

// signedRequest is a POST to the webhook, signed with secret.
func signedRequest(secret []byte, id string, ts time.Time, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/alerts/mail-events", bytes.NewReader(body))
	req.Header = signedHeaders(secret, id, ts, body)
	return req
}

func TestVerifySvixValidPasses(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"type":"email.bounced"}`)
	now := time.Now()
	h := signedHeaders(secret, "msg_1", now, body)
	err := VerifySvix(secret, h, body, now)
	if err != nil {
		t.Fatalf("VerifySvix: %v", err)
	}
}

func TestVerifySvixWrongSecret(t *testing.T) {
	body := []byte(`{"type":"email.bounced"}`)
	now := time.Now()
	h := signedHeaders([]byte("right-secret"), "msg_1", now, body)
	err := VerifySvix([]byte("wrong-secret"), h, body, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifySvixStaleTimestamp(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"type":"email.bounced"}`)
	now := time.Now()
	old := now.Add(-6 * time.Minute)
	h := signedHeaders(secret, "msg_1", old, body)
	err := VerifySvix(secret, h, body, now)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("err = %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifySvixBadTimestampFormatIsBadSignature(t *testing.T) {
	h := http.Header{}
	h.Set("svix-id", "msg_1")
	h.Set("svix-timestamp", "not-a-number")
	h.Set("svix-signature", "v1,abc")
	err := VerifySvix([]byte("test-secret"), h, []byte("{}"), time.Now())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature for an unparseable timestamp", err)
	}
}

func TestVerifySvixMissingHeaders(t *testing.T) {
	err := VerifySvix([]byte("test-secret"), http.Header{}, []byte("{}"), time.Now())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifySvixFutureSkewIsStale(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"type":"email.bounced"}`)
	now := time.Now()
	future := now.Add(6 * time.Minute)
	h := signedHeaders(secret, "msg_1", future, body)
	err := VerifySvix(secret, h, body, now)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("err = %v, want ErrStaleTimestamp for a future timestamp", err)
	}
}

// TestVerifySvixEmptySecretNeverVerifies covers the critical case: HMAC-SHA256
// with a zero-length key is a fixed value anyone can compute without ever
// seeing the real secret, so an empty Secret must never verify anything.
func TestVerifySvixEmptySecretNeverVerifies(t *testing.T) {
	body := []byte(`{"type":"email.bounced"}`)
	now := time.Now()
	h := signedHeaders(nil, "msg_1", now, body)
	err := VerifySvix(nil, h, body, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature for an empty secret", err)
	}
}

func TestDecodeSvixSecret(t *testing.T) {
	raw := []byte("abcdefghijklmnop")
	encoded := base64.StdEncoding.EncodeToString(raw)
	got, err := DecodeSvixSecret("whsec_" + encoded)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("DecodeSvixSecret = %x, %v", got, err)
	}
}

func TestDecodeSvixSecretInvalidBase64(t *testing.T) {
	_, err := DecodeSvixSecret("whsec_***not-base64***")
	if err == nil {
		t.Fatal("expected an error for invalid base64")
	}
}

// TestDecodeSvixSecretEmptyErrors covers the critical case: an empty or
// prefix-only secret must error rather than decode to a zero-length key.
func TestDecodeSvixSecretEmptyErrors(t *testing.T) {
	if _, err := DecodeSvixSecret(""); err == nil {
		t.Fatal("expected an error for an empty secret")
	}
	if _, err := DecodeSvixSecret("whsec_"); err == nil {
		t.Fatal("expected an error for a secret that is only the whsec_ prefix")
	}
}

func TestParseMailEvent(t *testing.T) {
	body := []byte(`{"type":"email.bounced","created_at":"2026-10-03T00:00:00Z","data":{"email_id":"msg_1","to":["ann@example.com"]}}`)
	e, err := ParseMailEvent(body)
	if err != nil {
		t.Fatalf("ParseMailEvent: %v", err)
	}
	if e.Type != "email.bounced" || len(e.To) != 1 || e.To[0] != "ann@example.com" {
		t.Fatalf("unexpected event %+v", e)
	}
}

func TestParseMailEventInvalidJSON(t *testing.T) {
	_, err := ParseMailEvent([]byte("not json"))
	if err == nil {
		t.Fatal("expected an error for invalid json")
	}
}

// TestParseMailEventToAsSingleString covers data.to sent as one address
// rather than a one-element array.
func TestParseMailEventToAsSingleString(t *testing.T) {
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":"ann@example.com"}}`)
	e, err := ParseMailEvent(body)
	if err != nil {
		t.Fatalf("ParseMailEvent: %v", err)
	}
	if len(e.To) != 1 || e.To[0] != "ann@example.com" {
		t.Fatalf("unexpected event %+v", e)
	}
}

// disableCall records one DisableChannel call the fake store saw.
type disableCall struct {
	userHash string
	kind     ChannelKind
	source   ChannelSource
	reason   string
}

// fakeWebhookStore is an in-memory WebhookStore for the handler's paths that
// do not need a real database.
type fakeWebhookStore struct {
	channels    map[string][]Channel // keyed by lower-cased address
	channelsErr error
	disableErr  error
	parkErr     error
	disabled    []disableCall
	parked      map[string]string // userHash -> reason
}

func newFakeWebhookStore() *fakeWebhookStore {
	return &fakeWebhookStore{channels: map[string][]Channel{}, parked: map[string]string{}}
}

func (f *fakeWebhookStore) ChannelByAddress(_ context.Context, _ ChannelKind, address string) ([]Channel, error) {
	if f.channelsErr != nil {
		return nil, f.channelsErr
	}
	return f.channels[strings.ToLower(address)], nil
}

func (f *fakeWebhookStore) DisableChannel(_ context.Context, userHash string, kind ChannelKind, source ChannelSource, reason string, _ time.Time) error {
	if f.disableErr != nil {
		return f.disableErr
	}
	f.disabled = append(f.disabled, disableCall{userHash, kind, source, reason})
	return nil
}

func (f *fakeWebhookStore) ParkEmailAlerts(_ context.Context, userHash, reason string) (int64, error) {
	if f.parkErr != nil {
		return 0, f.parkErr
	}
	f.parked[userHash] = reason
	return 1, nil
}

// ChannelFor answers as the store does, over the rows not disabled since.
func (f *fakeWebhookStore) ChannelFor(_ context.Context, userHash string, kind ChannelKind) (Channel, bool, error) {
	var best Channel
	found := false
	for _, rows := range f.channels {
		for _, c := range rows {
			off := slices.Contains(f.disabled, disableCall{c.UserHash, c.Kind, c.Source, ReasonBounced}) ||
				slices.Contains(f.disabled, disableCall{c.UserHash, c.Kind, c.Source, ReasonComplained})
			if c.UserHash != userHash || c.Kind != kind || c.DisabledAt != nil || off || (c.Source == SourceUser && c.VerifiedAt == nil) {
				continue
			}
			if !found || c.Source == SourceUser {
				best, found = c, true
			}
		}
	}
	return best, found, nil
}

// A bounce on a pending alternate address leaves mail on the working
// Patreon address, so nothing is parked.
func TestWebhookBounceOnPendingRowKeepsAlertsOnPatreon(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	now := time.Now()
	store.channels["typo@example.com"] = []Channel{{UserHash: "u1", Kind: ChannelEmail, Address: "typo@example.com", Source: SourceUser}}
	store.channels["ann@patreon.example"] = []Channel{{UserHash: "u1", Kind: ChannelEmail, Address: "ann@patreon.example", Source: SourcePatreon, VerifiedAt: &now}}
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["typo@example.com"]}}`)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, signedRequest(secret, "msg_1", now, body))
	if rec.Code != http.StatusOK || len(store.disabled) != 1 || store.disabled[0].source != SourceUser {
		t.Fatalf("status %d disabled %+v", rec.Code, store.disabled)
	}
	if len(store.parked) != 0 {
		t.Fatalf("parked %+v, want none", store.parked)
	}
}

// A complaint about B's address parks B, left with nothing, and not A, who
// typed B's address but still has a working Patreon one.
func TestWebhookComplaintParksOnlyTheUserLeftWithoutMail(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	now := time.Now()
	store.channels["b@example.com"] = []Channel{
		{UserHash: "uA", Kind: ChannelEmail, Address: "b@example.com", Source: SourceUser},
		{UserHash: "uB", Kind: ChannelEmail, Address: "b@example.com", Source: SourcePatreon, VerifiedAt: &now},
	}
	store.channels["a@example.com"] = []Channel{{UserHash: "uA", Kind: ChannelEmail, Address: "a@example.com", Source: SourcePatreon, VerifiedAt: &now}}
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.complained","data":{"email_id":"m1","to":["b@example.com"]}}`)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, signedRequest(secret, "msg_1", now, body))
	if rec.Code != http.StatusOK || len(store.disabled) != 2 {
		t.Fatalf("status %d disabled %+v", rec.Code, store.disabled)
	}
	if len(store.parked) != 1 || store.parked["uB"] != ParkComplained {
		t.Fatalf("parked %+v, want only uB", store.parked)
	}
}

func TestWebhookServeHTTPMethodNotAllowed(t *testing.T) {
	wh := &Webhook{Secret: []byte("s"), Store: newFakeWebhookStore()}
	req := httptest.NewRequest(http.MethodGet, "/alerts/mail-events", nil)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestWebhookServeHTTPNoSecretConfigured covers the critical case: a nil or
// empty Secret must refuse before reading the body, answering 503 and
// logging, not 401 as if a real secret had rejected a real signature.
func TestWebhookServeHTTPNoSecretConfigured(t *testing.T) {
	var logged []string
	wh := &Webhook{Store: newFakeWebhookStore(), Log: func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := httptest.NewRequest(http.MethodPost, "/alerts/mail-events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "webhook secret not configured") {
		t.Fatalf("logged = %+v, want one line mentioning webhook secret not configured", logged)
	}
}

func TestWebhookServeHTTPBadSignature(t *testing.T) {
	store := newFakeWebhookStore()
	wh := &Webhook{Secret: []byte("right-secret"), Store: store}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := signedRequest([]byte("wrong-secret"), "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebhookServeHTTPBadJSONAfterValidSignature(t *testing.T) {
	secret := []byte("s")
	wh := &Webhook{Secret: secret, Store: newFakeWebhookStore()}
	body := []byte("not json")
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestWebhookServeHTTPUnknownTypeDoesNothing(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	store.channels["ann@example.com"] = []Channel{{UserHash: "u1", Kind: ChannelEmail, Address: "ann@example.com", Source: SourceUser}}
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.delivered","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(store.disabled) != 0 || len(store.parked) != 0 {
		t.Fatalf("unknown type touched the store: disabled=%+v parked=%+v", store.disabled, store.parked)
	}
}

func TestWebhookServeHTTPUnknownAddressDoesNothing(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["nobody@example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(store.disabled) != 0 || len(store.parked) != 0 {
		t.Fatalf("unknown address touched the store: disabled=%+v parked=%+v", store.disabled, store.parked)
	}
}

func TestWebhookServeHTTPBouncedDisablesAndParksOnce(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	// Ann's address matches both her user and patreon channel rows; she
	// must still be parked once, not twice.
	store.channels["ann@example.com"] = []Channel{
		{UserHash: "u1", Kind: ChannelEmail, Address: "ann@example.com", Source: SourceUser},
		{UserHash: "u1", Kind: ChannelEmail, Address: "ann@example.com", Source: SourcePatreon},
	}
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(store.disabled) != 2 {
		t.Fatalf("disabled = %+v, want 2 rows", store.disabled)
	}
	for _, d := range store.disabled {
		if d.reason != "bounced" {
			t.Fatalf("disable reason = %q, want bounced", d.reason)
		}
	}
	if store.parked["u1"] != "email bounced" {
		t.Fatalf("parked = %+v, want u1 => email bounced", store.parked)
	}
}

func TestWebhookServeHTTPComplainedUsesItsOwnReasons(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	store.channels["bob@example.com"] = []Channel{{UserHash: "u2", Kind: ChannelEmail, Address: "bob@example.com", Source: SourceUser}}
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.complained","data":{"email_id":"m2","to":["bob@example.com"]}}`)
	req := signedRequest(secret, "msg_2", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(store.disabled) != 1 || store.disabled[0].reason != "complained" {
		t.Fatalf("disabled = %+v, want complained", store.disabled)
	}
	if store.parked["u2"] != "email marked as spam" {
		t.Fatalf("parked = %+v, want u2 => email marked as spam", store.parked)
	}
}

func TestWebhookServeHTTPStoreErrorAnswers500AndLogs(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	store.channels["ann@example.com"] = []Channel{{UserHash: "u1", Kind: ChannelEmail, Address: "ann@example.com", Source: SourceUser}}
	store.disableErr = errors.New("db down")
	var logged []string
	wh := &Webhook{Secret: secret, Store: store, Log: func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(logged) != 1 {
		t.Fatalf("logged = %+v, want one line", logged)
	}
}

// TestWebhookServeHTTPParkFailureThenRetrySucceeds covers a failure partway
// through handleAddress: DisableChannel succeeds but ParkEmailAlerts then
// fails, answering 500 so Svix retries; once the underlying failure clears,
// an identical retry completes. Re-running DisableChannel on the retry is
// itself idempotent at the real store (an UPDATE that changes nothing when
// the row is already disabled the same way); the fake just records the call
// again.
func TestWebhookServeHTTPParkFailureThenRetrySucceeds(t *testing.T) {
	secret := []byte("s")
	store := newFakeWebhookStore()
	store.channels["ann@example.com"] = []Channel{{UserHash: "u1", Kind: ChannelEmail, Address: "ann@example.com", Source: SourceUser}}
	store.parkErr = errors.New("db down")
	wh := &Webhook{Secret: secret, Store: store}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)

	req1 := signedRequest(secret, "msg_1", time.Now(), body)
	rec1 := httptest.NewRecorder()
	wh.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusInternalServerError {
		t.Fatalf("first attempt status = %d, want 500", rec1.Code)
	}
	if len(store.disabled) != 1 || store.disabled[0].reason != "bounced" {
		t.Fatalf("disable did not run before the park failure: %+v", store.disabled)
	}
	if len(store.parked) != 0 {
		t.Fatalf("park recorded despite failing: %+v", store.parked)
	}

	store.parkErr = nil
	req2 := signedRequest(secret, "msg_1", time.Now(), body)
	rec2 := httptest.NewRecorder()
	wh.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", rec2.Code)
	}
	if store.parked["u1"] != "email bounced" {
		t.Fatalf("retry did not park: %+v", store.parked)
	}
	if len(store.disabled) != 2 {
		t.Fatalf("disable not retried: %+v", store.disabled)
	}
}

// TestWebhookServeHTTPBounceDisablesAndParksDB is the DB test the brief
// describes: a real bounce for Ann disables her user and patreon email rows
// and parks her two active email alerts, while her Discord alert stays
// active; an unknown address and an unrelated event type change nothing.
func TestWebhookServeHTTPBounceDisablesAndParksDB(t *testing.T) {
	s := testStore(t)
	h := "webhook-ann"
	cleanUser(t, s, h)
	ctx := context.Background()
	must(t, s.UpsertContact(ctx, Contact{UserHash: h, Tier: "Legacy", DiscordKnown: true, DiscordUserID: "d1"}))
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "ann@example.com", Source: SourceUser, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "ann@example.com", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelDiscord, Address: "d1", Source: SourcePatreon, VerifiedAt: &now}))

	email1 := sample(h)
	email1.Delivery = DeliveryEmail
	a1, err := s.Create(ctx, email1)
	must(t, err)
	email2 := sample(h)
	email2.Delivery = DeliveryEmail
	a2, err := s.Create(ctx, email2)
	must(t, err)
	discordAlert, err := s.Create(ctx, sample(h))
	must(t, err)

	secret := []byte("db-test-secret")
	wh := &Webhook{Secret: secret, Store: s}

	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["ann@example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	chans, err := s.Channels(ctx, h)
	must(t, err)
	for _, c := range chans {
		switch c.Kind {
		case ChannelEmail:
			if c.DisabledReason != "bounced" || c.DisabledAt == nil {
				t.Fatalf("email channel not disabled: %+v", c)
			}
		case ChannelDiscord:
			if c.DisabledAt != nil {
				t.Fatalf("discord channel disabled: %+v", c)
			}
		}
	}

	got1, _, _ := s.Get(ctx, a1.ID, h)
	got2, _, _ := s.Get(ctx, a2.ID, h)
	if got1.Status != StatusUndeliverable || got1.LastError != "email bounced" {
		t.Fatalf("alert 1 not parked: %+v", got1)
	}
	if got2.Status != StatusUndeliverable || got2.LastError != "email bounced" {
		t.Fatalf("alert 2 not parked: %+v", got2)
	}
	gotDiscord, _, _ := s.Get(ctx, discordAlert.ID, h)
	if gotDiscord.Status != StatusActive {
		t.Fatalf("discord alert touched: %+v", gotDiscord)
	}

	// An unknown address changes nothing.
	body2 := []byte(`{"type":"email.bounced","data":{"email_id":"m2","to":["nobody@example.com"]}}`)
	req2 := signedRequest(secret, "msg_2", time.Now(), body2)
	rec2 := httptest.NewRecorder()
	wh.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}

	// email.delivered changes nothing.
	body3 := []byte(`{"type":"email.delivered","data":{"email_id":"m3","to":["ann@example.com"]}}`)
	req3 := signedRequest(secret, "msg_3", time.Now(), body3)
	rec3 := httptest.NewRecorder()
	wh.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec3.Code)
	}

	chansAfter, err := s.Channels(ctx, h)
	must(t, err)
	if len(chansAfter) != len(chans) {
		t.Fatalf("channel count changed: before=%d after=%d", len(chans), len(chansAfter))
	}
	for _, c := range chansAfter {
		if c.Kind == ChannelEmail && c.DisabledReason != "bounced" {
			t.Fatalf("email channel reason changed: %+v", c)
		}
	}
}

// TestWebhookServeHTTPBounceAcrossTwoUsersSharingAnAddressDB covers two
// distinct mtgban accounts that happen to share one email address (in
// different casing): a bounce for it must disable and park both, not just
// whichever channel row ChannelByAddress returns first, while each user's
// own Discord alert stays active.
func TestWebhookServeHTTPBounceAcrossTwoUsersSharingAnAddressDB(t *testing.T) {
	s := testStore(t)
	ha, hb := "webhook-shared-a", "webhook-shared-b"
	cleanUser(t, s, ha)
	cleanUser(t, s, hb)
	ctx := context.Background()
	must(t, s.UpsertContact(ctx, Contact{UserHash: ha, Tier: "Legacy", DiscordKnown: true, DiscordUserID: "da"}))
	must(t, s.UpsertContact(ctx, Contact{UserHash: hb, Tier: "Legacy", DiscordKnown: true, DiscordUserID: "db"}))
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: ha, Kind: ChannelEmail, Address: "Shared@Example.com", Source: SourceUser, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: hb, Kind: ChannelEmail, Address: "shared@example.com", Source: SourceUser, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: ha, Kind: ChannelDiscord, Address: "da", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: hb, Kind: ChannelDiscord, Address: "db", Source: SourcePatreon, VerifiedAt: &now}))

	emailA := sample(ha)
	emailA.Delivery = DeliveryEmail
	aEmail, err := s.Create(ctx, emailA)
	must(t, err)
	discordA, err := s.Create(ctx, sample(ha))
	must(t, err)

	emailB := sample(hb)
	emailB.Delivery = DeliveryEmail
	bEmail, err := s.Create(ctx, emailB)
	must(t, err)
	discordB, err := s.Create(ctx, sample(hb))
	must(t, err)

	secret := []byte("db-test-secret-2")
	wh := &Webhook{Secret: secret, Store: s}
	body := []byte(`{"type":"email.bounced","data":{"email_id":"m1","to":["SHARED@Example.com"]}}`)
	req := signedRequest(secret, "msg_1", time.Now(), body)
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	for _, h := range []string{ha, hb} {
		chans, err := s.Channels(ctx, h)
		must(t, err)
		for _, c := range chans {
			if c.Kind == ChannelEmail && (c.DisabledReason != "bounced" || c.DisabledAt == nil) {
				t.Fatalf("%s email channel not disabled: %+v", h, c)
			}
			if c.Kind == ChannelDiscord && c.DisabledAt != nil {
				t.Fatalf("%s discord channel disabled: %+v", h, c)
			}
		}
	}

	gotA, _, _ := s.Get(ctx, aEmail.ID, ha)
	if gotA.Status != StatusUndeliverable || gotA.LastError != "email bounced" {
		t.Fatalf("user a email alert not parked: %+v", gotA)
	}
	gotB, _, _ := s.Get(ctx, bEmail.ID, hb)
	if gotB.Status != StatusUndeliverable || gotB.LastError != "email bounced" {
		t.Fatalf("user b email alert not parked: %+v", gotB)
	}
	gotDiscordA, _, _ := s.Get(ctx, discordA.ID, ha)
	if gotDiscordA.Status != StatusActive {
		t.Fatalf("user a discord alert touched: %+v", gotDiscordA)
	}
	gotDiscordB, _, _ := s.Get(ctx, discordB.ID, hb)
	if gotDiscordB.Status != StatusActive {
		t.Fatalf("user b discord alert touched: %+v", gotDiscordB)
	}
}
