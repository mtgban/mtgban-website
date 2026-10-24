package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/mtgban/mtgban-website/internal/poke"
	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"
)

// webhookEmail is the member the sanitised deliveries in patreon/testdata
// name.
const webhookEmail = "patron@example.com"

// webhookFixture is a delivery Patreon's portal sent, sanitised.
func webhookFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("patreon/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// withWebhookSecret has the test's site check deliveries against secret.
func withWebhookSecret(t *testing.T, secret string) {
	t.Helper()
	saved := Config().Config.PatreonWebhookSecret
	t.Cleanup(func() { Config().Config.PatreonWebhookSecret = saved })
	Config().Config.PatreonWebhookSecret = secret
}

// webhookRequest is Patreon posting body, with the headers its delivery
// carries.
func webhookRequest(event, signature string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/webhook/patreon", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Patreon HTTP Robot")
	if event != "" {
		req.Header.Set("X-Patreon-Event", event)
	}
	if signature != "" {
		req.Header.Set("X-Patreon-Signature", signature)
	}
	return req
}

// serveWebhook runs req through the wrapper the route is registered behind.
func serveWebhook(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	noSigning(http.HandlerFunc(PatreonWebhook)).ServeHTTP(rec, req)
	return rec
}

// webhookRig is a site with a webhook secret, a poke window and a poke set of
// its own, and the admin log the webhook writes to.
type webhookRig struct {
	secret string
	pokes  *poke.Set
	logged *strings.Builder
}

func newWebhookRig(t *testing.T) *webhookRig {
	t.Helper()
	renewalConfig(t, renewalBlock, "client-id")
	withWebhookSecret(t, "hook-secret")
	return &webhookRig{secret: "hook-secret", pokes: freshPokes(t), logged: captureAdminLog(t)}
}

// deliver posts body signed under the rig's secret.
func (rig *webhookRig) deliver(event string, body []byte) *httptest.ResponseRecorder {
	return serveWebhook(webhookRequest(event, patreonSignature(rig.secret, body), body))
}

// wantNothingPoked fails if anyone is poked.
func (rig *webhookRig) wantNothingPoked(t *testing.T) {
	t.Helper()
	if rig.pokes.Len() != 0 {
		t.Errorf("poke set %v, want none poked", rig.pokes.Len())
	}
}

// A delivery whose signature checks out pokes its member and answers 200,
// whichever of the pledge events it is: the body's own verdict is not read.
func TestPatreonWebhookPokesTheMember(t *testing.T) {
	for _, tc := range []struct{ event, fixture string }{
		{"members:pledge:update", "webhook-pledge-update.json"},
		{"members:pledge:delete", "webhook-pledge-delete.json"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			rig := newWebhookRig(t)
			body := webhookFixture(t, tc.fixture)

			rec := rig.deliver(tc.event, body)
			if rec.Code != http.StatusOK {
				t.Errorf("status %d, want 200", rec.Code)
			}
			hash := userstate.HashEmail(webhookEmail)
			if !rig.pokes.Poked(hash, time.Now(), pokeWindow()) || rig.pokes.Len() != 1 {
				t.Errorf("poke set %v, want only %s", rig.pokes.Len(), webhookEmail)
			}
			want := "webhook: event=" + strconv.Quote(tc.event) + " email=" + strconv.Quote(webhookEmail)
			if !strings.Contains(rig.logged.String(), want) {
				t.Errorf("admin log %q, want the line %s", rig.logged.String(), want)
			}
		})
	}
}

// The email is lowercased and trimmed as the login does, so a member whose
// Patreon email is cased differently is poked all the same.
func TestPatreonWebhookPokesTheLowercasedEmail(t *testing.T) {
	rig := newWebhookRig(t)
	body := []byte(`{"data":{"attributes":{"email":"  Patron@Example.COM "}}}`)

	rec := rig.deliver("members:pledge:update", body)
	if rec.Code != http.StatusOK || !rig.pokes.Poked(userstate.HashEmail(webhookEmail), time.Now(), pokeWindow()) {
		t.Errorf("status %d, poke set %v; want 200 and %s poked", rec.Code, rig.pokes.Len(), webhookEmail)
	}
	if !strings.Contains(rig.logged.String(), "email="+strconv.Quote(webhookEmail)) {
		t.Errorf("admin log %q does not name the lowercased email", rig.logged.String())
	}
}

// A delivery that does not carry Patreon's signature changes nothing and
// reveals nothing: 401, one log line, and neither the body nor any signature in
// it. It is refused before the body is read, so a body that is not JSON is
// refused too.
func TestPatreonWebhookRefusesADeliveryItCannotVerify(t *testing.T) {
	body := webhookFixture(t, "webhook-pledge-update.json")
	for _, tc := range []struct {
		name      string
		signature func(rig *webhookRig) string
		body      []byte
	}{
		{"a wrong signature", func(*webhookRig) string { return strings.Repeat("ab", 16) }, body},
		{"no signature header", func(*webhookRig) string { return "" }, body},
		{"a signature that is not hex", func(*webhookRig) string { return "not-a-signature" }, body},
		{"a signature cut short", func(rig *webhookRig) string { return patreonSignature(rig.secret, body)[:30] }, body},
		{"a body signed under another secret", func(*webhookRig) string { return patreonSignature("another-secret", body) }, body},
		{"a signature of another body", func(rig *webhookRig) string { return patreonSignature(rig.secret, []byte("{}")) }, body},
		{"a body changed after signing", func(rig *webhookRig) string { return patreonSignature(rig.secret, body) }, append([]byte(" "), body...)},
		{"a SHA-256 signature", func(rig *webhookRig) string { return sha256Signed(rig.secret, body) }, body},
		{"a body that is not JSON", func(*webhookRig) string { return strings.Repeat("ab", 16) }, []byte("<html>")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWebhookRig(t)
			signature := tc.signature(rig)

			rec := serveWebhook(webhookRequest("members:pledge:update", signature, tc.body))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401", rec.Code)
			}
			rig.wantNothingPoked(t)
			logged := rig.logged.String()
			if strings.Count(logged, "\n") != 1 || !strings.Contains(logged, "webhook: signature") {
				t.Errorf("admin log %q, want the one line", logged)
			}
			if strings.Contains(logged, webhookEmail) || strings.Contains(logged, "campaign") || (signature != "" && strings.Contains(logged, signature)) {
				t.Errorf("admin log %q holds the body or the signature", logged)
			}
		})
	}
}

// The signature is the hex HMAC-MD5 of the body: RFC 2202's test case 2, whose
// answer no test here computes.
func TestPatreonSignatureIsHMACMD5(t *testing.T) {
	const vector = "750c783e6ab0b503eaa86e310a5db738"
	body := []byte("what do ya want for nothing?")
	if !patreonSignatureMatches("Jefe", body, vector) {
		t.Error("the HMAC-MD5 of RFC 2202's second case does not verify")
	}
	if !patreonSignatureMatches("Jefe", body, strings.ToUpper(vector)) {
		t.Error("the same signature in capitals does not verify")
	}
	if patreonSignatureMatches("Jefe", body, vector[:30]) || patreonSignatureMatches("Jefe", body, "") || patreonSignatureMatches("Jefa", body, vector) {
		t.Error("a short, empty or other-keyed signature verifies")
	}
	if patreonSignature("Jefe", body) != vector {
		t.Errorf("the signer gives %s, want RFC 2202's %s", patreonSignature("Jefe", body), vector)
	}
}

// Only a POST is a delivery.
func TestPatreonWebhookAnswersOnlyPosts(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rig := newWebhookRig(t)
			body := webhookFixture(t, "webhook-pledge-update.json")
			req := webhookRequest("members:pledge:update", patreonSignature(rig.secret, body), body)
			req.Method = method

			rec := serveWebhook(req)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
				t.Errorf("status %d, Allow %q; want 405 and POST", rec.Code, rec.Header().Get("Allow"))
			}
			rig.wantNothingPoked(t)
		})
	}
}

// A site with no webhook secret is not the receiver: the route answers 404 to
// everything, a delivery signed under the empty key included, which anyone can
// compute.
func TestPatreonWebhookIsOffWithoutASecret(t *testing.T) {
	rig := newWebhookRig(t)
	withWebhookSecret(t, "")
	body := webhookFixture(t, "webhook-pledge-update.json")

	for name, req := range map[string]*http.Request{
		"signed under the empty key": webhookRequest("members:pledge:update", patreonSignature("", body), body),
		"signed under a secret":      webhookRequest("members:pledge:update", patreonSignature("hook-secret", body), body),
		"unsigned":                   webhookRequest("members:pledge:update", "", body),
		"a GET":                      httptest.NewRequest(http.MethodGet, "/webhook/patreon", nil),
	} {
		rec := serveWebhook(req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, rec.Code)
		}
	}
	rig.wantNothingPoked(t)
	if rig.logged.Len() != 0 {
		t.Errorf("admin log %q, want nothing logged for a route that is off", rig.logged.String())
	}
}

// A signed body the handler cannot take an email from is answered 200, so
// Patreon does not retry it for good, logged, and pokes nobody.
func TestPatreonWebhookAnswers200ToABodyItCannotUse(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":                  "<html>",
		"empty":                     "",
		"truncated":                 `{"data":{"attributes":{"email":"patron@exa`,
		"no data":                   `{"included":[]}`,
		"no attributes":             `{"data":{"type":"member"}}`,
		"no email":                  `{"data":{"attributes":{"patron_status":"active_patron"}}}`,
		"a blank email":             `{"data":{"attributes":{"email":"  "}}}`,
		"an email that is null":     `{"data":{"attributes":{"email":null}}}`,
		"an email that is a number": `{"data":{"attributes":{"email":42}}}`,
		"data that is a list":       `{"data":[{"attributes":{"email":"patron@example.com"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			rig := newWebhookRig(t)

			rec := rig.deliver("members:pledge:create", []byte(body))
			if rec.Code != http.StatusOK {
				t.Errorf("status %d, want 200", rec.Code)
			}
			rig.wantNothingPoked(t)
			want := "webhook: event=" + strconv.Quote("members:pledge:create") + " carries no email"
			if !strings.Contains(rig.logged.String(), want) {
				t.Errorf("admin log %q, want the line %s", rig.logged.String(), want)
			}
			if body != "" && strings.Contains(rig.logged.String(), body) {
				t.Errorf("admin log %q holds the body", rig.logged.String())
			}
		})
	}
}

// Only the email is read: a body whose own verdict says nothing is pledged
// pokes the same, and one whose email belongs to another member pokes theirs.
func TestPatreonWebhookReadsNothingButTheEmail(t *testing.T) {
	rig := newWebhookRig(t)
	body := []byte(`{"data":{"attributes":{"email":"other@example.com","patron_status":"former_patron"},
		"relationships":{"currently_entitled_tiers":{"data":[]},"user":{"data":{"id":"1"}}}},
		"included":[{"type":"user","attributes":{"email":"patron@example.com"}}]}`)

	rig.deliver("members:pledge:delete", body)
	if !rig.pokes.Poked(userstate.HashEmail("other@example.com"), time.Now(), pokeWindow()) || rig.pokes.Len() != 1 {
		t.Errorf("poke set %v, want only data.attributes.email", rig.pokes.Len())
	}
}

// A delivery posted again pokes again: a replay is one more renewal, serialised
// by the lease, and not an error.
func TestPatreonWebhookReplayPokesAgain(t *testing.T) {
	rig := newWebhookRig(t)
	body := webhookFixture(t, "webhook-pledge-update.json")
	hash := userstate.HashEmail(webhookEmail)

	for range 2 {
		rec := rig.deliver("members:pledge:update", body)
		if rec.Code != http.StatusOK || !rig.pokes.Poked(hash, time.Now(), pokeWindow()) || rig.pokes.Len() != 1 {
			t.Fatalf("status %d, %d poked; want 200 and %s poked", rec.Code, rig.pokes.Len(), webhookEmail)
		}
	}
	if !strings.Contains(rig.logged.String(), "email="+strconv.Quote(webhookEmail)) || strings.Count(rig.logged.String(), "\n") != 2 {
		t.Errorf("admin log %q, want a line per delivery", rig.logged.String())
	}
}

// A body past the cap is refused unread, whoever signed it.
func TestPatreonWebhookRefusesABodyPastTheCap(t *testing.T) {
	rig := newWebhookRig(t)
	body := []byte(`{"data":{"attributes":{"email":"patron@example.com","note":"` + strings.Repeat("x", maxPatreonWebhookBody) + `"}}}`)

	rec := rig.deliver("members:pledge:update", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
	rig.wantNothingPoked(t)
}

// A form posted to the route is no delivery: the form is parsed in front of the
// handler, which then finds no signed body.
func TestPatreonWebhookRefusesAFormPost(t *testing.T) {
	rig := newWebhookRig(t)
	form := []byte("data=1&sig=x")
	req := webhookRequest("members:pledge:update", patreonSignature(rig.secret, []byte("data=1")), form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := serveWebhook(req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
	rig.wantNothingPoked(t)
}

// The sender pokes its own set and notifies the peers, and a peer's listener
// pokes the same reader from the notification: the hash travels, never the
// email.
func TestPatreonWebhookNotifiesThePeers(t *testing.T) {
	if os.Getenv("USERSTATE_TEST") == "" {
		t.Skip("USERSTATE_TEST not set; skipping DB integration test")
	}
	rig := newWebhookRig(t)
	port, err := strconv.Atoi(userStateTestEnv("USERSTATE_TEST_PORT", "5432"))
	if err != nil {
		t.Fatalf("USERSTATE_TEST_PORT: %v", err)
	}
	cfg := timeseries.SQLConfig{
		Host: userStateTestEnv("USERSTATE_TEST_HOST", "127.0.0.1"), Port: port, User: userStateTestEnv("USERSTATE_TEST_USER", "mtgban"),
		Password: userStateTestEnv("USERSTATE_TEST_PASSWORD", "mtgban"), DBName: userStateTestEnv("USERSTATE_TEST_DB", "user_state"), SSLMode: "disable",
	}
	client, err := timeseries.NewClient(cfg)
	if err != nil {
		t.Fatalf("timeseries.NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	saved := PricesArchiveDB
	t.Cleanup(func() { PricesArchiveDB = saved })
	PricesArchiveDB = client

	listener := pq.NewListener(cfg.SessionDSN(), time.Second, time.Minute, nil)
	t.Cleanup(func() { listener.Close() })
	err = listener.Listen(patreonPokeChannel)
	if err != nil {
		t.Fatal(err)
	}

	body := webhookFixture(t, "webhook-pledge-update.json")
	rec := rig.deliver("members:pledge:update", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	hash := userstate.HashEmail(webhookEmail)
	select {
	case n := <-listener.Notify:
		if n == nil || n.Channel != patreonPokeChannel || n.Extra != hash {
			t.Fatalf("notification %+v, want %s carrying the hash %s", n, patreonPokeChannel, hash)
		}
		peer := freshPokes(t)
		if !takePoke(n) || !peer.Poked(hash, time.Now(), pokeWindow()) {
			t.Errorf("the peer has %d poked after the notification, want %s", peer.Len(), webhookEmail)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification within 5s")
	}
}

// sha256Signed is a hex HMAC-SHA256 of body, which Patreon does not send.
func sha256Signed(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
