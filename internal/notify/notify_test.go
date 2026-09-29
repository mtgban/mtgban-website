package notify

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// webhook stands in for a Discord webhook that answers every post with
// status, and returns its url and the content of each post it receives.
func webhook(t *testing.T, status int) (string, <-chan string) {
	t.Helper()
	posts := make(chan string, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p payload
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			t.Error(err)
		}
		posts <- p.Content
		w.WriteHeader(status)
	}))
	t.Cleanup(hook.Close)
	return hook.URL, posts
}

// posted returns the content of the post that reached the webhook. Post
// only returns once the webhook has answered, so the post is there by then.
func posted(t *testing.T, posts <-chan string) string {
	t.Helper()
	select {
	case content := <-posts:
		return content
	default:
		t.Fatal("nothing reached the webhook")
		return ""
	}
}

// A message Discord would refuse as too long is cut to fit instead, never
// through a rune: the one the cut straddles is left out whole. A message
// that fits is sent as it is.
func TestPostCutsToWhatDiscordAccepts(t *testing.T) {
	hook, posts := webhook(t, http.StatusNoContent)

	Post(hook, "test", "fits", false)
	got := posted(t, posts)
	if got != "fits" {
		t.Errorf("posted %q, want the message as it is", got)
	}

	// The two bytes of "é" sit either side of the cut.
	kept := strings.Repeat("a", maxContent-1)
	Post(hook, "test", kept+"é"+strings.Repeat("b", 100), false)
	got = posted(t, posts)
	if got != kept {
		t.Errorf("posted %d bytes ending %q, want the %d before the cut rune", len(got), got[max(0, len(got)-4):], len(kept))
	}
}

// A post Discord refuses leaves a line in the log instead of vanishing.
func TestPostLogsARefusal(t *testing.T) {
	hook, _ := webhook(t, http.StatusBadRequest)
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })

	Post(hook, "panic", "refused", false)
	if !strings.Contains(logged.String(), "notify: panic post refused: 400 Bad Request") {
		t.Errorf("logged %q, want the refusal", logged.String())
	}
}

// A post that never reaches Discord is logged with what went wrong, but not
// with the webhook's URL, whose path carries its token.
func TestPostKeepsTheTokenOutOfTheLog(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })

	Post(down.URL+"/api/webhooks/1/SECRET", "panic", "unsent", false)
	got := logged.String()
	if strings.Contains(got, "SECRET") {
		t.Errorf("logged %q, want no token", got)
	}
	if !strings.Contains(got, "notify: panic post failed: ") || !strings.Contains(got, "connection refused") {
		t.Errorf("logged %q, want the kind and the failure", got)
	}
}

// Send says whether the message went through, for a caller that tries
// again later.
func TestSendReturnsTheRefusal(t *testing.T) {
	hook, _ := webhook(t, http.StatusTooManyRequests)
	err := Send(hook, "stale", "refused", false)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("err = %v, want the 429", err)
	}

	hook, _ = webhook(t, http.StatusNoContent)
	err = Send(hook, "stale", "accepted", false)
	if err != nil {
		t.Errorf("err = %v, want none", err)
	}
}
