package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The panic report goes to a Discord channel, so the request it names must
// not carry the working sig it came with.
func TestRecoverPanicMasksSig(t *testing.T) {
	reported := make(chan string, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var p struct{ Content string }
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			t.Error(err)
		}
		_, source, found := strings.Cut(p.Content, "source request: ")
		if found {
			reported <- source
		}
	}))
	defer hook.Close()

	prev := Config.Discord.ServerWebhookURL
	Config.Discord.ServerWebhookURL = hook.URL
	t.Cleanup(func() { Config.Discord.ServerWebhookURL = prev })

	panicky := noSigning(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	panicky.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search?q=bolt&sig=SECRET", nil))

	select {
	case got := <-reported:
		want := "/search?q=bolt&sig=REDACTED"
		if got != want {
			t.Errorf("reported %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no source request was reported")
	}
}
