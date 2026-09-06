package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// The endpoint is declared as application/json+oembed, so every answer it
// gives has to be one - the search handler's own error paths render a whole
// html page, which a consumer asking for json cannot read.
func TestOEmbedAlwaysAnswersInJSON(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	for _, probe := range []struct {
		name   string
		url    string
		status int
	}{
		{"a format we do not serve", "/search/oembed?format=xml&url=https%3A%2F%2Fmtgban.com%2Fsearch%3Fq%3DCounterspell", http.StatusNotImplemented},
		{"a page that is not ours", "/search/oembed?format=json&url=https%3A%2F%2Fexample.com%2Fsearch%3Fq%3DCounterspell", http.StatusNotFound},
		{"a search with no cards", "/search/oembed?format=json&url=https%3A%2F%2Fmtgban.com%2Fsearch%3Fq%3Dzzzznotacardzzzz", http.StatusNotFound},
		{"a card we do carry", "/search/oembed?format=json&url=https%3A%2F%2Fmtgban.com%2Fsearch%3Fq%3DCounterspell", http.StatusOK},
	} {
		w := httptest.NewRecorder()
		Search(w, httptest.NewRequest(http.MethodGet, probe.url, nil))
		res := w.Result()
		body, _ := io.ReadAll(res.Body)

		if res.StatusCode != probe.status {
			t.Errorf("%s: answered %d, want %d", probe.name, res.StatusCode, probe.status)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: answered %q, want application/json", probe.name, ct)
		}
		if !json.Valid(body) {
			head := string(body)
			if len(head) > 60 {
				head = head[:60]
			}
			t.Errorf("%s: body is not json: %q", probe.name, head)
		}
	}
}

// A preview lists several printings, each under its own heading. Handing them
// all one price list quotes the first card's numbers under every other card's
// name - a Tempest common priced as a 30th Anniversary one.
func TestPreviewQuotesEachCardWithItsOwnPrices(t *testing.T) {
	ids, _ := mtgmatcher.SearchEquals("Counterspell")
	if len(ids) < 2 {
		t.Skip("no datastore loaded")
	}

	prices := map[string]float64{ids[0]: 1.11, ids[1]: 22.22}
	out := embed.Generate(externalURL(), ids[:2], editionTitle, func(cardID string) []embed.Entry {
		return []embed.Entry{{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: prices[cardID]}}
	})

	for _, want := range []string{"$1.11", "$22.22"} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("preview never quoted %s:\n%s", want, out.HTML)
		}
	}
}
