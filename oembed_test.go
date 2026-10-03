package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/embed"
)

// The endpoint is declared as application/json+oembed, so every answer it
// gives has to be one, errors included: a consumer asking for json cannot
// read an html page.
func TestOEmbedAlwaysAnswersInJSON(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)

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
		testSite.SearchOEmbed(w, httptest.NewRequest(http.MethodGet, probe.url, nil))
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

// The unfurl is the page it names: the first card it previews is the one the
// page leads with, in the page's own sort, order, page of results and pinned
// bar.
func TestOEmbedPreviewsThePageItNames(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	ogTitle := regexp.MustCompile(`<meta property="og:title" content="([^"]*)"`)
	for _, page := range []string{
		"/search?q=s%3AM10&reverse=true",
		"/search?q=s%3AM10&sort=alpha",
		"/search?q=s%3AM10&p=2",
		"/search?q=s%3AM10&scope=r%3Acommon",
	} {
		w := httptest.NewRecorder()
		testSite.Search(w, httptest.NewRequest(http.MethodGet, page, nil))
		m := ogTitle.FindStringSubmatch(w.Body.String())
		if m == nil {
			t.Fatalf("%s: the page has no og:title", page)
		}

		w = httptest.NewRecorder()
		testSite.SearchOEmbed(w, httptest.NewRequest(http.MethodGet, "/search/oembed?url="+url.QueryEscape("https://mtgban.com"+page), nil))
		var preview embed.OEmbed
		if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		if want := html.UnescapeString(m[1]); preview.Title != want {
			t.Errorf("%s: previews %q, the page leads with %q", page, preview.Title, want)
		}
	}
}

// An unfurl is shown to everyone who sees the link, and the endpoint runs
// behind noSigning: the preview quotes the stores any reader is shown,
// whatever signature the request carries.
func TestOEmbedQuotesWhatAnyReaderSees(t *testing.T) {
	skipWithoutDatastore(t)
	signingEnabled(t, false)

	ids, _ := backend().SearchEquals("Counterspell")
	inventory := mtgban.InventoryRecord{}
	for _, id := range ids {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 1, Quantity: 1})
	}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "SHOWNIDX", Name: "Shown Index", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "HIDDENIDX", Name: "Hidden Index", MetadataOnly: true}),
	}
	vendors := []mtgban.Vendor{}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	withConfigCopy(t)
	Config().SearchRetailBlockList = []string{"HIDDENIDX"}

	expires := time.Now().Add(time.Hour)
	forged := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("Expires=%d&SearchDisabled=NONE", expires.Unix())))
	signed := signedAs(t, url.Values{"UserName": {"Reader"}, "UserTier": {"Pro"}, "SearchDisabled": {"NONE"}}, expires)
	_, ok := signatureIsValid(signed)
	if !ok {
		t.Fatal("refused a signature it had just written")
	}

	page := "https://mtgban.com/search?q=Counterspell"
	oembed := func(page string) string {
		return "/search/oembed?format=json&url=" + url.QueryEscape(page)
	}
	handler := noSigning(http.HandlerFunc(testSite.SearchOEmbed))

	for _, probe := range []struct {
		name   string
		target string
		cookie string
	}{
		{"no signature", oembed(page), ""},
		{"a forged cookie", oembed(page), forged},
		{"a forged sig", oembed(page) + "&sig=" + url.QueryEscape(forged), ""},
		{"a forged sig in the page url", oembed(page + "&sig=" + url.QueryEscape(forged)), ""},
		{"a cookie this host signed", oembed(page), signed},
	} {
		req := httptest.NewRequest(http.MethodGet, probe.target, nil)
		if probe.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: probe.cookie})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var preview embed.OEmbed
		err := json.Unmarshal(w.Body.Bytes(), &preview)
		if err != nil {
			t.Fatalf("%s: answered %d, not an oEmbed: %v", probe.name, w.Code, err)
		}
		if !strings.Contains(preview.HTML, "Shown Index") {
			t.Errorf("%s: preview quotes no store:\n%s", probe.name, preview.HTML)
		}
		if strings.Contains(preview.HTML, "Hidden Index") {
			t.Errorf("%s: preview quotes a store the blocklist hides:\n%s", probe.name, preview.HTML)
		}
	}
}

// The custom buylist is the reader's own, priced off a store they pick: it
// belongs on their search page, never in an unfurl everyone sees, whatever
// signature comes with the request.
func TestOEmbedLeavesOutTheCustomBuylist(t *testing.T) {
	skipWithoutDatastore(t)
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	// One store stocks Counterspell and the blocklist hides it, so in a
	// search that skips cards nobody offers, only a custom buylist priced
	// off that store keeps the card.
	ids, _ := backend().SearchEquals("Counterspell")
	inventory := mtgban.InventoryRecord{}
	for _, id := range ids {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "HIDDENSTORE", Name: "Hidden Store"}),
	}
	vendors := []mtgban.Vendor{}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	withConfigCopy(t)
	Config().SearchRetailBlockList = []string{"HIDDENSTORE"}

	expires := time.Now().Add(time.Hour)
	signed := signedAs(t, url.Values{"UserName": {"Reader"}, "UserTier": {"Pro"}, "UploadCustom": {"true"}}, expires)
	forged := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("Expires=%d&UploadCustom=true", expires.Unix())))
	withCookies := func(req *http.Request, sig string) *http.Request {
		for name, value := range map[string]string{
			"MTGBAN":            sig,
			"SearchMiscOpts":    "skipEmpty",
			"UploadCustomOpts":  "enabled",
			"UploadCustomRate":  "0.5",
			"UploadCustomBuyer": "HIDDENSTORE",
		} {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		return req
	}

	w := httptest.NewRecorder()
	testSite.Search(w, withCookies(httptest.NewRequest(http.MethodGet, "/search?q=Counterspell", nil), signed))
	if !strings.Contains(w.Body.String(), "Custom Buylist") {
		t.Fatal("the reader's own page shows no custom buylist")
	}

	target := "/search/oembed?format=json&url=" + url.QueryEscape("https://mtgban.com/search?q=Counterspell")
	handler := noSigning(http.HandlerFunc(testSite.SearchOEmbed))
	for _, probe := range []struct {
		name   string
		cookie string
	}{
		{"a cookie this host signed", signed},
		{"a forged cookie", forged},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, withCookies(httptest.NewRequest(http.MethodGet, target, nil), probe.cookie))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: answered %d with a card only the custom buylist keeps:\n%s", probe.name, w.Code, w.Body.String())
		}
	}
}

// A preview lists several printings, each under its own heading. Handing them
// all one price list quotes the first card's numbers under every other card's
// name - a Tempest common priced as a 30th Anniversary one.
func TestPreviewQuotesEachCardWithItsOwnPrices(t *testing.T) {
	ids, _ := backend().SearchEquals("Counterspell")
	if len(ids) < 2 {
		t.Skip("no datastore loaded")
	}

	prices := map[string]float64{ids[0]: 1.11, ids[1]: 22.22}
	out := embed.Generate(backend(), externalURL(nil), ids[:2], func(cardID string) string {
		return editionTitle(backend(), cardID)
	}, func(cardID string) []embed.Entry {
		return []embed.Entry{{ScraperName: "TCG Low", Shorthand: "TCGLow", Price: prices[cardID]}}
	})

	for _, want := range []string{"$1.11", "$22.22"} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("preview never quoted %s:\n%s", want, out.HTML)
		}
	}
}
