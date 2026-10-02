package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A failed export answers with a page or an error, so it must not keep the
// headers that told the browser to save the answer as a file.
func TestFailedExportIsNotADownload(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	// Every TCGplayer export fails without a TCGplayer seller.
	_, err := findSellerInventory("TCGPlayer")
	if err == nil {
		t.Skip("a TCGplayer seller is loaded")
	}
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
	}

	var decklist string
	for _, id := range backend().GetSealedUUIDs() {
		list, _ := getDecklist(backend(), id)
		if len(list) > 0 {
			decklist = id
			break
		}
	}
	if decklist == "" {
		t.Fatal("no sealed product with a decklist")
	}

	post := func(form url.Values) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	card := backend().GetUUIDs()[0]
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{"upload tcgplayer csv", testSite.Upload, post(url.Values{
			"textArea": {"Name,Quantity\nCounterspell,2\n"}, "tcgplayer_csv": {"true"}, "mode": {"true"}})},
		{"upload TCG tag", testSite.Upload, post(url.Values{
			"tag": {"TCG"}, "TCGhashes": {card}, "TCGhashesQtys": {"1"}, "TCGhashesCond": {"NM"}})},
		{"tcgplayer decklist", testSite.TCGHandler,
			httptest.NewRequest(http.MethodGet, "/api/tcgplayer/decklist/"+decklist, nil)},
	} {
		rec := httptest.NewRecorder()
		c.handler(rec, c.req)
		disp := rec.Header().Get("Content-Disposition")
		if disp != "" {
			t.Errorf("%s: failed export answered %d %s with %q", c.name, rec.Code, rec.Header().Get("Content-Type"), disp)
		}
	}
}
