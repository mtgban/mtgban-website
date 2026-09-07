package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A product's slug is a name this site publishes for it, and the matcher
// finds the product under it - but the page echoed the slug in the title and
// the search box. Found under another spelling, a product is shown under the
// catalog's.
func TestSealedTabNamesTheProductItFound(t *testing.T) {
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

	set, err := mtgmatcher.GetSet("SLD")
	if err != nil || len(set.SealedProduct) == 0 {
		t.Skip("no SLD products")
	}
	product := set.SealedProduct[0]
	slug := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(product.Name), "-")

	shown := func(path string) (title, box string) {
		rec := httptest.NewRecorder()
		Search(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body, _ := io.ReadAll(rec.Result().Body)
		if m := regexp.MustCompile(`<title>([^<]*)</title>`).FindSubmatch(body); m != nil {
			title = string(m[1])
		}
		if m := regexp.MustCompile(`id="nav-searchbox"[^>]*value="([^"]*)"`).FindSubmatch(body); m != nil {
			box = string(m[1])
		}
		return
	}

	title, box := shown("/sealed?q=" + slug)
	if box != product.Name {
		t.Errorf("box reads %q for the slug, want %q", box, product.Name)
	}
	if !regexp.MustCompile(regexp.QuoteMeta(product.Name)).MatchString(title) {
		t.Errorf("title reads %q for the slug, want it to name %q", title, product.Name)
	}

	// With a filter beside it the query is what was typed
	_, box = shown("/sealed?q=s:sld+" + slug)
	if box == product.Name {
		t.Errorf("a filtered query was rewritten to the product's name")
	}
}
