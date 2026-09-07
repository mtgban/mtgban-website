package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// sealedRedirectQuery is what a path redirects the sealed tab to ask.
func sealedRedirectQuery(t *testing.T, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	SealedRedirect(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("%s answered %d, want a redirect", path, rec.Code)
	}
	got, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/sealed" {
		t.Errorf("%s landed on %q, want the sealed tab", path, got.Path)
	}
	return got.Query().Get("q")
}

// A product has no number to be named by, so its path carries its name as a
// slug, and the slug is enough to find it again: every product in the
// datastore goes out as a path and comes back as itself.
func TestSealedPathRoundTrips(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var products, pathless int
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			co, err := mtgmatcher.GetUUID(product.UUID)
			if err != nil {
				continue
			}
			products++
			path := cardPath(co)
			if path == "" {
				pathless++
				continue
			}
			if got := sealedRedirectQuery(t, path); got != product.Name {
				t.Errorf("%s asks for %q, want %q", path, got, product.Name)
			}
		}
	}
	if products == 0 {
		t.Fatal("no products")
	}
	if pathless > 0 {
		t.Errorf("%d of %d products have no path", pathless, products)
	}
}

// Each part narrows the one before it, and a path that stops early stops
// narrowing rather than failing.
func TestSealedPathNamesLessAsksForMore(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	for _, tt := range []struct{ path, want string }{
		{"/sealed/", ""},
		{"/sealed/sld", "s:sld"},
		{"/sealed/sld/", "s:sld"},
		{"/sealed/sld/no-such-drop", "s:sld no such drop"},
	} {
		if got := sealedRedirectQuery(t, tt.path); got != tt.want {
			t.Errorf("%s asks %q, want %q", tt.path, got, tt.want)
		}
	}
}

// The path is only as good as the search it lands on: followed through the
// redirect into the sealed tab, a product's path shows that product.
func TestSealedPathLandsOnTheProduct(t *testing.T) {
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
	co, _ := mtgmatcher.GetUUID(product.UUID)

	rec := httptest.NewRecorder()
	SealedRedirect(rec, httptest.NewRequest(http.MethodGet, cardPath(co), nil))
	landing := rec.Header().Get("Location")

	page := httptest.NewRecorder()
	Search(page, httptest.NewRequest(http.MethodGet, landing, nil))
	body := page.Body.String()
	if !strings.Contains(body, product.UUID) {
		t.Errorf("%s -> %s does not show %q", cardPath(co), landing, product.Name)
	}
}
