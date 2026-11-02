package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// readyToRender gives a test what main() gives the server before it renders
// a search: the parsed template cache and the page's log.
func readyToRender(tb testing.TB) {
	tb.Helper()
	if TemplateCache == nil {
		cache, err := buildTemplateCache()
		if err != nil {
			tb.Fatal(err)
		}
		TemplateCache = cache
		tb.Cleanup(func() { TemplateCache = nil })
	}
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	saved := LogPages["Search"]
	tb.Cleanup(func() { LogPages["Search"] = saved })
	LogPages["Search"] = log.New(io.Discard, "", 0)
}

// BenchmarkSearchPage is the search handler end to end, render included,
// for a query that fills the result cap, one that fills a page and one that
// finds a few printings. It needs stores loaded, which TestMain does from a
// B2 key pair in the environment.
func BenchmarkSearchPage(b *testing.B) {
	if len(GetSellers()) == 0 {
		b.Skip("no stores loaded; B2_KEY_ID and B2_APP_KEY load them")
	}
	readyToRender(b)

	for _, q := range []string{"r:mythic", "s:MH2", "Lightning Bolt"} {
		b.Run(q, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(q), nil)
			b.ReportAllocs()
			for range b.N {
				rec := httptest.NewRecorder()
				testSite.Search(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("%s answered %d", q, rec.Code)
				}
			}
		})
	}
}
