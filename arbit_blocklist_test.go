package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// A reader's cookie vendors join the config's blocklist for their own request.
// Appended in place, they landed in the spare capacity a JSON decode usually
// leaves, the same slots every other request appends into.
func TestArbitBlocksCookieVendorsPerRequest(t *testing.T) {
	// DevMode so render reads templates from disk
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Arbitrage"] == nil {
		LogPages["Arbitrage"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Arbitrage") })
	}
	seedReverseScrapers(t, "card-a")
	prev := Config().ArbitBlockVendors
	t.Cleanup(func() { Config().ArbitBlockVendors = prev })
	Config().ArbitBlockVendors = append(make([]string, 0, 4), "CONFIG_VENDOR")
	array := Config().ArbitBlockVendors[:cap(Config().ArbitBlockVendors)]

	// The /reverse menu lists every vendor the blocklist lets through
	reverseMenu := func(cookie string) string {
		req := httptest.NewRequest(http.MethodGet, "/reverse", nil)
		req.AddCookie(&http.Cookie{Name: "ReverseVendorsList", Value: cookie})
		rec := httptest.NewRecorder()
		testSite.Reverse(rec, req)
		return rec.Body.String()
	}
	const entry = `<span class="store-name">Reverse Buyer</span>`
	if !strings.Contains(reverseMenu(""), entry) {
		t.Fatal("the menu does not list the vendor to begin with")
	}
	if strings.Contains(reverseMenu("REVBUY"), entry) {
		t.Error("the cookie's vendor is still in the menu")
	}
	if !slices.Equal(array, []string{"CONFIG_VENDOR", "", "", ""}) {
		t.Errorf("a request wrote its vendors into the config's blocklist: %q", array)
	}
}
