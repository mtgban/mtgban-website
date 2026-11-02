package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A reader's cookie vendors join the blocklist for their own request, never
// the spare capacity of the config's API-only list it starts from, the same
// slots every other request appends into.
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
	prev := Config().Stores.APIOnlyStores
	t.Cleanup(func() { Config().Stores.APIOnlyStores = prev })
	Config().Stores.APIOnlyStores = append(make([]string, 0, 4), "APIONLY")
	array := Config().Stores.APIOnlyStores[:cap(Config().Stores.APIOnlyStores)]

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
	if !slices.Equal(array, []string{"APIONLY", "", "", ""}) {
		t.Errorf("a request wrote its vendors into the config's API-only list: %q", array)
	}
}

// A store only the price API serves is on none of the arbitrage pages, as
// a source or as a table, nor in their settings grids, nor in the palette.
func TestAPIOnlyStoresStayOffArbitrage(t *testing.T) {
	skipWithoutDatastore(t)
	cardID := backend().GetUUIDs()[0]
	// DevMode so render reads templates from disk, and opens every source
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	for _, name := range []string{"Arbitrage", "Global"} {
		if LogPages[name] == nil {
			LogPages[name] = log.New(io.Discard, "", 0)
			t.Cleanup(func() { delete(LogPages, name) })
		}
	}

	stock := func(price float64) mtgban.InventoryRecord {
		inv := mtgban.InventoryRecord{}
		inv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: 2, URL: "u"})
		return inv
	}
	buys := func(price float64) mtgban.BuylistRecord {
		bl := mtgban.BuylistRecord{}
		bl.Add(cardID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: price, Quantity: 2, URL: "u"})
		return bl
	}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(stock(10), mtgban.ScraperInfo{Name: "Reverse Shop", Shorthand: "REVSHOP"}),
		mtgban.NewSellerFromInventory(stock(40), mtgban.ScraperInfo{Name: "Probe Shop", Shorthand: "PROBESHOP"}),
		mtgban.NewSellerFromInventory(stock(40), mtgban.ScraperInfo{Name: "API Shop", Shorthand: "APISHOP"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buys(100), mtgban.ScraperInfo{Name: "Reverse Buyer", Shorthand: "REVBUY"}),
		mtgban.NewVendorFromBuylist(buys(110), mtgban.ScraperInfo{Name: "API Buyer", Shorthand: "APIBUY"}),
	})
	withConfigCopy(t)
	Config().Stores.APIOnlyStores = []string{"APISHOP", "APIBUY"}
	Config().Stores.GlobalAllowList = []string{"REVSHOP", "APISHOP"}
	Config().Stores.GlobalProbeList = []string{"PROBESHOP", "APISHOP"}

	for _, page := range []struct {
		target    string
		serve     func(http.ResponseWriter, *http.Request)
		want, not string
	}{
		{"/arbit", testSite.Arbit, "Reverse Shop", "API Shop"},
		{"/arbit?source=REVSHOP", testSite.Arbit, "Reverse Buyer", "API Buyer"},
		{"/arbit?source=APISHOP", testSite.Arbit, "Unknown APISHOP", "API Buyer"},
		{"/reverse", testSite.Reverse, "Reverse Buyer", "API Buyer"},
		{"/reverse?source=REVBUY", testSite.Reverse, "Reverse Shop", "API Shop"},
		{"/global", testSite.Global, "Reverse Shop", "API Shop"},
		{"/global?source=REVSHOP&legit=0", testSite.Global, "Probe Shop", "API Shop"},
	} {
		rec := httptest.NewRecorder()
		page.serve(rec, httptest.NewRequest(http.MethodGet, page.target, nil))
		body := rec.Body.String()
		if !strings.Contains(body, page.want) {
			t.Errorf("%s: %q is missing", page.target, page.want)
		}
		if strings.Contains(body, page.not) {
			t.Errorf("%s: the API-only %q is shown", page.target, page.not)
		}
	}

	for name, c := range map[string]struct{ got, want []string }{
		"arbit grid":   {arbitVendorKeys(arbitBlockedVendors(""), false), []string{"REVBUY"}},
		"reverse grid": {arbitVendorKeys(arbitBlockedVendors(""), true), []string{"PROBESHOP", "REVSHOP"}},
		"global grid":  {globalVendorKeys(globalProbeBlocklist()), []string{"PROBESHOP"}},
		"global probe": {globalProbeBlocklist(), []string{"REVSHOP", "APISHOP"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}

	rec := httptest.NewRecorder()
	testSite.palette.Stores(rec, httptest.NewRequest(http.MethodGet, "/api/palette/stores.json", nil))
	if !strings.Contains(rec.Body.String(), "REVSHOP") || strings.Contains(rec.Body.String(), "APISHOP") || strings.Contains(rec.Body.String(), "APIBUY") {
		t.Errorf("the palette lists %s", rec.Body.String())
	}
}
