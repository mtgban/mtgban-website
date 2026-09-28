package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The index section links a marketplace it has no price from, which is worth
// offering only where the site carries that marketplace at all.
func TestSearchLinksOnlyTheMarketplacesItCarries(t *testing.T) {
	skipWithoutDatastore(t)
	uuid := backend().GetUUIDs()[0]

	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	stock := mtgban.InventoryRecord{}
	stock.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 1.5, Quantity: 1, URL: "https://example.test"})

	search := func(t *testing.T, families ...string) string {
		t.Helper()
		prev := sellersPtr.Load()
		t.Cleanup(func() { sellersPtr.Store(prev) })

		// One stocked seller so the search has a result to render, plus a
		// reference seller per marketplace under test.
		sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(stock,
			mtgban.ScraperInfo{Name: "CK", Shorthand: "CK"})}
		for _, family := range families {
			sellers = append(sellers, mtgban.NewSellerFromInventory(mtgban.InventoryRecord{},
				mtgban.ScraperInfo{Name: family, Shorthand: family, Family: family, MetadataOnly: true}))
		}
		sellersPtr.Store(&sellers)

		rec := httptest.NewRecorder()
		testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(uuid), nil))
		return rec.Body.String()
	}

	out := search(t)
	if strings.Contains(out, ">TCGplayer<") || strings.Contains(out, ">CardMarket<") {
		t.Error("a site carrying neither marketplace linked one anyway")
	}

	out = search(t, "TCG")
	if !strings.Contains(out, ">TCGplayer<") {
		t.Error("a site carrying TCGplayer did not link it")
	}
	if strings.Contains(out, ">CardMarket<") {
		t.Error("a site carrying no Cardmarket linked it anyway")
	}
}

// A TCG Direct price over twice the market is flagged against the market
// price the handler read for the card, and the warning says what it was.
func TestSearchFlagsDirectAgainstTheMarketItRead(t *testing.T) {
	skipWithoutDatastore(t)
	uuid := backend().GetUUIDs()[0]

	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	market := mtgban.InventoryRecord{}
	market.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 2, URL: "https://example.test"})
	direct := mtgban.InventoryRecord{}
	direct.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 9.99, Quantity: 1, URL: "https://example.test"})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(market, mtgban.ScraperInfo{Name: "TCG Market", Shorthand: "TCGMarket", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(direct, mtgban.ScraperInfo{Name: "TCG Direct", Shorthand: "TCGDirect"}),
	}
	sellersPtr.Store(&sellers)

	rec := httptest.NewRecorder()
	testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(uuid), nil))
	if !strings.Contains(rec.Body.String(), `data-tooltip="Price looks off - TCG Market is $ 2.00"`) {
		t.Error("the Direct price is not flagged against the market price")
	}
}
