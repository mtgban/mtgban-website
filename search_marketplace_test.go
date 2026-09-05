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
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The index section links a marketplace it has no price from, which is worth
// offering only where the site carries that marketplace at all.
func TestSearchLinksOnlyTheMarketplacesItCarries(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	uuid := mtgmatcher.GetUUIDs()[0]

	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
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
		Search(rec, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(uuid), nil))
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
