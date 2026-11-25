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

func TestGroupBySlab(t *testing.T) {
	row := func(store string, price float64, slab mtgban.Slab) SearchEntry {
		return SearchEntry{Shorthand: store, Price: price, Slab: &slab}
	}
	gather := func() map[string]map[mtgban.Condition][]SearchEntry {
		return map[string]map[mtgban.Condition][]SearchEntry{"card": {
			"NM": {
				row("A", 50, mtgban.Slab{Grader: "CGC", Score: 10}),
				row("B", 30, mtgban.Slab{Grader: "BGS", Score: 9.5}),
				row("C", 90, mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}),
				row("D", 20, mtgban.Slab{Grader: "CGC", Score: 10}),
				row("E", 10, mtgban.Slab{Label: "SGC 9"}),
				row("F", 70, mtgban.Slab{Grader: "PSA", Score: 10}),
				row("I", 80, mtgban.Slab{Grader: "BGS", Score: 10, Label: "Pristine"}),
				row("J", 85, mtgban.Slab{Grader: "BGS", Score: 10, Label: "Black Label"}),
				row("K", 60, mtgban.Slab{Grader: "BGS", Score: 10}),
			},
			"SP": {
				row("G", 15, mtgban.Slab{Grader: "CGC", Label: "Less than 8"}),
				row("H", 5, mtgban.Slab{}),
			},
		}}
	}

	for byPrice, wantCGC := range map[bool]string{true: "DA", false: "AD"} {
		found := gather()
		keys := groupBySlab(found, byPrice)
		want := []mtgban.Condition{"PSA 10", "BGS 10 Black Label", "BGS 10 Pristine", "BGS 10", "BGS 9.5", "CGC 10 Pristine", "CGC 10", "CGC Less than 8", otherSlabs}
		if !slices.Equal(keys, want) {
			t.Errorf("byPrice %v: groups = %q, want %q", byPrice, keys, want)
		}
		var stores string
		for _, entry := range found["card"]["CGC 10"] {
			stores += entry.Shorthand
		}
		if stores != wantCGC {
			t.Errorf("byPrice %v: CGC 10 lists %s, want %s", byPrice, stores, wantCGC)
		}
		if len(found["card"][otherSlabs]) != 2 {
			t.Errorf("byPrice %v: other slabs = %+v, want two", byPrice, found["card"][otherSlabs])
		}
		if len(found["card"]["NM"]) != 0 {
			t.Errorf("byPrice %v: a row is left under its condition", byPrice)
		}
	}

	if keys := groupBySlab(map[string]map[mtgban.Condition][]SearchEntry{}, true); len(keys) != 0 {
		t.Errorf("groups of nothing = %q", keys)
	}
}

// The Graded page finds only the cards a slab seller offers, lists that
// seller's slabs under their grades and no buylist, while the search keeps
// every store.
func TestGradedPage(t *testing.T) {
	skipWithoutDatastore(t)
	// DevMode so render reads templates from disk
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 2)
	stock := func(name string, graded bool, inv mtgban.InventoryRecord) mtgban.Seller {
		return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: name, Shorthand: name, GradedMode: graded})
	}
	withPrices(t, []mtgban.Seller{
		stock("RAWSHOP", false, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 10, URL: "u"}},
			cards[1]: {{Conditions: "NM", Price: 10, URL: "u"}},
		}),
		stock("SLABSHOP", true, mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 40, URL: "u", Slab: &mtgban.Slab{Grader: "PSA", Score: 9}}},
		}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{cards[0]: {{Conditions: "NM", BuyPrice: 5, URL: "u"}}},
			mtgban.ScraperInfo{Name: "BUYSHOP", Shorthand: "BUYSHOP"}),
	})

	row := func(store string) string { return `data-track-value="` + store + `"` }
	card := func(i int) string { return `data-card-id="` + cards[i] + `"` }
	serve := func(path, agent string) string {
		req := httptest.NewRequest(http.MethodGet, path+"?q="+strings.Join(cards, ","), nil)
		req.Header.Set("User-Agent", agent)
		rec := httptest.NewRecorder()
		testSite.Search(rec, req)
		return rec.Body.String()
	}
	for _, agent := range []string{"", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"} {
		body := serve("/graded", agent)
		for _, want := range []string{row("SLABSHOP"), ">PSA 9</div>", "Last Sold", "No sales on record", card(0)} {
			if !strings.Contains(body, want) {
				t.Errorf("graded, %q: %q is missing", agent, want)
			}
		}
		for _, not := range []string{row("RAWSHOP"), row("BUYSHOP"), "Condition: NM", card(1), "/search/export/", "data-buyers-set"} {
			if strings.Contains(body, not) {
				t.Errorf("graded, %q: %q is shown", agent, not)
			}
		}

		body = serve("/search", agent)
		for _, want := range []string{row("RAWSHOP"), row("SLABSHOP"), row("BUYSHOP"), "Condition: NM", card(0), card(1)} {
			if !strings.Contains(body, want) {
				t.Errorf("search, %q: %q is missing", agent, want)
			}
		}
	}
}

// The sorts that read raw copies' prices and sales do not order the Graded
// page, wherever they were asked for.
func TestGradedPageSort(t *testing.T) {
	config := SearchConfig{VelocitySort: true}
	gradedSearch(&config)
	for _, sort := range []string{"retail", "buylist", "velocity"} {
		req := httptest.NewRequest(http.MethodGet, "/graded?sort="+sort, nil)
		req.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: sort})
		asked := config
		asked.SortMode = sort
		if got := readSearchSort(req, asked); got != "" {
			t.Errorf("sort %s orders the page by %q", sort, got)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/graded?sort=retail", nil)
	req.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: "number"})
	if got := readSearchSort(req, config); got != "number" {
		t.Errorf("the saved sort gives %q, want number", got)
	}
}

// The Graded page is in the menu only where a store lists slabs.
func TestGradedPageHiddenWithoutSlabs(t *testing.T) {
	nav, found := ExtraNavs["Search"].pageAt("/graded")
	if !found {
		t.Fatal("no /graded page")
	}
	for _, graded := range []bool{false, true} {
		withPrices(t, []mtgban.Seller{
			mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "SHOP", GradedMode: graded}),
		}, nil)
		if nav.hiddenOn(testSite) == graded {
			t.Errorf("with a graded store %v: hidden = %v", graded, !graded)
		}
	}
}
