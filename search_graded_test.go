package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
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

		// The phone's panel names its landscape column too.
		if agent != "" && !strings.Contains(body, `role="region" aria-label="Last Sold"`) {
			t.Errorf("graded, %q: the Last Sold panel is not named", agent)
		}

		body = serve("/search", agent)
		for _, want := range []string{row("RAWSHOP"), row("SLABSHOP"), row("BUYSHOP"), "Condition: NM", card(0), card(1)} {
			if !strings.Contains(body, want) {
				t.Errorf("search, %q: %q is missing", agent, want)
			}
		}
		if agent != "" && !strings.Contains(body, `role="region" aria-label="Buyers"`) {
			t.Errorf("search, %q: the Buyers panel is not named", agent)
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

// The Last Sold column opens with the slabs' Sales Velocity, then draws the
// sales of the grades a store lists the card in as the Sales pane draws the
// recent orders, in the page's order, and shows a reader without the sales an
// upsell instead.
func TestGradedPageLastSold(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cards := somePlainCardUUIDs(t, 1)
	psa9 := mtgban.Slab{Grader: "PSA", Score: 9}
	pristine := mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {
				{Conditions: "NM", Price: 40, URL: "u", Slab: &psa9},
				{Conditions: "NM", Price: 90, URL: "u", Slab: &pristine},
			},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
	}, nil)

	now := time.Now()
	at := func(days int) uint32 { return uint32(now.AddDate(0, 0, -days).Unix()) }
	previous := gradedSalesStore.Snapshot()
	t.Cleanup(func() { gradedSalesStore.Publish(previous) })
	gradedSalesStore.Publish(&salesvelocity.GradedSnapshot{Day: now, Cards: map[string]*salesvelocity.GradedCard{
		cards[0]: {
			Grades: map[mtgban.Slab]*salesvelocity.GradeSales{
				psa9: {Sales: []salesvelocity.GradedSale{
					{At: at(1), Cents: 51500, ListingID: "111"},
					{At: at(3), Cents: 70000, ListingID: "222", BestOffer: true},
				}},
				pristine: {Sales: []salesvelocity.GradedSale{{At: at(200), Cents: 99900, Fanatics: true, ListingID: "fanatics:W1"}}},
				// No store lists a PSA 10 of it.
				{Grader: "PSA", Score: 10}: {Sales: []salesvelocity.GradedSale{{At: at(1), Cents: 123400, ListingID: "333"}}},
			},
			Sales: 3, Days: 2,
			Last: salesvelocity.GradedSale{At: at(1), Cents: 51500}, LastSlab: psa9,
		},
	}})

	req := httptest.NewRequest(http.MethodGet, "/graded?q="+cards[0], nil)
	rec := httptest.NewRecorder()
	testSite.Search(rec, req)
	body := rec.Body.String()
	for _, want := range []string{
		"<span>PSA 9</span><span class=\"sales-avg\">avg <b>$ 515.00</b>",
		`href="https://www.ebay.com/itm/111"`,
		`data-track="ui.graded.sale" data-track-value="eBay"`,
		`data-track="ui.graded.sale" data-track-value="Fanatics"`,
		`<span class="sales-qty">offer</span>`,
		"<span>CGC 10 Pristine</span><span class=\"sales-avg\">avg <b>$ 999.00</b>",
		`href="https://sales-history.fanaticscollect.com/items/W1"`,
		`<span class="store-name dim">Sales Velocity</span>`,
		">0.1/day<",
		"$515.00 PSA 9",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Last Sold: %q is missing", want)
		}
	}
	if strings.Contains(body, "ebay.com/itm/333") {
		t.Error("Last Sold lists a grade no store lists the card in")
	}
	psa, cgc := strings.Index(body, "ebay.com/itm/111"), strings.Index(body, "items/W1")
	if psa < 0 || cgc < 0 || psa > cgc {
		t.Error("Last Sold does not follow the page's order of grades")
	}
	if strings.Contains(body, "No sales on record") || strings.Contains(body, "Condition: PSA") {
		t.Error("Last Sold says there are no sales, or heads a grade as a condition")
	}

	// Without the sales, the column says how to get them.
	withSigMode(t, true, true)
	rec = httptest.NewRecorder()
	testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/graded?q="+cards[0], nil))
	body = rec.Body.String()
	if strings.Contains(body, "ebay.com/itm/111") || !strings.Contains(body, `data-track-value="sales_upsell"`) {
		t.Error("a reader without the sales sees them, or no upsell")
	}
}

// The Graded page's random card is always one a graded store the reader sees
// lists, never a raw card or one only a blocked or hidden store lists.
func TestRandomGradedSearch(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	cards := somePlainCardUUIDs(t, 3)
	slab := &mtgban.Slab{Grader: "PSA", Score: 9}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[0]: {{Conditions: "NM", Price: 10, URL: "u"}},
		}, mtgban.ScraperInfo{Name: "RAWSHOP", Shorthand: "RAWSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[1]: {{Conditions: "NM", Price: 40, URL: "u", Slab: slab}},
		}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			cards[2]: {{Conditions: "NM", Price: 40, URL: "u", Slab: slab}},
		}, mtgban.ScraperInfo{Name: "HIDDENSLABS", Shorthand: "HIDDENSLABS", GradedMode: true}),
	}, nil)
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"HIDDENSLABS"}

	for range 30 {
		rec := httptest.NewRecorder()
		testSite.RandomGradedSearch(rec, httptest.NewRequest(http.MethodGet, "/randomgraded", nil))
		want := "/graded?q=" + cards[1]
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
			t.Fatalf("redirect %d to %q, want %q", rec.Code, rec.Header().Get("Location"), want)
		}
	}

	// A store the reader hid in their store choices is skipped too.
	Config().Stores.SearchRetailBlockList = nil
	for range 30 {
		req := httptest.NewRequest(http.MethodGet, "/randomgraded", nil)
		req.Header.Set("Cookie", "SearchSellersList=SLABSHOP,")
		rec := httptest.NewRecorder()
		testSite.RandomGradedSearch(rec, req)
		want := "/graded?q=" + cards[2]
		if rec.Header().Get("Location") != want {
			t.Fatalf("with SLABSHOP hidden, redirect to %q, want %q", rec.Header().Get("Location"), want)
		}
	}
}
