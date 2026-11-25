package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/salesvelocity"
)

// The median sale is a section of Arbit's for a reader with SearchSales, and
// of no other page's or reader's.
func TestArbitMedianSales(t *testing.T) {
	skipWithoutDatastore(t)
	readyToRender(t)
	signingEnabled(t, true)
	for _, page := range []string{"Arbitrage", "Global"} {
		if LogPages[page] == nil {
			LogPages[page] = log.New(io.Discard, "", 0)
			t.Cleanup(func() { delete(LogPages, page) })
		}
	}
	stores := &Config().Stores
	allow, probe := stores.GlobalAllowList, stores.GlobalProbeList
	t.Cleanup(func() { stores.GlobalAllowList, stores.GlobalProbeList = allow, probe })
	stores.GlobalAllowList, stores.GlobalProbeList = []string{"MEDSHOP"}, []string{"DEARSHOP"}

	boxes := backend().GetSealedUUIDsInSet("MH2")
	if len(boxes) == 0 {
		t.Fatal("no sealed product to list")
	}
	box := boxes[0]
	const bolt = "78380203-7623-50bc-ab48-577cd655ee9a"
	at := uint32(time.Now().Add(-time.Hour).Unix())
	recent := &salesvelocity.Recent{}
	recent.Grades[1] = slices.Repeat([]salesvelocity.Order{{At: at, Cents: 4000, Qty: 1}}, 5)
	unopened := &salesvelocity.Recent{}
	unopened.Grades[5] = slices.Repeat([]salesvelocity.Order{{At: at, Cents: 20000, Qty: 1}}, 5)
	saved := recentSalesStore.Snapshot()
	recentSalesStore.Publish(&salesvelocity.RecentSnapshot{Cards: map[string]*salesvelocity.Recent{bolt: recent, box: unopened}})
	t.Cleanup(func() { recentSalesStore.Publish(saved) })

	// Nothing sold NM, so only the SP copy has a median sale to compare with.
	// The buylist and the second seller give every page a section to draw.
	stock := mtgban.InventoryRecord{bolt: {
		{Conditions: "NM", Price: 10, Quantity: 2, URL: "u"},
		{Conditions: "SP", Price: 10, Quantity: 2, URL: "u"},
	}}
	sealed := mtgban.InventoryRecord{box: {{Conditions: "NM", Price: 100, Quantity: 2, URL: "u"}}}
	// A product whose contents simulate unevenly, bought by one sealed store
	sim := mtgban.InventoryRecord{box: {{Conditions: "NM", Price: 1, ExtraValues: map[string]float64{"iqr": IQRThreshold + 1}}}}
	sealedBuylist := mtgban.BuylistRecord{box: {{Conditions: "NM", BuyPrice: 90}}}
	dear := mtgban.InventoryRecord{bolt: {{Conditions: "NM", Price: 100, Quantity: 2, URL: "u"}}}
	buylist := mtgban.BuylistRecord{bolt: {{Conditions: "NM", BuyPrice: 60}}}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{Name: "Median Shop", Shorthand: "MEDSHOP"}),
		mtgban.NewSellerFromInventory(dear, mtgban.ScraperInfo{Name: "Dear Shop", Shorthand: "DEARSHOP"}),
		mtgban.NewSellerFromInventory(sealed, mtgban.ScraperInfo{Name: "Box Shop", Shorthand: "BOXSHOP", SealedMode: true}),
		mtgban.NewSellerFromInventory(sim, mtgban.ScraperInfo{Name: "TCG Low Sim", Shorthand: "TCGLowSim", SealedMode: true, MetadataOnly: true}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Name: "Median Buyer", Shorthand: "MEDBUY"}),
		mtgban.NewVendorFromBuylist(sealedBuylist, mtgban.ScraperInfo{Name: "Box Buyer", Shorthand: "BOXBUY", SealedMode: true}),
	})

	render := func(path string, handler http.HandlerFunc, sales string) string {
		fields := url.Values{
			"UserEmail": {"reader@example.com"}, "UserTier": {"Test"},
			"ArbitEnabled": {"ALL"}, "AnyEnabled": {"true"}, "SearchSales": {sales},
		}
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
		rec := httptest.NewRecorder()
		handler(rec, r)
		return rec.Body.String()
	}
	const section = `data-store="TCGSales"`

	page := render("/arbit?source=MEDSHOP", testSite.Arbit, "true")
	_, median, found := strings.Cut(page, section)
	if !found {
		t.Fatalf("no median sale section in the %d byte page", len(page))
	}
	for _, want := range []string{"TCG Median Sales", "Median Sales", "$ 40.00", "300.00 %", "tcgplayer.com/product/", "Condition=Lightly"} {
		if !strings.Contains(median, want) {
			t.Errorf("the section lacks %q", want)
		}
	}
	if strings.Count(median, "data-arb-id=") != 1 {
		t.Errorf("%d rows, want the SP copy's alone", strings.Count(median, "data-arb-id="))
	}
	if strings.Contains(median, "Ratio") {
		t.Error("the section has a buylist's ratio")
	}

	page = render("/arbit?source=BOXSHOP", testSite.Arbit, "true")
	buylists, median, _ := strings.Cut(page, section)
	const warning = "arb-price-warn"
	if !strings.Contains(buylists, warning) {
		t.Error("the sealed buylist lost its simulation warning")
	}
	if strings.Contains(median, warning) {
		t.Error("the median sale has the simulation warning")
	}
	for _, want := range []string{"$ 200.00", "tcgplayer.com/product/"} {
		if !strings.Contains(median, want) {
			t.Errorf("the sealed section lacks %q", want)
		}
	}
	if strings.Contains(median, "Condition=") {
		t.Error("a sealed product's Sell link asks for a condition")
	}

	none := map[string]string{
		"without SearchSales": render("/arbit?source=MEDSHOP", testSite.Arbit, "false"),
		"reverse":             render("/reverse?source=MEDBUY", testSite.Reverse, "true"),
		"global":              render("/global?source=MEDSHOP&legit=0", testSite.Global, "true"),
	}
	for name, page := range none {
		if !strings.Contains(page, `class="arb-section"`) {
			t.Errorf("%s: no section at all in the %d byte page", name, len(page))
		}
		if strings.Contains(page, section) {
			t.Errorf("%s: the median sale shows", name)
		}
	}
}
