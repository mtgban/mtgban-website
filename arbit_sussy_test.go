package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// reversePageVars is one reverse-mode table whose second entry the page has
// been told not to trust, so the badge has one row to land on and one to
// leave alone.
func reversePageVars() PageVars {
	entry := func(id string, sell, buy float64) mtgban.ArbitEntry {
		return mtgban.ArbitEntry{
			CardID:         id,
			InventoryEntry: mtgban.InventoryEntry{Price: sell, Conditions: "NM", Quantity: 1},
			BuylistEntry:   mtgban.BuylistEntry{BuyPrice: buy},
			Difference:     buy - sell,
			Spread:         100 * (buy - sell) / sell,
		}
	}
	return PageVars{
		ScraperShort: "TCGDirectNet",
		ReverseMode:  true,
		BetaNav:      &NavElem{Short: "beta"},
		Arb: []Arbitrage{
			{Name: "Store One", Key: "ONE", Arbit: []mtgban.ArbitEntry{
				entry("card-a", 10, 14),
				entry("card-b", 20, 23934.02),
			}, SussyList: map[string]float64{"card-b": 483.56}},
		},
		Metadata: map[string]GenericCard{
			"card-a": {Name: "Card A", Edition: "Edition A", SetCode: "AAA"},
			"card-b": {Name: "Card B", Edition: "Edition B", SetCode: "BBB"},
		},
	}
}

// TestReverseSussyBadge pins the warning to the column reverse actually shows.
// The buy price is the one TCG Direct (net) derives from a Direct listing, and
// it is the only price on a reverse row that a bad listing can inflate, but
// the badge used to render only beside a reference price that no reverse page
// ever fills in.
func TestReverseSussyBadge(t *testing.T) {
	page := renderArbit(t, reversePageVars())

	row := page[strings.Index(page, `data-arb-id="card-b"`):]
	row = row[:strings.Index(row, "</tr>")]
	if !strings.Contains(row, "$ 23934.02") {
		t.Fatal("the buy price is missing from the row")
	}
	if !strings.Contains(row, "TCG Market is $483.56") {
		t.Error("the suspect buy price carries no warning")
	}

	clean := page[strings.Index(page, `data-arb-id="card-a"`):]
	clean = clean[:strings.Index(clean, "</tr>")]
	if strings.Contains(clean, "TCG Market is") {
		t.Error("a price the market backs up was flagged anyway")
	}
}

// seedReverseScrapers publishes one real seller, one index seller and one
// vendor, all holding the same card, so a reverse comparison has both kinds
// of buy side to choose between.
func seedReverseScrapers(t *testing.T, cardID string) {
	t.Helper()

	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})

	shopInv := mtgban.InventoryRecord{}
	shopInv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 2, URL: "u"})

	// What an index reports for a card its market has no supply to average
	idxInv := mtgban.InventoryRecord{}
	idxInv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 0.02, URL: "u"})

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(shopInv, mtgban.ScraperInfo{
			Name: "Reverse Shop", Shorthand: "REVSHOP",
		}),
		mtgban.NewSellerFromInventory(idxInv, mtgban.ScraperInfo{
			Name: "Reverse Index", Shorthand: "REVIDX", MetadataOnly: true,
		}),
	}
	sellersPtr.Store(&sellers)

	bl := mtgban.BuylistRecord{}
	bl.Add(cardID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 40, Quantity: 2, URL: "u"})

	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
			Name: "Reverse Buyer", Shorthand: "REVBUY",
		}),
	}
	vendorsPtr.Store(&vendors)
}

// renderReverse runs one reverse comparison the way the handler does.
func renderReverse(t *testing.T, query string) string {
	t.Helper()

	oldDev := DevMode
	DevMode = true
	t.Cleanup(func() { DevMode = oldDev })

	r := httptest.NewRequest("GET", "/reverse?"+query, nil)
	w := httptest.NewRecorder()
	pageVars := PageVars{ReverseMode: true, BetaNav: &NavElem{Short: "beta"}}
	scraperCompare(w, r, pageVars, nil, nil, scraperCompareOpts{AllResults: true})
	return w.Body.String()
}

// TestReverseDropsIndexSellers pins the buy side of a reverse row to something
// that can actually be bought. An index reports a fraction of a cent where its
// market has no supply, and dividing a real buy price by that put every such
// row above every real listing on the page.
func TestReverseDropsIndexSellers(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}
	seedReverseScrapers(t, uuids[0])

	page := renderReverse(t, "source=REVBUY")
	if !strings.Contains(page, "Reverse Shop") {
		t.Fatal("the real seller is missing from the default page")
	}
	if strings.Contains(page, "Reverse Index") {
		t.Error("an index price is still one side of a trade by default")
	}

	page = renderReverse(t, "source=REVBUY&noindex=false")
	if !strings.Contains(page, "Reverse Index") {
		t.Error("turning the option off does not bring the index back")
	}
}

// TestSuspectPriceFor pins which side of a row carries the price a bad TCG
// Direct listing inflates. The derived buy price is the same price on every
// page, so the side it arrives on names it: reverse reads it off the source,
// arbit off the vendor whose table it is. Reading only the source left every
// arbit page unwarned.
func TestSuspectPriceFor(t *testing.T) {
	res := mtgban.ArbitEntry{
		ReferenceEntry: mtgban.InventoryEntry{Price: 11},
		BuylistEntry:   mtgban.BuylistEntry{BuyPrice: 22},
	}
	for _, tt := range []struct {
		desc                    string
		global, reverse         bool
		sourceShort, scraperSho string
		want                    float64
	}{
		{"global reads the reference listing off the probe", true, false, "CK", "TCGDirect", 11},
		{"reverse reads the derived buy price off the source", false, true, "TCGDirectNet", "CK", 22},
		{"arbit reads it off the vendor whose table it is", false, false, "CK", "TCGDirectNet", 22},
		{"a seller of that name in arbit is not the vendor", false, false, "TCGDirectNet", "CK", 0},
		{"an ordinary pairing carries no suspect price", false, false, "CK", "SCG", 0},
		{"and neither does one in reverse", false, true, "CK", "SCG", 0},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			fn := suspectPriceFor(tt.global, tt.reverse, tt.sourceShort, tt.scraperSho)
			if tt.want == 0 {
				if fn != nil {
					t.Errorf("suspectPriceFor(%v, %v, %q, %q) = a price, want none",
						tt.global, tt.reverse, tt.sourceShort, tt.scraperSho)
				}
				return
			}
			if fn == nil {
				t.Fatalf("suspectPriceFor(%v, %v, %q, %q) = none, want %.0f",
					tt.global, tt.reverse, tt.sourceShort, tt.scraperSho, tt.want)
			}
			if got := fn(res); got != tt.want {
				t.Errorf("suspect price = %.0f, want %.0f", got, tt.want)
			}
		})
	}
}
