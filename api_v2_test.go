package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/banprice"
)

// v2Backend holds one Cardmarket product sold in two finishes, with two
// uuids of its nonfoil, and a sealed product.
func v2Backend() *mtgmatcher.Backend {
	card := func(uuid, finish string) *mtgmatcher.CardObject {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Identifiers: map[string]string{"mcmId": "600001"}}}
		co.Finish = finish
		return co
	}
	box := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: "box", Identifiers: map[string]string{"mcmId": "700"}}, Sealed: true}
	return &mtgmatcher.Backend{
		AllUUIDs: []string{"lor-1", "lor-2", "lor-3", "box"},
		UUIDs: map[string]*mtgmatcher.CardObject{
			"lor-1": card("lor-1", "nonfoil"),
			"lor-2": card("lor-2", "coldfoil"),
			"lor-3": card("lor-3", "nonfoil"),
			"box":   box,
		},
	}
}

// seedV2Scrapers publishes a graded store, an index, TCGplayer Direct, a
// sealed store, a graded buyer, a want-count index buyer and an index buyer.
func seedV2Scrapers(t *testing.T) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	setTestTCGDirect(t, map[string]*tcgListings{"lor-1": {Direct: [5]int32{7}}})

	ct := mtgban.InventoryRecord{}
	ct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1, Quantity: 3, SellerName: "a"})
	ct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1.5, Quantity: 2, SellerName: "b"})
	ct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 0.8, Quantity: 1})
	ct.Add("lor-3", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 0.9, Quantity: 1})
	ct.Add("lor-3", &mtgban.InventoryEntry{Conditions: mtgban.MP, Price: 0.5, Quantity: 4})
	ct.Add("lor-2", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 38, Quantity: 1})

	trend := mtgban.InventoryRecord{}
	trend.Add("lor-1", &mtgban.InventoryEntry{Price: 1.1})
	trend.Add("lor-2", &mtgban.InventoryEntry{Price: 35})

	direct := mtgban.InventoryRecord{}
	direct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 2})

	sealed := mtgban.InventoryRecord{}
	sealed.Add("box", &mtgban.InventoryEntry{Price: 99, Quantity: 5})

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(ct, mtgban.ScraperInfo{Name: "Card Trader", Shorthand: "CT"}),
		mtgban.NewSellerFromInventory(trend, mtgban.ScraperInfo{Name: "Cardmarket Trend", Shorthand: "MKMTrend", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(direct, mtgban.ScraperInfo{Name: "TCGplayer Direct", Shorthand: tcgDirectStore, NoQuantityInventory: true}),
		mtgban.NewSellerFromInventory(sealed, mtgban.ScraperInfo{Name: "Card Trader Sealed", Shorthand: "CTSealed", SealedMode: true}),
	}
	sellersPtr.Store(&sellers)

	ck := mtgban.BuylistRecord{}
	ck.Add("lor-1", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 0.5, Quantity: 4})
	ck.Add("lor-3", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 0.6, Quantity: 1})
	ck.Add("lor-1", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 0.4, Quantity: 2})

	syp := mtgban.BuylistRecord{}
	syp.Add("lor-1", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 0.7, Quantity: 12})

	idx := mtgban.BuylistRecord{}
	idx.Add("lor-1", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 0.3, Quantity: 2})

	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"}),
		mtgban.NewVendorFromBuylist(syp, mtgban.ScraperInfo{Name: "TCG SYP", Shorthand: "SYP", MetadataOnly: true, QuantityPriority: true}),
		mtgban.NewVendorFromBuylist(idx, mtgban.ScraperInfo{Name: "Index Buyer", Shorthand: "IDXV", MetadataOnly: true}),
	}
	vendorsPtr.Store(&vendors)
}

func wireOf(t *testing.T, v any) string {
	t.Helper()
	wire, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

// TestPriceAPIv2Prices files every grade a store has under the product's
// finish, merging the two nonfoil uuids grade by grade, and gives the same
// answer from a full dump and from a request for the cards.
func TestPriceAPIv2Prices(t *testing.T) {
	seedV2Scrapers(t)
	b := v2Backend()
	cards := []string{"lor-1", "lor-2", "lor-3"}
	stores := []string{"CT", "MKMTrend", tcgDirectStore, "CTSealed", "CK", "SYP", "IDXV"}

	wantRetail := `{"600001":{` +
		`"coldfoil":{"CT":[{"grade":"SP","price":38,"qty":1}],"MKMTrend":[{"price":35}]},` +
		`"nonfoil":{` +
		`"CT":[{"grade":"NM","price":0.9,"qty":6},{"grade":"SP","price":0.8,"qty":1},{"grade":"MP","price":0.5,"qty":4}],` +
		`"MKMTrend":[{"price":1.1}],` +
		`"TCGDirect":[{"grade":"NM","price":2,"qty":7}]}}}`
	wantBuylist := `{"600001":{"nonfoil":{` +
		`"CK":[{"grade":"NM","price":0.6,"qty":5},{"grade":"SP","price":0.4,"qty":2}],` +
		`"IDXV":[{"price":0.3}],` +
		`"SYP":[{"price":0.7,"qty":12}]}}}`

	for _, tc := range []struct {
		name  string
		cards []string
	}{
		{"full dump", nil},
		{"filtered", cards},
	} {
		retail := getSellerPricesV2(b, "mkm", stores, "", tc.cards, "", false, "")
		if got := wireOf(t, retail); got != wantRetail {
			t.Errorf("%s retail =\n%s\nwant\n%s", tc.name, got, wantRetail)
		}
		buylist := getVendorPricesV2(b, "mkm", stores, "", tc.cards, "", false, "")
		if got := wireOf(t, buylist); got != wantBuylist {
			t.Errorf("%s buylist =\n%s\nwant\n%s", tc.name, got, wantBuylist)
		}
	}

	sealed := getSellerPricesV2(b, "mkm", stores, "", nil, "", true, "names")
	want := `{"700":{"sealed":{"Card Trader Sealed":[{"price":99,"qty":5}]}}}`
	if got := wireOf(t, sealed); got != want {
		t.Errorf("sealed =\n%s\nwant\n%s", got, want)
	}
}

// TestPriceAPIv2Route serves v2 at /api/v2/, with the version in the meta,
// and leaves v1 as it was.
func TestPriceAPIv2Route(t *testing.T) {
	withSigMode(t, true, false)
	seedV2Scrapers(t)

	s := newSite()
	s.ds.Store(&datastore{backend: v2Backend()})

	get := func(handler http.HandlerFunc, url string, into any) {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, url, nil))
		err := json.Unmarshal(rec.Body.Bytes(), into)
		if err != nil {
			t.Fatalf("%s: %v\n%s", url, err, rec.Body.String())
		}
	}

	var v2 PriceAPIOutputV2
	get(s.PriceAPIv2, "/api/v2/retail.json?id=mkm&vendor=CT", &v2)
	if v2.Meta.Version != APIVersionV2 || v2.Error != "" {
		t.Errorf("v2 meta %+v, error %q", v2.Meta, v2.Error)
	}
	grades := v2.Retail["600001"]["nonfoil"]["CT"]
	if len(grades) != 3 || grades[0] != (banprice.Entry{Grade: "NM", Price: 0.9, Qty: 6}) {
		t.Errorf("v2 CT nonfoil = %+v", grades)
	}

	var v1 PriceAPIOutput
	get(s.PriceAPI, "/api/mtgban/retail.json?id=mkm&vendor=CT", &v1)
	if v1.Meta.Version != APIVersion || v1.Retail["600001"]["CT"] == nil {
		t.Errorf("v1 = %+v", v1)
	}

	var stores []string
	get(s.PriceAPIv2, "/api/v2/stores.json", &stores)
	if len(stores) == 0 {
		t.Error("v2 lists no stores")
	}
}
