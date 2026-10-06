package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

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
		AllUUIDs:       []string{"lor-1", "lor-2", "lor-3"},
		AllSealedUUIDs: []string{"box"},
		UUIDs: map[string]*mtgmatcher.CardObject{
			"lor-1": card("lor-1", "nonfoil"),
			"lor-2": card("lor-2", "coldfoil"),
			"lor-3": card("lor-3", "nonfoil"),
			"box":   box,
		},
	}
}

// seedV2Scrapers publishes a store pricing by condition, an index, TCGplayer and its Direct
// (two Direct listings in one condition, its stock covering both), a store that
// counts its copies but keeps no quantities, a sealed store, a buyer by condition,
// a want-count index buyer and an index buyer. The listings scrape was capped
// on the coldfoil.
func seedV2Scrapers(t *testing.T) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	setTestTCGDirect(t, map[string]*tcgListings{
		"lor-1": {Direct: [5]int32{7}, Copies: [5]int32{20, 5}},
		"lor-2": {Copies: [5]int32{3}, Capped: true},
	})

	ct := mtgban.InventoryRecord{}
	ct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1, Quantity: 3, Available: 10, SellerName: "a"})
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
	direct.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 2.5, SellerName: "other"})

	tcg := mtgban.InventoryRecord{}
	tcg.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1.3})
	tcg.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1})
	tcg.Add("lor-2", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 40})

	mp := mtgban.InventoryRecord{}
	mp.Add("lor-1", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1.05, Available: 8})
	mp.Add("lor-3", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 0.95, Available: 4})
	mp.Add("lor-3", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 0.7})

	sealed := mtgban.InventoryRecord{}
	sealed.Add("box", &mtgban.InventoryEntry{Price: 99, Quantity: 5})

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(ct, mtgban.ScraperInfo{Name: "Card Trader", Shorthand: "CT"}),
		mtgban.NewSellerFromInventory(trend, mtgban.ScraperInfo{Name: "Cardmarket Trend", Shorthand: "MKMTrend", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(direct, mtgban.ScraperInfo{Name: "TCGplayer Direct", Shorthand: tcgDirectStore, NoQuantityInventory: true}),
		mtgban.NewSellerFromInventory(tcg, mtgban.ScraperInfo{Name: "TCGplayer", Shorthand: tcgListingsStore, NoQuantityInventory: true}),
		mtgban.NewSellerFromInventory(mp, mtgban.ScraperInfo{Name: "Mana Pool", Shorthand: "MP", NoQuantityInventory: true}),
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
		mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK", CreditMultiplier: 1.3}),
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

// TestPriceAPIv2Prices files every condition a store prices under the product's
// finish, merging the two nonfoil uuids condition by condition, and gives the same
// answer from a full dump and from a request for the cards.
func TestPriceAPIv2Prices(t *testing.T) {
	seedV2Scrapers(t)
	b := v2Backend()
	cards := []string{"lor-1", "lor-2", "lor-3"}
	stores := []string{"CT", "MKMTrend", "MP", tcgDirectStore, tcgListingsStore, "CTSealed", "CK", "SYP", "IDXV"}

	wantRetail := `{"600001":{` +
		`"coldfoil":{"CT":[{"condition":"SP","price":38,"qty":1}],"MKMTrend":[{"price":35}],"TCGPlayer":[{"condition":"NM","price":40}]},` +
		`"nonfoil":{` +
		`"CT":[{"condition":"NM","price":0.9,"qty":6,"available":10},{"condition":"SP","price":0.8,"qty":1},{"condition":"MP","price":0.5,"qty":4}],` +
		`"MKMTrend":[{"price":1.1}],` +
		`"MP":[{"condition":"NM","price":0.95,"available":12},{"condition":"SP","price":0.7}],` +
		`"TCGDirect":[{"condition":"NM","price":2,"available":7}],` +
		`"TCGPlayer":[{"condition":"NM","price":1.3,"available":20},{"condition":"SP","price":1,"available":5}]}}}`
	wantBuylist := `{"600001":{"nonfoil":{` +
		`"CK":[{"condition":"NM","price":0.6,"qty":5},{"condition":"SP","price":0.4,"qty":2}],` +
		`"IDXV":[{"price":0.3}],` +
		`"SYP":[{"price":0.7,"qty":12}]}}}`

	for _, tc := range []struct {
		name  string
		cards []string
	}{
		{"full dump", nil},
		{"filtered", cards},
	} {
		retail := getSellerPricesV2(b, "mkm", stores, "", tc.cards, "", false)
		if got := wireOf(t, retail); got != wantRetail {
			t.Errorf("%s retail =\n%s\nwant\n%s", tc.name, got, wantRetail)
		}
		buylist := getVendorPricesV2(b, "mkm", stores, "", tc.cards, "", false)
		if got := wireOf(t, buylist); got != wantBuylist {
			t.Errorf("%s buylist =\n%s\nwant\n%s", tc.name, got, wantBuylist)
		}
	}

	sealed := getSellerPricesV2(b, "mkm", stores, "", nil, "", true)
	want := `{"700":{"sealed":{"CTSealed":[{"price":99,"qty":5}]}}}`
	if got := wireOf(t, sealed); got != want {
		t.Errorf("sealed =\n%s\nwant\n%s", got, want)
	}
}

// TestPriceAPIv2Route serves v2 at /api/v2/, with the version in the meta,
// and leaves v1 as it was.
func TestPriceAPIv2Route(t *testing.T) {
	withSigMode(t, true, false)
	seedV2Scrapers(t)
	prevOverrides := Config().ScraperConfig.NameOverride
	t.Cleanup(func() { Config().ScraperConfig.NameOverride = prevOverrides })
	Config().ScraperConfig.NameOverride = map[string]string{"Card Trader": "CardTrader"}

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
	entries := v2.Retail["600001"]["nonfoil"]["CT"]
	if len(entries) != 3 || entries[0] != (banprice.Entry{Condition: "NM", Price: 0.9, Qty: 6, Available: 10}) {
		t.Errorf("v2 CT nonfoil = %+v", entries)
	}

	var v1 PriceAPIOutput
	get(s.PriceAPI, "/api/mtgban/retail.json?id=mkm&vendor=CT", &v1)
	if v1.Meta.Version != APIVersion || v1.Retail["600001"]["CT"] == nil {
		t.Errorf("v1 = %+v", v1)
	}

	var stores banprice.Stores
	get(s.PriceAPIv2, "/api/v2/stores.json", &stores)
	sellers := map[string]banprice.Store{}
	for _, store := range stores.Sellers {
		sellers[store.Shorthand] = store
	}
	vendors := map[string]banprice.Store{}
	for _, store := range stores.Vendors {
		vendors[store.Shorthand] = store
	}
	for _, tc := range []struct {
		name string
		got  banprice.Store
		want banprice.Store
	}{
		{"CT", sellers["CT"], banprice.Store{Shorthand: "CT", Name: "CardTrader", Quantities: true}},
		{"MKMTrend", sellers["MKMTrend"], banprice.Store{Shorthand: "MKMTrend", Name: "Cardmarket Trend", Index: true}},
		{"TCGDirect", sellers[tcgDirectStore], banprice.Store{Shorthand: tcgDirectStore, Name: "TCGplayer Direct"}},
		{"CTSealed", sellers["CTSealed"], banprice.Store{Shorthand: "CTSealed", Name: "Card Trader Sealed", Sealed: true, Quantities: true}},
		{"CK", vendors["CK"], banprice.Store{Shorthand: "CK", Name: "Card Kingdom", Quantities: true, CreditMultiplier: 1.3}},
		{"SYP", vendors["SYP"], banprice.Store{Shorthand: "SYP", Name: "TCG SYP", Index: true, Quantities: true}},
		{"IDXV", vendors["IDXV"], banprice.Store{Shorthand: "IDXV", Name: "Index Buyer", Index: true}},
	} {
		if tc.got != tc.want {
			t.Errorf("v2 stores.json %s = %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}

	// An id system v2 does not know is refused, where v1 falls back to mtgban
	var unknown PriceAPIOutputV2
	get(s.PriceAPIv2, "/api/v2/retail.json?id=tcgplayer", &unknown)
	if !strings.Contains(unknown.Error, `unknown id "tcgplayer"`) || unknown.Retail != nil {
		t.Errorf("v2 id=tcgplayer: error %q, %d cards", unknown.Error, len(unknown.Retail))
	}
	var fallback PriceAPIOutput
	get(s.PriceAPI, "/api/mtgban/retail.json?id=tcgplayer", &fallback)
	if fallback.Error != "" || len(fallback.Retail) == 0 {
		t.Errorf("v1 id=tcgplayer: error %q, %d cards", fallback.Error, len(fallback.Retail))
	}

	// v2 keys prices by shorthand whatever tag asks for
	var named PriceAPIOutputV2
	get(s.PriceAPIv2, "/api/v2/retail.json?id=mkm&tag=names", &named)
	if named.Retail["600001"]["nonfoil"]["CT"] == nil {
		t.Errorf("tag=names keys %v, want CT among them", named.Retail["600001"]["nonfoil"])
	}

	stores = banprice.Stores{}
	get(s.PriceAPIv2, "/api/v2/stores.json?filter=sealed", &stores)
	if len(stores.Sellers) != 1 || stores.Sellers[0].Shorthand != "CTSealed" || len(stores.Vendors) != 0 {
		t.Errorf("v2 stores.json?filter=sealed = %+v", stores)
	}
}

// TestPriceAPIv2Finishes lists the finishes v2 keys the game's prices by,
// commonest first, as JSON and CSV.
func TestPriceAPIv2Finishes(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	s.ds.Store(s.newDatastore(v2Backend(), time.Now()))

	get := func(url string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		s.PriceAPIv2(rec, httptest.NewRequest(http.MethodGet, url, nil))
		return rec.Body.String()
	}
	for _, tc := range []struct{ url, want string }{
		{"/api/v2/finishes.json", `[{"value":"nonfoil","label":"Non-foil","count":2},{"value":"coldfoil","label":"Cold Foil","count":1},{"value":"sealed","label":"Sealed","count":1}]` + "\n"},
		{"/api/v2/finishes.json?filter=singles", `[{"value":"nonfoil","label":"Non-foil","count":2},{"value":"coldfoil","label":"Cold Foil","count":1}]` + "\n"},
		{"/api/v2/finishes.json?filter=sealed", `[{"value":"sealed","label":"Sealed","count":1}]` + "\n"},
		{"/api/v2/finishes.csv", "Value,Label,Count\nnonfoil,Non-foil,2\ncoldfoil,Cold Foil,1\nsealed,Sealed,1\n"},
	} {
		got := get(tc.url)
		if got != tc.want {
			t.Errorf("%s =\n%s\nwant\n%s", tc.url, got, tc.want)
		}
	}

	// Before the first load there are no finishes, still an array
	empty := newSite()
	rec := httptest.NewRecorder()
	empty.PriceAPIv2(rec, httptest.NewRequest(http.MethodGet, "/api/v2/finishes.json", nil))
	if rec.Body.String() != "[]\n" {
		t.Errorf("finishes.json before a load = %q, want []", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.PriceAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgban/finishes.json", nil))
	if strings.HasPrefix(rec.Body.String(), "[") {
		t.Errorf("v1 serves finishes.json: %s", rec.Body.String())
	}
}

// TestPriceAPIv2EveryEndpoint calls every v2 endpoint against the datastore:
// each answers as version 2, the prices ones with the seeded stores' prices.
func TestPriceAPIv2EveryEndpoint(t *testing.T) {
	regular, foil, sealed := parityCards(t)
	seedParityScrapers(t, regular, foil)
	withSigMode(t, true, false)

	co, err := backend().GetUUID(regular)
	if err != nil {
		t.Fatal(err)
	}
	sealedCo, err := backend().GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}

	call := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		testSite.PriceAPIv2(rec, httptest.NewRequest(http.MethodGet, "/api/v2/"+path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
		return rec
	}

	for _, tc := range []struct {
		path    string
		retail  bool
		buylist bool
	}{
		{"retail.json", true, false},
		{"buylist.json", false, true},
		{"all.json", true, true},
		{"retail/" + co.SetCode + ".json", true, false},
		{"buylist/" + co.SetCode + ".json", false, true},
		{"all/" + co.SetCode + ".json", true, true},
		{"retail/" + regular + ".json", true, false},
		{"buylist/" + regular + ".json", false, true},
		{"sealed/" + sealedCo.SetCode + ".json", false, false},
	} {
		var out PriceAPIOutputV2
		rec := call(tc.path)
		err := json.Unmarshal(rec.Body.Bytes(), &out)
		if err != nil || out.Error != "" || out.Meta.Version != APIVersionV2 {
			t.Errorf("%s: version %q error %q (%v)", tc.path, out.Meta.Version, out.Error, err)
			continue
		}
		if tc.retail && out.Retail[regular]["nonfoil"]["PARITYA"] == nil {
			t.Errorf("%s: no retail price for the seeded card", tc.path)
		}
		if tc.buylist && out.Buylist[regular]["nonfoil"]["PARITYV"] == nil {
			t.Errorf("%s: no buylist price for the seeded card", tc.path)
		}
	}

	csvBody := call("retail/" + co.SetCode + ".csv").Body.String()
	if strings.HasPrefix(csvBody, "{") || !strings.Contains(csvBody, ",") {
		t.Errorf("retail csv: %.200s", csvBody)
	}

	var sets []string
	err = json.Unmarshal(call("sets.json").Body.Bytes(), &sets)
	if err != nil || !slices.Contains(sets, co.SetCode) {
		t.Errorf("sets.json: %v, %d sets", err, len(sets))
	}
	var stores banprice.Stores
	err = json.Unmarshal(call("stores.json").Body.Bytes(), &stores)
	if err != nil || len(stores.Sellers) == 0 || len(stores.Vendors) == 0 {
		t.Errorf("stores.json: %v, %+v", err, stores)
	}
	var finishes []banprice.Finish
	err = json.Unmarshal(call("finishes.json").Body.Bytes(), &finishes)
	if err != nil || !slices.ContainsFunc(finishes, func(f banprice.Finish) bool { return f.Value == co.Finish }) {
		t.Errorf("finishes.json: %v, %+v", err, finishes)
	}
	for _, path := range []string{"sets.csv", "stores.csv", "finishes.csv"} {
		body := call(path).Body.String()
		if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
			t.Errorf("%s is not CSV: %.200s", path, body)
		}
	}
}

// TestPriceAPIv2CardmarketIDs keys v2's id=mkm on the product the Cardmarket
// shelves price a card under, over the datastore's id, which answers only
// for a card the shelves do not price: Low first, then Trend, for singles,
// and Sealed for sealed product, on retail and buylist alike. v1 keeps the
// datastore's.
func TestPriceAPIv2CardmarketIDs(t *testing.T) {
	card := func(uuid, mcmID string, sealed bool) *mtgmatcher.CardObject {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Identifiers: map[string]string{}}, Sealed: sealed}
		if mcmID != "" {
			co.Identifiers["mcmId"] = mcmID
		}
		co.Finish = "nonfoil"
		return co
	}
	b := &mtgmatcher.Backend{
		AllUUIDs: []string{"unlisted", "moved", "unpriced", "trend-only", "box"},
		UUIDs: map[string]*mtgmatcher.CardObject{
			"unlisted":   card("unlisted", "", false),
			"moved":      card("moved", "600001", false),
			"unpriced":   card("unpriced", "620000", false),
			"trend-only": card("trend-only", "", false),
			"box":        card("box", "", true),
		},
	}

	singles := []string{"unlisted", "moved", "unpriced", "trend-only"}

	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })
	low := mtgban.InventoryRecord{}
	low.Add("unlisted", &mtgban.InventoryEntry{Price: 1, OriginalID: "700001"})
	low.Add("moved", &mtgban.InventoryEntry{Price: 2, OriginalID: "610000"})
	trend := mtgban.InventoryRecord{}
	trend.Add("unlisted", &mtgban.InventoryEntry{Price: 1, OriginalID: "700001"})
	trend.Add("trend-only", &mtgban.InventoryEntry{Price: 3, OriginalID: "710000"})
	// A single the sealed shelf names is not keyed from it.
	sealedShelf := mtgban.InventoryRecord{}
	sealedShelf.Add("box", &mtgban.InventoryEntry{Price: 90, OriginalID: "500001"})
	sealedShelf.Add("unpriced", &mtgban.InventoryEntry{Price: 9, OriginalID: "999999"})
	ct, cts := mtgban.InventoryRecord{}, mtgban.InventoryRecord{}
	for _, uuid := range b.AllUUIDs {
		record := ct
		if b.UUIDs[uuid].Sealed {
			record = cts
		}
		record.Add(uuid, &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 5})
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(trend, mtgban.ScraperInfo{Name: "Cardmarket Trend", Shorthand: "MKMTrend", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(low, mtgban.ScraperInfo{Name: "Cardmarket Low", Shorthand: "MKMLow", MetadataOnly: true}),
		mtgban.NewSellerFromInventory(sealedShelf, mtgban.ScraperInfo{Name: "Cardmarket Sealed", Shorthand: "MKMSealed", SealedMode: true}),
		mtgban.NewSellerFromInventory(ct, mtgban.ScraperInfo{Name: "Card Trader", Shorthand: "CT"}),
		mtgban.NewSellerFromInventory(cts, mtgban.ScraperInfo{Name: "Card Trader Sealed", Shorthand: "CTSealed", SealedMode: true}),
	}
	sellersPtr.Store(&sellers)
	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prevVendors) })
	ck := mtgban.BuylistRecord{}
	for _, uuid := range singles {
		ck.Add(uuid, &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1})
	}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"})}
	vendorsPtr.Store(&vendors)

	ids := func(prices map[string]map[string]map[string][]banprice.Entry) []string {
		var out []string
		for id := range prices {
			out = append(out, id)
		}
		slices.Sort(out)
		return out
	}
	want := []string{"610000", "620000", "700001", "710000"}
	for _, cards := range [][]string{nil, singles} {
		got := ids(getSellerPricesV2(b, "mkm", []string{"CT"}, "", cards, "", false))
		if !slices.Equal(got, want) {
			t.Errorf("v2 ids for %v = %v, want %v", cards, got, want)
		}
		got = ids(getVendorPricesV2(b, "mkm", []string{"CK"}, "", cards, "", false))
		if !slices.Equal(got, want) {
			t.Errorf("v2 buylist ids for %v = %v, want %v", cards, got, want)
		}
	}
	got := ids(getSellerPricesV2(b, "mkm", []string{"CTSealed"}, "", nil, "", true))
	if !slices.Equal(got, []string{"500001"}) {
		t.Errorf("v2 sealed ids = %v, want the sealed shelf's", got)
	}

	var v1 []string
	for id := range getSellerPrices(b, "mkm", []string{"CT"}, "", nil, "", false, false, false, "") {
		v1 = append(v1, id)
	}
	slices.Sort(v1)
	if !slices.Equal(v1, []string{"600001", "620000"}) {
		t.Errorf("v1 ids = %v, want the datastore's", v1)
	}
}
