package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Characterization suite for the search vs price-API unification (see
// todo/unify-price-pipelines.md). Both pipelines walk the same seller/vendor
// records; these tests seed identical synthetic data into both and assert
// where they must agree — and pin, explicitly, where they diverge today so
// the unification work has to flip those pins on purpose.

// parityCards returns a regular (nonfoil) single, a foil single, and a sealed
// product from the datastore, skipping when unavailable.
func parityCards(t *testing.T) (regular, foil, sealed string) {
	t.Helper()
	uuids := backend().GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}
	for _, u := range uuids {
		co, err := backend().GetUUID(u)
		if err != nil || co.Sealed || co.Etched {
			continue
		}
		if co.Foil && foil == "" {
			foil = u
		} else if !co.Foil && regular == "" {
			regular = u
		}
		if regular != "" && foil != "" {
			break
		}
	}
	sealedIDs := backend().GetSealedUUIDs()
	if len(sealedIDs) > 0 {
		sealed = sealedIDs[0]
	}
	if regular == "" || foil == "" || sealed == "" {
		t.Skip("could not find suitable printings")
	}
	return regular, foil, sealed
}

// seedParityScrapers publishes synthetic sellers and vendors covering the
// interesting store shapes: a plain retailer with several conditions, an
// index (MetadataOnly) source, and a vendor with a credit multiplier.
func seedParityScrapers(t *testing.T, regular, foil string) {
	t.Helper()

	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})

	inv := mtgban.InventoryRecord{}
	inv.Add(regular, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 2, URL: "u"})
	inv.Add(regular, &mtgban.InventoryEntry{Conditions: "SP", Price: 8, Quantity: 1, URL: "u"})
	inv.Add(regular, &mtgban.InventoryEntry{Conditions: "PO", Price: 2, Quantity: 5, URL: "u"})
	inv.Add(foil, &mtgban.InventoryEntry{Conditions: "NM", Price: 30, Quantity: 1, URL: "u"})

	idxInv := mtgban.InventoryRecord{}
	idxInv.Add(regular, &mtgban.InventoryEntry{Conditions: "NM", Price: 11, URL: "u"})

	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
			Name: "Parity Store", Shorthand: "PARITYA",
		}),
		mtgban.NewSellerFromInventory(idxInv, mtgban.ScraperInfo{
			Name: "Parity Index", Shorthand: "PARITYIDX", MetadataOnly: true,
		}),
	}
	sellersPtr.Store(&sellers)

	bl := mtgban.BuylistRecord{}
	bl.Add(regular, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 5, Quantity: 4, URL: "u"})
	bl.Add(regular, &mtgban.BuylistEntry{Conditions: "SP", BuyPrice: 4, Quantity: 2, URL: "u"})

	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
			Name: "Parity Buyer", Shorthand: "PARITYV", CreditMultiplier: 1.3,
		}),
	}
	vendorsPtr.Store(&vendors)
}

// searchPrice returns the price of the first row for the given store and
// condition bucket, or -1 when the bucket has no row for it.
func searchPrice(found map[string]map[string][]SearchEntry, cardID, cond, shorthand string) float64 {
	for _, res := range found[cardID][cond] {
		if res.Shorthand == shorthand {
			return res.Price
		}
	}
	return -1
}

func TestPriceParityRetail(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIDs := []string{regular, foil}
	config := parseSearchOptionsNG(backend(), regular, nil, nil, nil)
	found := searchSellersNG(cardIDs, config)

	api := getSellerPrices(currentDatastore(), "", []string{"PARITYA", "PARITYIDX"}, "", cardIDs, "", true, true, false, "")

	// Parity: the search row per condition and the API conditions map must
	// carry the same numbers.
	for _, tc := range []struct {
		cond string
		want float64
	}{
		{"NM", 10}, {"SP", 8},
	} {
		if got := searchPrice(found, regular, tc.cond, "PARITYA"); got != tc.want {
			t.Errorf("search %s = %v, want %v", tc.cond, got, tc.want)
		}
		if got := api[regular]["PARITYA"].Conditions.Get(tc.cond); got != tc.want {
			t.Errorf("api conditions[%s] = %v, want %v", tc.cond, got, tc.want)
		}
	}

	// Parity: base price is the best (first) entry on both sides.
	if got := api[regular]["PARITYA"].Regular; got != 10 {
		t.Errorf("api regular = %v, want 10", got)
	}
	if got := api[foil]["PARITYA"].Foil; got != 30 {
		t.Errorf("api foil = %v, want 30", got)
	}
	if got := searchPrice(found, foil, "NM", "PARITYA"); got != 30 {
		t.Errorf("search foil NM = %v, want 30", got)
	}

	// Parity: index sellers are reported by both (search reroutes the rows
	// into the INDEX bucket, the API drops the base condition tag).
	if got := searchPrice(found, regular, "INDEX", "PARITYIDX"); got != 11 {
		t.Errorf("search INDEX = %v, want 11", got)
	}
	if got := api[regular]["PARITYIDX"].Regular; got != 11 {
		t.Errorf("api index regular = %v, want 11", got)
	}
	if got := api[regular]["PARITYIDX"].Cond; got != "" {
		t.Errorf("api index cond = %q, want empty", got)
	}

	// Parity (was divergence #3 in the plan): the walk exports every
	// condition on both sides; hiding PO rows when NM and SP exist is a
	// website display policy applied in CSS (search.css .cond-PO rule).
	if got := searchPrice(found, regular, "PO", "PARITYA"); got != 2 {
		t.Errorf("search PO = %v, want 2", got)
	}
	if got := api[regular]["PARITYA"].Conditions.Get("PO"); got != 2 {
		t.Errorf("api conditions[PO] = %v, want 2", got)
	}

	// Pin: the API sums quantities across every condition, PO included.
	if got := api[regular]["PARITYA"].Qty; got != 8 {
		t.Errorf("api qty = %v, want 8", got)
	}
}

// Decklist/hashing searches repeat a uuid once per copy; the walks must
// still produce one row per store entry, not one per copy (this used to be
// guarded by the isSame dedup scan, now by deduping the ids up front).
func TestWalkRepeatedIds(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIDs := []string{regular, regular, regular, regular}
	config := parseSearchOptionsNG(backend(), regular, nil, nil, nil)

	found := searchSellersNG(cardIDs, config)
	for _, cond := range []string{"NM", "SP", "PO"} {
		if got := len(found[regular][cond]); got != 1 {
			t.Errorf("sellers %s rows = %d, want 1", cond, got)
		}
	}

	foundBl := searchVendorsNG(cardIDs, config)
	for _, cond := range []string{"NM", "SP"} {
		if got := len(foundBl[regular][cond]); got != 1 {
			t.Errorf("vendors %s rows = %d, want 1", cond, got)
		}
	}
}

func TestPriceParityBuylist(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIDs := []string{regular}
	config := parseSearchOptionsNG(backend(), regular, nil, nil, nil)
	found := searchVendorsNG(cardIDs, config)

	api := getVendorPrices(currentDatastore(), "", []string{"PARITYV"}, "", cardIDs, "", true, true, false, "")

	// Parity: raw buylist prices must match; the credit multiplier is a
	// search-side display value layered on the same base number.
	if got := searchPrice(found, regular, "NM", "PARITYV"); got != 5 {
		t.Errorf("search NM = %v, want 5", got)
	}
	if got := api[regular]["PARITYV"].Conditions.Get("NM"); got != 5 {
		t.Errorf("api conditions[NM] = %v, want 5", got)
	}
	if got := api[regular]["PARITYV"].Regular; got != 5 {
		t.Errorf("api regular = %v, want 5", got)
	}

	for _, res := range found[regular]["NM"] {
		if res.Shorthand == "PARITYV" && res.Credit != 5*1.3 {
			t.Errorf("search credit = %v, want %v", res.Credit, 5*1.3)
		}
	}
}

// A vendor like SYP flags QuantityPriority because its rows are a count of
// copies wanted, not an offer; quantityUnit reads that flag into the
// PriceUnit the template keys its display off. searchSellersNG already
// copied the flag from Info() - searchVendorsNG silently didn't, so every
// buylist result read as a price no matter what the vendor declared.
func TestSearchVendorsCarriesQuantityPriority(t *testing.T) {
	regular, _, _ := parityCards(t)

	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prevVendors) })

	bl := mtgban.BuylistRecord{}
	bl.Add(regular, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 5, Quantity: 12, URL: "u"})
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
			Name: "Parity SYP", Shorthand: "PARITYSYP",
			MetadataOnly: true, QuantityPriority: true,
		}),
	}
	vendorsPtr.Store(&vendors)

	config := parseSearchOptionsNG(backend(), regular, nil, nil, nil)
	found := searchVendorsNG([]string{regular}, config)

	var got bool
	for _, res := range found[regular]["INDEX"] {
		if res.Shorthand == "PARITYSYP" {
			got = res.PriceUnit == PriceUnitCount
		}
	}
	if !got {
		t.Error("QuantityPriority did not carry through searchVendorsNG as PriceUnitCount")
	}
}

// A metadata-only vendor's row is read as a want-count only when its own
// unit says so - PriceUnitCount - not whenever it merely isn't a dollar
// offer. A synthetic row like an average count of copies is a non-offer
// too, and carries no want at all to sum; banPricesFromRows must tell the
// two apart rather than treat every non-offer alike.
func TestBanPricesSumsQuantityByPriceUnitCountOnly(t *testing.T) {
	regular, foil, _ := parityCards(t)

	prevVendors := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prevVendors) })
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{
			Name: "Fake Index Vendor", Shorthand: "FAKEIDX", MetadataOnly: true,
		}),
	}
	vendorsPtr.Store(&vendors)

	found := map[string]map[string][]SearchEntry{
		regular: {"INDEX": {{Shorthand: "FAKEIDX", Price: 5, Quantity: 12, PriceUnit: PriceUnitCount}}},
		foil:    {"INDEX": {{Shorthand: "FAKEIDX", Price: 5, Quantity: 12, PriceUnit: PriceUnitExpectedCount}}},
	}
	out := banPricesFromRows(backend(), []string{regular, foil}, found, "name", "shorthands", true, false, true)

	coRegular, err := backend().GetUUID(regular)
	if err != nil {
		t.Fatal(err)
	}
	idRegular := getIDFromMode(backend(), "name", coRegular)
	if got := out[idRegular]["FAKEIDX"].Qty; got != 12 {
		t.Errorf("a want-count row summed to %v, want 12", got)
	}

	coFoil, err := backend().GetUUID(foil)
	if err != nil {
		t.Fatal(err)
	}
	idFoil := getIDFromMode(backend(), "name", coFoil)
	if got := out[idFoil]["FAKEIDX"].QtyFoil; got != 0 {
		t.Errorf("an average-count row summed to %v, want 0 - it is not a want", got)
	}
}

// TestFinishPredicateParity flips divergence #1 from the plan: checkFinish is
// gone, and one finish predicate (the search's cardFilterFinish) applies
// everywhere - filtered API requests inherit it through the funnel, full
// dumps through EntryRule.Finish. Notable semantic changes from checkFinish:
// sealed products now count as nonfoil (kept by finish=nonfoil, dropped by
// foil/etched - checkFinish kept them under every value), and unknown finish
// values drop everything instead of filtering nothing.
func TestFinishPredicateParity(t *testing.T) {
	regular, foil, sealed := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIDs := []string{regular, foil}
	stores := []string{"PARITYA", "PARITYIDX"}

	// Funnel path (hash filter): finish=foil keeps only the foil printing
	api := getSellerPrices(currentDatastore(), "", stores, "", cardIDs, "foil", false, false, false, "")
	if _, found := api[regular]; found {
		t.Error("regular printing should be dropped by finish=foil")
	}
	if got := api[foil]["PARITYA"].Foil; got != 30 {
		t.Errorf("foil = %v, want 30", got)
	}

	// Full dump path: the same predicate through EntryRule.Finish
	api = getSellerPrices(currentDatastore(), "", stores, "", nil, "foil", false, false, false, "")
	if _, found := api[regular]; found {
		t.Error("regular printing should be dropped by finish=foil in a full dump")
	}
	if got := api[foil]["PARITYA"].Foil; got != 30 {
		t.Errorf("full dump foil = %v, want 30", got)
	}

	// Sealed products count as nonfoil under the shared predicate (neither
	// Foil nor Etched is set) and are dropped by foil/etched filters - the
	// old checkFinish kept them under every finish value
	coSealed, err := backend().GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if applyCardFilter(backend(), "finish", []string{"nonfoil"}, coSealed) {
		t.Error("finish(sealed, nonfoil) drops; want kept")
	}
	for _, finish := range []string{"foil", "etched"} {
		if !applyCardFilter(backend(), "finish", []string{finish}, coSealed) {
			t.Errorf("finish(sealed, %s) keeps; want dropped", finish)
		}
	}
}

// TestSearchDownloadFilters pins the search download path (SearchAPI): it
// hands the fully parsed config to the walks and converts the rows, so
// query-level store and entry filters shape the output. The old path
// re-derived a store list from blocklists alone and silently dropped every
// non-card filter the query carried.
func TestSearchDownloadFilters(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIDs := []string{regular}

	// A positive seller filter (query "seller:paritya") excludes the index
	// seller from the download
	config := SearchConfig{StoreFilters: []FilterStoreElem{{
		Name: "seller", Values: []string{"paritya"}, OnlyForSeller: true,
	}}}
	api := banPricesFromRows(backend(), cardIDs, searchSellersNG(cardIDs, config), "", "", true, true, false)
	if _, found := api[regular]["PARITYIDX"]; found {
		t.Error("seller filter should exclude PARITYIDX from the output")
	}
	if got := api[regular]["PARITYA"].Regular; got != 10 {
		t.Errorf("regular = %v, want 10", got)
	}

	// A hideBLconds-style entry filter keeps only NM buylist rows, prices
	// and quantities alike
	config = SearchConfig{EntryFilters: []FilterEntryElem{{
		Name: "condition", Values: []string{"NM"}, OnlyForVendor: true,
	}}}
	bl := banPricesFromRows(backend(), cardIDs, searchVendorsNG(cardIDs, config), "", "", true, true, true)
	if got := bl[regular]["PARITYV"].Conditions.Get("NM"); got != 5 {
		t.Errorf("conditions[NM] = %v, want 5", got)
	}
	if got := bl[regular]["PARITYV"].Conditions.Get("SP"); got != 0 {
		t.Errorf("conditions[SP] = %v, want dropped by the entry filter", got)
	}
	if got := bl[regular]["PARITYV"].Qty; got != 4 {
		t.Errorf("qty = %v, want 4 (SP copies filtered out)", got)
	}
}

// TestZeroPricedListings pins how both API paths treat zero-priced listings:
// they are ignored entirely. The base price is the first nonzero entry, and
// zero entries contribute neither conditions nor quantities. This is the
// search walk's semantic (shouldSkipPriceNG drops them), adopted by
// processEntry too - the old behavior dropped the whole store when a zero
// listing sorted first, while still counting its quantity when it didn't.
func TestZeroPricedListings(t *testing.T) {
	regular, _, _ := parityCards(t)

	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })

	inv := mtgban.InventoryRecord{}
	inv.Add(regular, &mtgban.InventoryEntry{Conditions: "NM", Price: 0, Quantity: 1, URL: "u1"})
	inv.Add(regular, &mtgban.InventoryEntry{Conditions: "NM", Price: 5, Quantity: 2, URL: "u2"})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Zero Store", Shorthand: "ZEROA"}),
	}
	sellersPtr.Store(&sellers)

	check := func(t *testing.T, api map[string]map[string]*BanPrice) {
		t.Helper()
		price, found := api[regular]["ZEROA"]
		if !found {
			t.Fatal("store with a zero-priced best listing should not be dropped")
		}
		if price.Regular != 5 {
			t.Errorf("regular = %v, want 5 (first nonzero listing)", price.Regular)
		}
		if price.Qty != 2 {
			t.Errorf("qty = %v, want 2 (zero listing contributes none)", price.Qty)
		}
		if price.Cond != "NM" {
			t.Errorf("cond = %q, want NM", price.Cond)
		}
	}

	t.Run("funnel path", func(t *testing.T) {
		check(t, getSellerPrices(currentDatastore(), "", []string{"ZEROA"}, "", []string{regular}, "", true, true, false, ""))
	})
	t.Run("full dump path", func(t *testing.T) {
		check(t, getSellerPrices(currentDatastore(), "", []string{"ZEROA"}, "", nil, "", true, true, false, ""))
	})
}

// TestStoreEligible pins the precedence rule behind divergence #2 of the
// plan: an explicit allowlist is the entire store policy and bypasses
// blocklists; without one, blocklists exclude.
func TestStoreEligible(t *testing.T) {
	blocklist := []string{"BLOCKED"}

	if !storeEligible("STORE", nil, blocklist) {
		t.Error("unblocked store should be eligible")
	}
	if storeEligible("BLOCKED", nil, blocklist) {
		t.Error("blocklisted store should not be eligible")
	}
	if !storeEligible("BLOCKED", []string{"BLOCKED"}, blocklist) {
		t.Error("allowlist should override the blocklist")
	}
	if storeEligible("STORE", []string{"OTHER"}, nil) {
		t.Error("with an allowlist, membership is the whole policy")
	}
	if !storeEligible("ANY", nil, nil) {
		t.Error("no policy means everything is eligible")
	}
}

// TestApiEnabledStores pins how the API turns the sig store option into the
// store list: ALL_ACCESS applies the search blocklists at runtime,
// DEV_ACCESS applies nothing, an explicit list bypasses them entirely, and
// BASE_ACCESS additionally drops sealed and non-main-region stores, except
// for metadata-only indexes.
func TestApiEnabledStores(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	prevRetail := Config.SearchRetailBlockList
	prevBuylist := Config.SearchBuylistBlockList
	Config.SearchRetailBlockList = []string{"PARITYIDX"}
	Config.SearchBuylistBlockList = []string{"PARITYV"}
	t.Cleanup(func() {
		Config.SearchRetailBlockList = prevRetail
		Config.SearchBuylistBlockList = prevBuylist
	})

	got := apiEnabledStores("ALL_ACCESS")
	if !slices.Contains(got, "PARITYA") {
		t.Errorf("ALL_ACCESS should keep PARITYA, got %v", got)
	}
	if slices.Contains(got, "PARITYIDX") || slices.Contains(got, "PARITYV") {
		t.Errorf("ALL_ACCESS should apply both blocklists, got %v", got)
	}

	got = apiEnabledStores("DEV_ACCESS")
	for _, store := range []string{"PARITYA", "PARITYIDX", "PARITYV"} {
		if !slices.Contains(got, store) {
			t.Errorf("DEV_ACCESS should keep %s, got %v", store, got)
		}
	}

	got = apiEnabledStores("PARITYIDX,PARITYV")
	if !slices.Equal(got, []string{"PARITYIDX", "PARITYV"}) {
		t.Errorf("explicit list should bypass blocklists, got %v", got)
	}

	// BASE_ACCESS starts from the same blocklisted set as ALL_ACCESS, then
	// additionally drops sealed and non-main-region stores.
	sealedSeller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{
		Name: "Parity Sealed", Shorthand: "PARITYSEALED", SealedMode: true,
	})
	sellers := append(*sellersPtr.Load(), sealedSeller)
	sellersPtr.Store(&sellers)

	euVendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{
		Name: "Parity EU", Shorthand: "PARITYEU", CountryFlag: "EU",
	})
	vendors := append(*vendorsPtr.Load(), euVendor)
	vendorsPtr.Store(&vendors)

	euIndexSeller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{
		Name: "Parity EU Index", Shorthand: "PARITYEUIDX", CountryFlag: "EU", MetadataOnly: true,
	})
	sellers = append(*sellersPtr.Load(), euIndexSeller)
	sellersPtr.Store(&sellers)

	euIndexVendor := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{
		Name: "Parity EU Vendor Index", Shorthand: "PARITYEUVIDX", CountryFlag: "EU", MetadataOnly: true,
	})
	vendors = append(*vendorsPtr.Load(), euIndexVendor)
	vendorsPtr.Store(&vendors)

	got = apiEnabledStores("BASE_ACCESS")
	if !slices.Contains(got, "PARITYA") {
		t.Errorf("BASE_ACCESS should keep PARITYA, got %v", got)
	}
	if slices.Contains(got, "PARITYIDX") || slices.Contains(got, "PARITYV") {
		t.Errorf("BASE_ACCESS should apply both blocklists, got %v", got)
	}
	if slices.Contains(got, "PARITYSEALED") {
		t.Errorf("BASE_ACCESS should drop sealed sellers, got %v", got)
	}
	if slices.Contains(got, "PARITYEU") {
		t.Errorf("BASE_ACCESS should drop non-main-region vendors, got %v", got)
	}
	for _, store := range []string{"PARITYEUIDX", "PARITYEUVIDX"} {
		if !slices.Contains(got, store) {
			t.Errorf("BASE_ACCESS should keep metadata-only store %s, got %v", store, got)
		}
	}
}

// stores.json narrows to the singles or the sealed stores the way sets.json
// narrows its sets, as the guide documents.
func TestStoresFilterNarrowsBothWays(t *testing.T) {
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Singles", Shorthand: "SINGLES1"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Sealed", Shorthand: "SEALED1", SealedMode: true}),
	}
	sellersPtr.Store(&sellers)

	for filter, want := range map[string]string{"sealed": `["SEALED1"]`, "singles": `["SINGLES1"]`} {
		rec := httptest.NewRecorder()
		PriceAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgban/stores.json?filter="+filter, nil))
		got := strings.TrimSpace(rec.Body.String())
		if got != want {
			t.Errorf("stores.json?filter=%s = %s, want %s", filter, got, want)
		}
	}

	// A key whose scope holds no sealed store gets an empty list, not null.
	singles := sellers[:1]
	sellersPtr.Store(&singles)
	rec := httptest.NewRecorder()
	PriceAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgban/stores.json?filter=sealed", nil))
	got := strings.TrimSpace(rec.Body.String())
	if got != "[]" {
		t.Errorf("stores.json?filter=sealed with no sealed store = %s, want []", got)
	}
}

func TestBaseAccessStoreEligible(t *testing.T) {
	for _, tt := range []struct {
		name string
		info mtgban.ScraperInfo
		want bool
	}{
		{name: "main-region singles", info: mtgban.ScraperInfo{}, want: true},
		{name: "foreign singles", info: mtgban.ScraperInfo{CountryFlag: "EU"}, want: false},
		{name: "foreign metadata-only index", info: mtgban.ScraperInfo{CountryFlag: "EU", MetadataOnly: true}, want: true},
		{name: "sealed metadata-only index", info: mtgban.ScraperInfo{MetadataOnly: true, SealedMode: true}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := baseAccessStoreEligible(tt.info); got != tt.want {
				t.Errorf("baseAccessStoreEligible(%+v) = %v, want %v", tt.info, got, tt.want)
			}
		})
	}
}

// TestGetDefaultBlocklists pins the search-side counterpart: with no sig the
// config blocklists apply, a sig can replace them with its own list, and
// NONE disables them.
func TestGetDefaultBlocklists(t *testing.T) {
	prevRetail := Config.SearchRetailBlockList
	prevBuylist := Config.SearchBuylistBlockList
	Config.SearchRetailBlockList = []string{"RBLOCK"}
	Config.SearchBuylistBlockList = []string{"BBLOCK"}
	t.Cleanup(func() {
		Config.SearchRetailBlockList = prevRetail
		Config.SearchBuylistBlockList = prevBuylist
	})

	retail, buylist := getDefaultBlocklists("")
	if !slices.Equal(retail, []string{"RBLOCK"}) || !slices.Equal(buylist, []string{"BBLOCK"}) {
		t.Errorf("no sig should fall back to config: %v / %v", retail, buylist)
	}

	sig := base64.StdEncoding.EncodeToString([]byte("SearchDisabled=NONE&SearchBuylistDisabled=STOREX,STOREY"))
	retail, buylist = getDefaultBlocklists(sig)
	if retail != nil {
		t.Errorf("NONE should disable the retail blocklist, got %v", retail)
	}
	if !slices.Equal(buylist, []string{"STOREX", "STOREY"}) {
		t.Errorf("sig list should replace the buylist blocklist, got %v", buylist)
	}
}

// TestBanPriceWireFormat guards the JSON shape of the conditions/quantities
// structs: identical keys to the former maps, zeros omitted, and an unset
// group omitted entirely.
func TestBanPriceWireFormat(t *testing.T) {
	price := &BanPrice{Regular: 10}
	price.Conditions = &BanConditions{}
	price.Conditions.Set("NM", 10)
	price.Conditions.Set("SP_foil", 7.5)
	price.Quantities = &BanQuantities{}
	price.Quantities.Set("NM", 3)

	out, err := json.Marshal(price)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"regular":10,"conditions":{"NM":10,"SP_foil":7.5},"quantities":{"NM":3}}`
	if string(out) != want {
		t.Errorf("wire format changed:\n got %s\nwant %s", out, want)
	}

	// No conditions written at all: the field disappears, like an empty map.
	bare, err := json.Marshal(&BanPrice{Foil: 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(bare) != `{"foil":2}` {
		t.Errorf("bare wire format changed: %s", bare)
	}
}
