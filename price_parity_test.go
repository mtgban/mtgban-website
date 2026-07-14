package main

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
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
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher data not loaded")
	}
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
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
	sealedIds := mtgmatcher.GetSealedUUIDs()
	if len(sealedIds) > 0 {
		sealed = sealedIds[0]
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
func searchPrice(found map[string]map[string][]SearchEntry, cardId, cond, shorthand string) float64 {
	for _, res := range found[cardId][cond] {
		if res.Shorthand == shorthand {
			return res.Price
		}
	}
	return -1
}

func TestPriceParityRetail(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIds := []string{regular, foil}
	config := parseSearchOptionsNG(regular, nil, nil, nil)
	found := searchSellersNG(cardIds, config)

	api := getSellerPrices("", []string{"PARITYA", "PARITYIDX"}, "", cardIds, "", true, true, false, "")

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

	cardIds := []string{regular, regular, regular, regular}
	config := parseSearchOptionsNG(regular, nil, nil, nil)

	found := searchSellersNG(cardIds, config)
	for _, cond := range []string{"NM", "SP", "PO"} {
		if got := len(found[regular][cond]); got != 1 {
			t.Errorf("sellers %s rows = %d, want 1", cond, got)
		}
	}

	foundBl := searchVendorsNG(cardIds, config)
	for _, cond := range []string{"NM", "SP"} {
		if got := len(foundBl[regular][cond]); got != 1 {
			t.Errorf("vendors %s rows = %d, want 1", cond, got)
		}
	}
}

func TestPriceParityBuylist(t *testing.T) {
	regular, foil, _ := parityCards(t)
	seedParityScrapers(t, regular, foil)

	cardIds := []string{regular}
	config := parseSearchOptionsNG(regular, nil, nil, nil)
	found := searchVendorsNG(cardIds, config)

	api := getVendorPrices("", []string{"PARITYV"}, "", cardIds, "", true, true, false, "")

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

	cardIds := []string{regular, foil}
	stores := []string{"PARITYA", "PARITYIDX"}

	// Funnel path (hash filter): finish=foil keeps only the foil printing
	api := getSellerPrices("", stores, "", cardIds, "foil", false, false, false, "")
	if _, found := api[regular]; found {
		t.Error("regular printing should be dropped by finish=foil")
	}
	if got := api[foil]["PARITYA"].Foil; got != 30 {
		t.Errorf("foil = %v, want 30", got)
	}

	// Full dump path: the same predicate through EntryRule.Finish
	api = getSellerPrices("", stores, "", nil, "foil", false, false, false, "")
	if _, found := api[regular]; found {
		t.Error("regular printing should be dropped by finish=foil in a full dump")
	}
	if got := api[foil]["PARITYA"].Foil; got != 30 {
		t.Errorf("full dump foil = %v, want 30", got)
	}

	// Sealed products count as nonfoil under the shared predicate (neither
	// Foil nor Etched is set) and are dropped by foil/etched filters - the
	// old checkFinish kept them under every finish value
	coSealed, err := mtgmatcher.GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if applyCardFilter("finish", []string{"nonfoil"}, coSealed) {
		t.Error("finish(sealed, nonfoil) drops; want kept")
	}
	for _, finish := range []string{"foil", "etched"} {
		if !applyCardFilter("finish", []string{finish}, coSealed) {
			t.Errorf("finish(sealed, %s) keeps; want dropped", finish)
		}
	}
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
// DEV_ACCESS applies nothing, and an explicit list bypasses them entirely.
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
