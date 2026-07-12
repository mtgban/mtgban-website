package main

import (
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
		if got := api[regular]["PARITYA"].Conditions[tc.cond]; got != tc.want {
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

	// Pin (documented divergence #3 in the plan): search suppresses PO rows
	// when NM and SP rows exist; the API exports every condition. If either
	// side changes, revisit todo/unify-price-pipelines.md.
	if got := searchPrice(found, regular, "PO", "PARITYA"); got != -1 {
		t.Errorf("search PO row should be suppressed, got %v", got)
	}
	if got := api[regular]["PARITYA"].Conditions["PO"]; got != 2 {
		t.Errorf("api conditions[PO] = %v, want 2", got)
	}

	// Pin: the API sums quantities across every condition (PO included) even
	// though the PO row is hidden on the search side.
	if got := api[regular]["PARITYA"].Qty; got != 8 {
		t.Errorf("api qty = %v, want 8", got)
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
	if got := api[regular]["PARITYV"].Conditions["NM"]; got != 5 {
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

// TestFinishPredicateDivergence pins divergence #1 from the plan: the API's
// checkFinish and the search finish FilterCardFunc disagree on sealed
// products. checkFinish always keeps sealed regardless of the finish filter;
// the search filter drops sealed under f:foil / f:etched (a sealed product is
// neither). The unification (phase 1) replaces both with one predicate and
// must flip this test into a parity assertion.
func TestFinishPredicateDivergence(t *testing.T) {
	regular, foil, sealed := parityCards(t)

	coSealed, err := mtgmatcher.GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	searchFinish := FilterCardFuncs["finish"]

	// API: sealed passes any finish filter.
	for _, finish := range []string{"nonfoil", "foil", "etched"} {
		if checkFinish(coSealed, finish) {
			t.Errorf("checkFinish(sealed, %s) skips; pinned as kept", finish)
		}
	}
	// Search: sealed is dropped by foil/etched filters.
	for _, finish := range []string{"foil", "etched"} {
		if !searchFinish([]string{finish}, coSealed) {
			t.Errorf("search finish(sealed, %s) keeps; pinned as dropped", finish)
		}
	}

	// Where they agree already: plain singles.
	coRegular, _ := mtgmatcher.GetUUID(regular)
	coFoil, _ := mtgmatcher.GetUUID(foil)
	if checkFinish(coRegular, "nonfoil") || searchFinish([]string{"nonfoil"}, coRegular) {
		t.Error("regular card should pass a nonfoil filter on both sides")
	}
	if checkFinish(coFoil, "foil") || searchFinish([]string{"foil"}, coFoil) {
		t.Error("foil card should pass a foil filter on both sides")
	}
	if !checkFinish(coRegular, "foil") || !searchFinish([]string{"foil"}, coRegular) {
		t.Error("regular card should be dropped by a foil filter on both sides")
	}
}
