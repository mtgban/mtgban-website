package main

import (
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// registerTestVendor and registerTestSeller file a throwaway scraper under
// the given shorthand, carrying real card uuids drawn from the loaded
// datastore (fake ones would just fail mtgmatcher.GetUUID and be silently
// dropped by storeSeedUUIDs, defeating the point of the test). Restores
// whatever was registered before once the test ends, via t.Cleanup - these
// touch the same process-wide sellersPtr/vendorsPtr every real scraper load
// does.
func registerTestVendor(t *testing.T, shorthand string, uuids []string) {
	t.Helper()
	prev := vendorsPtr.Load()
	t.Cleanup(func() { vendorsPtr.Store(prev) })

	now := time.Now()
	bl := mtgban.BuylistRecord{}
	for _, uuid := range uuids {
		bl[uuid] = []mtgban.BuylistEntry{{BuyPrice: 5, Conditions: "NM"}}
	}
	vendor := mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, BuylistTimestamp: &now,
	})
	if err := updateVendors(vendor); err != nil {
		t.Fatalf("registering vendor %s: %v", shorthand, err)
	}
}

func registerTestSeller(t *testing.T, shorthand string, uuids []string) {
	t.Helper()
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	now := time.Now()
	inv := mtgban.InventoryRecord{}
	for _, uuid := range uuids {
		inv[uuid] = []mtgban.InventoryEntry{{Price: 5, Conditions: "NM"}}
	}
	seller := mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, InventoryTimestamp: &now,
	})
	if err := updateSellers(seller); err != nil {
		t.Fatalf("registering seller %s: %v", shorthand, err)
	}
}

// somePlainCardUUIDs returns n real, non-sealed card uuids from the loaded
// datastore, for building a throwaway scraper's inventory/buylist.
func somePlainCardUUIDs(t *testing.T, n int) []string {
	t.Helper()
	var uuids []string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		uuids = append(uuids, uuid)
		if len(uuids) == n {
			break
		}
	}
	return uuids
}

// A plain vendor:/seller:/store: query with no card name and no other
// filter used to fall to the full-datastore default search - every card the
// site holds, most of which the named store doesn't even carry - because
// that filter is a PostFilter, resolved only after pricing has already been
// fetched for the whole (usually far too large) candidate set. A small
// uploaded buylist searched for by its own name got "Too many results, try
// adjusting your filters" as a result, despite carrying a handful of cards.
//
// storeSeedUUIDs seeds the candidate pool from the named store's own
// inventory/buylist keys instead, the same way an edition or collector
// number filter already seeds an empty query.
func TestPlainStoreQuerySeedsFromTheStoreItself(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)

	for _, query := range []string{`vendor:TEST`, `store:TEST`} {
		t.Run(query, func(t *testing.T) {
			results, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(results) != len(uuids) {
				t.Errorf("%s found %d cards, want exactly the %d the store carries", query, len(results), len(uuids))
			}
		})
	}
}

// seller:/store: seeds from a seller's inventory the same way vendor: does
// from a buylist.
func TestPlainSellerQuerySeedsFromTheSellerItself(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestSeller(t, "TESTSELL", uuids)

	for _, query := range []string{`seller:TESTSELL`, `store:TESTSELL`} {
		t.Run(query, func(t *testing.T) {
			results, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(results) != len(uuids) {
				t.Errorf("%s found %d cards, want exactly the %d the store carries", query, len(results), len(uuids))
			}
		})
	}
}

// A store name that matches no registered scraper still answers directly -
// zero results - rather than falling back to the whole datastore only to
// filter it down to zero later. Same "a seed that finds nothing has still
// answered" principle the edition and number seeds already document.
func TestUnknownStoreQuerySeedsEmptyRatherThanEverything(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	results, err := searchAndFilter(parseSearchOptionsNG(`vendor:NoSuchStoreExists`, nil, nil, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(results) != 0 {
		t.Errorf("found %d cards for a store that doesn't exist", len(results))
	}
}

// A negated store filter (-vendor:TEST) resolves to a "hide this store"
// PostFilter with no Values, which storeSeedUUIDs must treat as
// inapplicable: it cannot enumerate "every card not sold by X" from one
// store's own keys. Asserts the seed itself is skipped (nil, false) rather
// than only that the full search doesn't error - a panic-free full-pool
// fallback would satisfy that weaker check too, without actually locking
// down that negation is left unseeded.
func TestNegatedStoreQueryDoesNotSeed(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)

	config := parseSearchOptionsNG(`-vendor:TEST`, nil, nil, nil)
	seeded, ok := storeSeedUUIDs(config)
	if ok || seeded != nil {
		t.Errorf("storeSeedUUIDs(-vendor:TEST) = (%v, %v), want (nil, false)", seeded, ok)
	}

	// The full search still has to run cleanly on the unseeded path.
	if _, err := searchAndFilter(config); err != nil {
		t.Fatalf("%v", err)
	}
}

// A store filter riding alongside another PostFilter - an automatic "hide
// empty" that qty>/skip:empty appends, or a second store filter from
// seller:/vendor: combined - must still seed: requiring the store filter to
// be the *only* PostFilter left the reported bug's residual case unfixed,
// since almost any companion option (qty>, skip:empty, a second store)
// appends a PostFilter of its own and would have made storeSeedUUIDs bail
// straight back to the full-datastore fallback.
func TestStoreQuerySeedsAlongsideACompanionPostFilter(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)

	for _, query := range []string{
		`vendor:TEST qty>5`,
		`vendor:TEST skip:empty`,
	} {
		t.Run(query, func(t *testing.T) {
			config := parseSearchOptionsNG(query, nil, nil, nil)
			if len(config.PostFilters) < 2 {
				t.Fatalf("%s: expected a companion PostFilter alongside the store one, got %+v", query, config.PostFilters)
			}
			results, err := searchAndFilter(config)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(results) != len(uuids) {
				t.Errorf("%s found %d cards, want exactly the %d the store carries (got the full-pool fallback instead of a seed)", query, len(results), len(uuids))
			}
		})
	}
}

// Two store filters combined (vendor:TEST seller:OTHER) both produce a
// Name=="any" PostFilter; storeSeedUUIDs only needs to seed from one of them
// to keep the candidate pool away from the full-datastore fallback - the
// other still narrows the final results later via PostSearchFilter in the
// real request handler, which this test does not exercise.
func TestStoreQuerySeedsWithASecondStoreFilterPresent(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)
	registerTestSeller(t, "OTHER", uuids)

	config := parseSearchOptionsNG(`vendor:TEST seller:OTHER`, nil, nil, nil)
	if len(config.PostFilters) != 2 {
		t.Fatalf("expected two store PostFilters, got %+v", config.PostFilters)
	}
	results, err := searchAndFilter(config)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(results) != len(uuids) {
		t.Errorf("found %d cards, want exactly the %d both stores carry (got the full-pool fallback instead of a seed)", len(results), len(uuids))
	}
}

// A store filter alongside a filter that already bounds the pool defers to
// it: the edition seed runs first (searchAndFilter checks it before the
// store seed), and the store still narrows the final results later via
// PostSearchFilter in the real request handler, which this test does not
// exercise - only that seeding here is the whole named edition, not merely
// what one store happens to carry.
func TestStoreQueryDefersToAnEditionFilterAlreadySeeding(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	leaUUIDs := mtgmatcher.GetUUIDsInSet("LEA")
	if len(leaUUIDs) == 0 {
		t.Skip("LEA not present in this datastore")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)

	results, err := searchAndFilter(parseSearchOptionsNG(`s:LEA vendor:TEST`, nil, nil, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(results) != len(leaUUIDs) {
		t.Errorf("s:LEA vendor:TEST found %d cards, want the whole LEA seed (%d) - the store filter should not have narrowed the seed itself", len(results), len(leaUUIDs))
	}
}

// A store filter alongside actual search text is unaffected by any of this:
// CleanQuery is non-empty, so searchAndFilter never reaches the empty-query
// seeding block storeSeedUUIDs lives in, and the query resolves exactly as
// it would have without the store filter riding along (the store still
// narrows the final results later via PostSearchFilter, not exercised
// here).
func TestStoreQueryWithSearchTextIsUnaffectedByTheSeed(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := somePlainCardUUIDs(t, 6)
	if len(uuids) < 6 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "TEST", uuids)

	co, err := mtgmatcher.GetUUID(uuids[0])
	if err != nil {
		t.Fatalf("%v", err)
	}

	plain, err := searchAndFilter(parseSearchOptionsNG(co.Name, nil, nil, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	withStore, err := searchAndFilter(parseSearchOptionsNG(co.Name+` vendor:TEST`, nil, nil, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(withStore) != len(plain) {
		t.Errorf("%q vendor:TEST found %d cards, want the same %d a plain name search finds", co.Name, len(withStore), len(plain))
	}
}

// A comma-joined list of stores under one key (vendor:A,B) unions both:
// storeSeedUUIDs' shorthand match already checks slices.Contains(f.Values,
// ...) against every value, not just the first, so two disjoint vendors
// both contribute their own cards to the seed.
func TestStoreQueryUnionsACommaJoinedList(t *testing.T) {
	all := mtgmatcher.GetUUIDs()
	if len(all) == 0 {
		t.Skip("no datastore loaded")
	}

	var uuidsA, uuidsB []string
	for _, uuid := range all {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		if len(uuidsA) < 3 {
			uuidsA = append(uuidsA, uuid)
			continue
		}
		if len(uuidsB) < 3 && !slices.Contains(uuidsA, uuid) {
			uuidsB = append(uuidsB, uuid)
		}
		if len(uuidsA) == 3 && len(uuidsB) == 3 {
			break
		}
	}
	if len(uuidsA) < 3 || len(uuidsB) < 3 {
		t.Skip("datastore doesn't hold enough plain cards for this test")
	}
	registerTestVendor(t, "STOREA", uuidsA)
	registerTestVendor(t, "STOREB", uuidsB)

	results, err := searchAndFilter(parseSearchOptionsNG(`vendor:STOREA,STOREB`, nil, nil, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	want := len(uuidsA) + len(uuidsB)
	if len(results) != want {
		t.Errorf("vendor:STOREA,STOREB found %d cards, want the union %d (%d + %d)", len(results), want, len(uuidsA), len(uuidsB))
	}
}
