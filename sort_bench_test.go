package main

import (
	"slices"
	"sort"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// benchSortUUIDs picks n uuids spread across the datastore pool,
// deterministically so every run sorts the same input.
func benchSortUUIDs(b *testing.B, n int) []string {
	all := mtgmatcher.GetUUIDs()
	if len(all) == 0 {
		b.Skip("mtgmatcher datastore not loaded")
	}
	if len(all) < n {
		n = len(all)
	}
	uuids := make([]string, n)
	step := len(all) / n
	for i := range n {
		uuids[i] = all[i*step]
	}
	return uuids
}

func BenchmarkSortSets(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)
	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sortData := resolveSortingData(keys)
		sort.Slice(keys, func(i, j int) bool {
			return cmpSets(sortData[keys[i]], sortData[keys[j]])
		})
	}
}

func BenchmarkSortSetsAlphabetical(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)
	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sortData := resolveSortingData(keys)
		sort.Slice(keys, func(i, j int) bool {
			return cmpSetsAlphabetical(sortData[keys[i]], sortData[keys[j]], false)
		})
	}
}

func BenchmarkSortSetsAlphabeticalSet(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)
	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sortData := resolveSortingData(keys)
		sort.Slice(keys, func(i, j int) bool {
			return cmpSetsAlphabeticalSet(sortData[keys[i]], sortData[keys[j]], false)
		})
	}
}

func BenchmarkSortByNumberAndFinish(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)
	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sortData := resolveSortingData(keys)
		sort.Slice(keys, func(i, j int) bool {
			return cmpNumberAndFinish(sortData[keys[i]], sortData[keys[j]], false)
		})
	}
}

// The retail sort consults seller prices per comparison, so give the priority
// sellers a price for every benched uuid.
func BenchmarkSortSetsByRetail(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)

	prevSellers := sellersPtr.Load()
	b.Cleanup(func() { sellersPtr.Store(prevSellers) })
	var sellers []mtgban.Seller
	for _, shorthand := range defaultSellerPriorityOpt {
		inv := mtgban.InventoryRecord{}
		for i, uuid := range uuids {
			inv.Add(uuid, &mtgban.InventoryEntry{
				Conditions: "NM", Price: float64(i%500) + 0.5, URL: "u",
			})
		}
		sellers = append(sellers, mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
			Name: "Bench " + shorthand, Shorthand: shorthand,
		}))
	}
	sellersPtr.Store(&sellers)

	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sort.Slice(keys, func(i, j int) bool {
			return sortSetsByRetail(keys[i], keys[j], defaultSellerPriorityOpt)
		})
	}
}

// The buylist sort consults vendor prices and breaks ties through the whole
// retail chain, so give the priority vendors and sellers a price for every
// benched uuid; the repeating prices force the tie-breaks to run.
func BenchmarkSortSetsByBuylist(b *testing.B) {
	uuids := benchSortUUIDs(b, 5000)

	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	b.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	var sellers []mtgban.Seller
	for _, shorthand := range defaultSellerPriorityOpt {
		inv := mtgban.InventoryRecord{}
		for i, uuid := range uuids {
			inv.Add(uuid, &mtgban.InventoryEntry{
				Conditions: "NM", Price: float64(i%500) + 0.5, URL: "u",
			})
		}
		sellers = append(sellers, mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
			Name: "Bench " + shorthand, Shorthand: shorthand,
		}))
	}
	sellersPtr.Store(&sellers)
	var vendors []mtgban.Vendor
	for _, shorthand := range defaultVendorPriorityOpt {
		bl := mtgban.BuylistRecord{}
		for i, uuid := range uuids {
			bl.Add(uuid, &mtgban.BuylistEntry{
				Conditions: "NM", BuyPrice: float64(i%500) + 0.5, URL: "u",
			})
		}
		vendors = append(vendors, mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
			Name: "Bench " + shorthand, Shorthand: shorthand,
		}))
	}
	vendorsPtr.Store(&vendors)

	b.ReportAllocs()
	for b.Loop() {
		keys := slices.Clone(uuids)
		sort.Slice(keys, func(i, j int) bool {
			return sortSetsByBuylist(keys[i], keys[j], defaultVendorPriorityOpt)
		})
	}
}

// Sorting must be deterministic: the same input in any starting order lands in
// one order. Also serves as a fixture to eyeball order stability across
// implementations of the comparators.
func TestSortSetsDeterministic(t *testing.T) {
	all := mtgmatcher.GetUUIDs()
	if len(all) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}
	uuids := make([]string, 0, 500)
	step := max(len(all)/500, 1)
	for i := 0; i < len(all) && len(uuids) < 500; i += step {
		uuids = append(uuids, all[i])
	}

	a := slices.Clone(uuids)
	sort.SliceStable(a, func(i, j int) bool { return sortSets(a[i], a[j]) })

	b := slices.Clone(uuids)
	slices.Reverse(b)
	sort.SliceStable(b, func(i, j int) bool { return sortSets(b[i], b[j]) })

	// Compare as sets of positions: equal elements may tie, so require the
	// comparator to consider adjacent out-of-order pairs equal rather than
	// demanding identical slices.
	for i := range a {
		if a[i] == b[i] {
			continue
		}
		if sortSets(a[i], b[i]) || sortSets(b[i], a[i]) {
			t.Fatalf("order diverges at %d: %s vs %s", i, a[i], b[i])
		}
	}
}
