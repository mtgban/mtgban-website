package main

import (
	"math"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// Each entry and price filter kind, judged against a seller's entry and a
// vendor's: the side-only filters pass the other side's entries untouched,
// and a ratio filter not marked for vendors turns away a seller's entry.
func TestEntryFoundBySide(t *testing.T) {
	seller := mtgban.InventoryEntry{Price: 5, Conditions: "SP", Quantity: 3}
	vendor := mtgban.BuylistEntry{BuyPrice: 2, Conditions: "SP", Quantity: 3, PriceRatio: 40}
	info := mtgban.ScraperInfo{Shorthand: "TST"}

	for _, tc := range []struct {
		name       string
		entries    []FilterEntryElem
		prices     []*FilterPriceElem
		metadata   bool
		unpriced   bool
		wantSeller bool
		wantVendor bool
	}{
		{name: "no filters", wantSeller: true, wantVendor: true},
		{name: "cond:NM", entries: []FilterEntryElem{{Name: "condition", Values: []string{"NM"}}}},
		{name: "-cond:NM", entries: []FilterEntryElem{{Name: "condition", Values: []string{"NM"}, Negate: true}}, wantSeller: true, wantVendor: true},
		{name: "condr:NM", entries: []FilterEntryElem{{Name: "condition", Values: []string{"NM"}, OnlyForSeller: true}}, wantVendor: true},
		{name: "condb:NM", entries: []FilterEntryElem{{Name: "condition", Values: []string{"NM"}, OnlyForVendor: true}}, wantSeller: true},
		{name: "cond<MP", entries: []FilterEntryElem{{Name: "condition_less_than", Values: []string{"MP"}}}},
		{name: "cond>MP", entries: []FilterEntryElem{{Name: "condition_greater_than", Values: []string{"MP"}}}, wantSeller: true, wantVendor: true},
		{name: "qty>5", entries: []FilterEntryElem{{Name: "qty_greater_than", Values: []string{"5"}}}},
		{name: "qty<5", entries: []FilterEntryElem{{Name: "qty_less_than", Values: []string{"5"}}}, wantSeller: true, wantVendor: true},
		{name: "ratio>50", entries: []FilterEntryElem{{Name: "ratio_greater_than", Values: []string{"50"}, OnlyForVendor: true}}, wantSeller: true},
		{name: "ratio>30 on both sides", entries: []FilterEntryElem{{Name: "ratio_greater_than", Values: []string{"30"}}}, wantVendor: true},
		{name: "an index seller's entry", entries: []FilterEntryElem{{Name: "condition", Values: []string{"NM"}}}, metadata: true, wantSeller: true},
		{name: "price>6", prices: []*FilterPriceElem{{Name: "price_greater_than", Value: 6, OnlyForSeller: true}}, wantVendor: true},
		{name: "buy_price>3", prices: []*FilterPriceElem{{Name: "buy_price_greater_than", Value: 3, OnlyForVendor: true}}, wantSeller: true},
		{name: "price<6 elsewhere", prices: []*FilterPriceElem{{Name: "price_less_than", Value: 6, ApplyTo: []string{"OTHER"}}}, wantSeller: true, wantVendor: true},
		{name: "no price", unpriced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := SearchConfig{EntryFilters: tc.entries, PriceFilters: tc.prices}
			s, v := seller, vendor
			if tc.unpriced {
				s.Price, v.BuyPrice = math.NaN(), math.Inf(1)
			}
			sinfo := info
			sinfo.MetadataOnly = tc.metadata

			got := sellerEntryFound(sinfo, "card", s, config)
			if got != tc.wantSeller {
				t.Errorf("seller entry found %v, want %v", got, tc.wantSeller)
			}
			got = vendorEntryFound(info, "card", v, config)
			if got != tc.wantVendor {
				t.Errorf("vendor entry found %v, want %v", got, tc.wantVendor)
			}
		})
	}
}

// Judging an entry allocates nothing, filters and all: the presence pass
// judges every entry of every card a search finds.
func TestEntryFoundAllocatesNothing(t *testing.T) {
	seller := mtgban.InventoryEntry{Price: 5, Conditions: "SP", Quantity: 3}
	vendor := mtgban.BuylistEntry{BuyPrice: 2, Conditions: "SP", Quantity: 3, PriceRatio: 40}
	info := mtgban.ScraperInfo{Shorthand: "TST"}
	config := SearchConfig{
		EntryFilters: []FilterEntryElem{
			{Name: "condition", Values: []string{"NM", "SP"}},
			{Name: "ratio_greater_than", Values: []string{"50"}, OnlyForVendor: true},
		},
		PriceFilters: []*FilterPriceElem{
			{Name: "price_greater_than", Value: 1, OnlyForSeller: true},
			{Name: "buy_price_greater_than", Value: 1, OnlyForVendor: true},
		},
	}

	allocs := testing.AllocsPerRun(100, func() {
		sellerEntryFound(info, "card", seller, config)
		vendorEntryFound(info, "card", vendor, config)
	})
	if allocs != 0 {
		t.Errorf("judging a seller's and a vendor's entry allocates %v times", allocs)
	}
}
