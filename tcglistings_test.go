package main

import (
	"database/sql"
	"errors"
	"testing"
)

// TestBuildTCGListings groups the rows by printing, keeps the grades
// TCGplayer names, totals every printing's listings, and marks the
// printings the scrape cut short.
func TestBuildTCGListings(t *testing.T) {
	reported := func(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }
	rows := []tcgListingsRow{
		// Complete: 195 listings stored of the 195 TCGplayer counts.
		{1, "Normal", "Near Mint", 51, 60, 83, reported(195)},
		{1, "Normal", "Lightly Played", 77, 88, 135, reported(195)},
		{1, "Normal", "Moderately Played", 27, 30, 37, reported(195)},
		{1, "Normal", "Heavily Played", 11, 12, 19, reported(195)},
		{1, "Normal", "Damaged", 5, 5, 5, reported(195)},
		// Cut short: 88 stored of 2,357, and the foil 11 of 966.
		{2, "Normal", "Near Mint", 75, 76, 704, reported(2357)},
		{2, "Normal", "Lightly Played", 12, 12, 93, reported(2357)},
		{2, "Foil", "Near Mint", 4, 4, 6, reported(966)},
		{2, "Foil", "Lightly Played", 6, 7, 12, reported(966)},
		// A condition that is no grade still counts as stored.
		{3, "Normal", "Near Mint", 2, 2, 2, reported(3)},
		{3, "Normal", "Unopened", 1, 1, 1, reported(3)},
		// No price row to compare with.
		{4, "Foil", "Near Mint", 1, 1, 1, sql.NullInt64{}},
		// None stored: the valuable foil a bulk nonfoil crowded out.
		{6, "Foil", "", 0, 0, 0, reported(46)},
		// Two short, listings that changed during the scrape.
		{7, "Normal", "Near Mint", 40, 40, 60, reported(42)},
		// No card.
		{5, "Normal", "Near Mint", 9, 9, 9, reported(9)},
	}
	ids := map[tcgPrintingKey]string{
		{1, "Normal"}: "complete", {2, "Normal"}: "bulk", {2, "Foil"}: "bulk-foil",
		{3, "Normal"}: "unopened", {4, "Foil"}: "unpriced",
		{6, "Foil"}: "crowded-foil", {7, "Normal"}: "drifted",
	}
	match := func(productID int64, printing string) (string, error) {
		id, found := ids[tcgPrintingKey{productID, printing}]
		if !found {
			return "", errors.New("no card")
		}
		return id, nil
	}

	cards, unmatched := buildTCGListings(rows, match)
	if unmatched != 1 {
		t.Errorf("unmatched: got %d, want 1", unmatched)
	}
	want := map[string]tcgListings{
		"complete":     {Sellers: [5]int32{51, 77, 27, 11, 5}, Copies: [5]int32{83, 135, 37, 19, 5}, Total: 195},
		"bulk":         {Sellers: [5]int32{75, 12}, Copies: [5]int32{704, 93}, Capped: true, Total: 2357},
		"bulk-foil":    {Sellers: [5]int32{4, 6}, Copies: [5]int32{6, 12}, Capped: true, Total: 966},
		"unopened":     {Sellers: [5]int32{2}, Copies: [5]int32{2}, Total: 3},
		"unpriced":     {Sellers: [5]int32{1}, Copies: [5]int32{1}, Total: 1},
		"crowded-foil": {Capped: true, Total: 46},
		"drifted":      {Sellers: [5]int32{40}, Copies: [5]int32{60}, Total: 40},
	}
	if len(cards) != len(want) {
		t.Fatalf("got %d cards, want %d", len(cards), len(want))
	}
	for id, w := range want {
		got := cards[id]
		if got == nil || *got != w {
			t.Errorf("%s: got %+v, want %+v", id, got, w)
		}
	}
}
