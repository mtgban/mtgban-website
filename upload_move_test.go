package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// moveRows prices the uploaded rows at CK for 5 and SCG for 4 a copy, best
// offer only, with the moves and filters st sets.
func moveRows(t *testing.T, entries []UploadEntry, st uploadSettings) uploadRows {
	t.Helper()
	prices := uploadPrices{
		results: map[string]map[string]*BanPrice{
			"card":  {"CK": {Regular: 5}, "SCG": {Regular: 4}},
			"other": {"CK": {Regular: 5}, "SCG": {Regular: 4}},
		},
		enabledStores: []string{"CK", "SCG", "ABU"},
	}
	st.percMargin = 1
	st.multiplier = 1
	return priceUploadRows(backend(), true, st, prices, uploadIndexes{}, entries)
}

// sectionOf lists the stores each card is filed under, and whether it was
// moved there.
func sectionOf(rows uploadRows, card string) []string {
	var out []string
	for _, store := range []string{"CK", "SCG", "ABU"} {
		for _, entry := range rows.optimizedResults[store] {
			if entry.CardID != card {
				continue
			}
			if entry.Moved {
				out = append(out, store+" moved")
			} else {
				out = append(out, store)
			}
		}
	}
	return out
}

// A move puts the card at the reader's store alone, past the margin and
// each of the value and spread filters, and leaves the other cards where
// the optimizer put them; a move to a store with no offer for the card is
// no move. Both cards were loaded at 10, so SCG's 4 is a 40% spread.
func TestOptimizerHonoursMoves(t *testing.T) {
	toSCG := map[string]string{"card": "SCG"}
	for _, tc := range []struct {
		name  string
		st    uploadSettings
		card  []string
		other []string
	}{
		{"no move", uploadSettings{}, []string{"CK"}, []string{"CK"}},
		{"to a lower offer", uploadSettings{moves: toSCG}, []string{"SCG moved"}, []string{"CK"}},
		{"past the low-value filter", uploadSettings{moves: toSCG, skipLowValueAbs: true, minLowVal: 4.5}, []string{"SCG moved"}, []string{"CK"}},
		{"past the high-value filter", uploadSettings{moves: toSCG, skipHighValueAbs: true, maxHighVal: 3}, []string{"SCG moved"}, nil},
		{"past the low-spread filter", uploadSettings{moves: toSCG, skipLowValue: true, percSpread: 45}, []string{"SCG moved"}, []string{"CK"}},
		{"past the high-spread filter", uploadSettings{moves: toSCG, skipHighValue: true, percSpreadMax: 30}, []string{"SCG moved"}, nil},
		{"to its best offer", uploadSettings{moves: map[string]string{"card": "CK"}}, []string{"CK moved"}, []string{"CK"}},
		{"to a store with no offer", uploadSettings{moves: map[string]string{"card": "ABU"}}, []string{"CK"}, []string{"CK"}},
		{"to a store not priced", uploadSettings{moves: map[string]string{"card": "ZZZ"}}, []string{"CK"}, []string{"CK"}},
	} {
		entries := []UploadEntry{{CardID: "card", OriginalPrice: 10}, {CardID: "other", OriginalPrice: 10}}
		rows := moveRows(t, entries, tc.st)
		card, other := sectionOf(rows, "card"), sectionOf(rows, "other")
		if strings.Join(card, ",") != strings.Join(tc.card, ",") || strings.Join(other, ",") != strings.Join(tc.other, ",") {
			t.Errorf("%s: card at %q, other at %q, want %q and %q", tc.name, card, other, tc.card, tc.other)
		}
	}
}

// The highest total counts a moved card at the store it was moved to, and
// two uploaded rows of the same card and condition move together.
func TestOptimizerMovesEveryRowOfTheCard(t *testing.T) {
	rows := moveRows(t, []UploadEntry{{CardID: "card"}, {CardID: "card"}, {CardID: "other"}}, uploadSettings{moves: map[string]string{"card": "SCG"}})
	if got := sectionOf(rows, "card"); strings.Join(got, ",") != "SCG moved,SCG moved" {
		t.Errorf("card at %q, want both rows moved to SCG", got)
	}
	if rows.highestTotal != 4+4+5 {
		t.Errorf("highest total %v, want 13", rows.highestTotal)
	}
	if rows.optimizedTotals["SCG"] != 8 || rows.optimizedTotals["CK"] != 5 {
		t.Errorf("totals %v, want SCG 8 and CK 5", rows.optimizedTotals)
	}
}

// Moves come only from a results page pricing its own rows, in the mode
// they were made in; a line short of a card or a store is skipped.
func TestReadOptMoves(t *testing.T) {
	const moves = "buylist\r\ncard\tNM\tSCG\r\nother\t\tCK\r\nbad line\r\n\tNM\tCK\r\nnostore\tNM\t\r\n"
	both := map[string]string{"cardNM": "SCG", "other": "CK"}
	for _, tc := range []struct {
		name   string
		rows   string
		moves  string
		blMode bool
		want   map[string]string
	}{
		{"buylist", "card\t1", moves, true, both},
		{"switched to retail", "card\t1", moves, false, nil},
		{"a list that is not the page's", "", moves, true, nil},
		{"retail", "card\t1", "retail\ncard\t\tCK", false, map[string]string{"card": "CK"}},
		{"no moves", "card\t1", "", true, nil},
	} {
		form := url.Values{"rows": {tc.rows}, "opt_moves": {tc.moves}}
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		got := readOptMoves(req, tc.blMode)
		if !maps.Equal(got, tc.want) {
			t.Errorf("%s: read %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A row's Move to list is the page's other stores that offer for it, best
// first in the page's direction, each once; a price under no store of the
// page's, an index's, is not one.
func TestMoveOptions(t *testing.T) {
	stores := []string{"CK", "SCG", "ABU", "CSI", "SCG"}
	prices := map[string]float64{"CK": 5, "SCG": 4, "ABU": 6, "CSI": 4, "TCGLow": 9}
	if got := moveOptions(stores, "CK", prices, true); got != "ABU:6.00,SCG:4.00,CSI:4.00" {
		t.Errorf("buylist: %q", got)
	}
	if got := moveOptions(stores, "CK", prices, false); got != "SCG:4.00,CSI:4.00,ABU:6.00" {
		t.Errorf("retail: %q", got)
	}
	if got := moveOptions([]string{"CK", "SCG"}, "CK", map[string]float64{"CK": 5}, true); got != "" {
		t.Errorf("no other offer: %q", got)
	}
}

// Every optimizer row another store offers for gets a Move to button and an
// empty menu the script fills from the row, at retail as on a buylist; a
// moved row is marked with the store it was moved to.
func TestOptimizerMoveMenu(t *testing.T) {
	for _, buylist := range []bool{true, false} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			IsBuylist:    buylist,
			ScraperKeys:  []string{"CK", "SCG"},
			ResultPrices: map[string]map[string]float64{"aNM": {"CK": 5, "SCG": 4}, "b": {"CK": 2}, "c": {"CK": 3, "SCG": 1}},
			Optimized: map[string][]OptimizedUploadEntry{"CK": {
				{CardID: "a", Condition: "NM", Quantity: 1},
				{CardID: "b", Quantity: 1},
				{CardID: "c", Quantity: 1, Moved: true},
			}},
			OptimizedKeys:   []string{"CK"},
			OptimizedTotals: map[string]float64{"CK": 10},
		}})
		if strings.Count(out, `class="opt-move-btn"`) != 2 {
			t.Errorf("buylist %v: want buttons on a and c alone", buylist)
		}
		for _, want := range []string{
			`data-opt-id="a" data-opt-cond="NM" data-move="SCG:4.00"`,
			`data-opt-id="b" data-opt-cond="" data-opt-price`,
			`data-opt-id="c" data-opt-cond="" class="opt-moved" data-opt-moved="CK" data-move="SCG:1.00"`,
			`popovertarget="opt-move-CK-0"`,
			`<div class="opt-move-menu" id="opt-move-CK-0" popover></div>`,
			`title="Moved here by you"`,
			`<svg aria-hidden="true"><use href="#opt-move-icon"/></svg>`,
			`window.BAN_OPT_STORE_NAMES = `,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("buylist %v: no %s", buylist, want)
			}
		}
	}
}
