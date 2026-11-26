package main

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/uploadtie"
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
	return priceUploadRows(backend(), true, st, prices, uploadIndexes{}, nil, entries)
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
		got := readOptMoves(req, tc.blMode, false)
		if !maps.Equal(got, tc.want) {
			t.Errorf("%s: read %v, want %v", tc.name, got, tc.want)
		}
	}
}

// With conditions ignored no row holds one, so a move is read without the
// condition its row showed, and a card moved to two stores has no move.
func TestReadOptMovesWithConditionsIgnored(t *testing.T) {
	form := url.Values{"rows": {"card\t1"}, "opt_moves": {"retail\ncard\tSP\tSCG\ncard\tMP\tSCG\nother\t\tCK\nsplit\tSP\tSCG\nsplit\tMP\tCK\nsplit\tHP\tCK"}}
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := readOptMoves(req, false, true)
	want := map[string]string{"card": "SCG", "other": "CK", "split": ""}
	if !maps.Equal(got, want) {
		t.Errorf("read %v, want %v", got, want)
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
// empty menu the script fills from the row, at retail as on a buylist, and
// on a buylist every row does; a moved row is marked with the store it was
// moved to.
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
		// On a buylist b can still go to Not bought
		buttons := 2
		if buylist {
			buttons = 3
		}
		if strings.Count(out, `class="opt-move-btn"`) != buttons {
			t.Errorf("buylist %v: want %d buttons", buylist, buttons)
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

// On a buylist a card moved to Not bought leaves every store's list and the
// highest total, past its offers, and lists there with the stores it can
// go back to; at retail, which has no such section, the move is ignored.
func TestOptimizerMovesToNotBought(t *testing.T) {
	st := uploadSettings{moves: map[string]string{"card": notBoughtMove}}
	entries := []UploadEntry{{CardID: "card", OriginalPrice: 10}, {CardID: "other", OriginalPrice: 10}}
	rows := moveRows(t, entries, st)
	if got := sectionOf(rows, "card"); got != nil {
		t.Errorf("card at %q, want no store", got)
	}
	if got := sectionOf(rows, "other"); strings.Join(got, ",") != "CK" {
		t.Errorf("other at %q, want CK", got)
	}
	if rows.highestTotal != 5 {
		t.Errorf("highest total %v, want 5", rows.highestTotal)
	}
	notBought := rows.notBought.rows
	if len(notBought) != 1 || notBought[0].CardID != "card" || !notBought[0].Moved || notBought[0].Store != "" {
		t.Errorf("not bought %+v, want card alone, moved, with no store", notBought)
	}
	if len(rows.filteredOut.rows) != 0 {
		t.Errorf("filtered out %+v, want none", rows.filteredOut.rows)
	}

	v := UploadVars{IsBuylist: true, NotBought: notBought, ResultPrices: rows.resultPrices}
	v.fillCarts(nil, []string{"CK", "SCG", "ABU"})
	if v.NotBought[0].MoveTo != "CK:5.00,SCG:4.00" {
		t.Errorf("move to %q, want CK and SCG", v.NotBought[0].MoveTo)
	}

	prices := uploadPrices{
		results:       map[string]map[string]*BanPrice{"card": {"CK": {Regular: 5}}},
		enabledStores: []string{"CK"},
	}
	retail := priceUploadRows(backend(), false, uploadSettings{moves: st.moves, percMargin: 1, multiplier: 1}, prices, uploadIndexes{}, nil, entries[:1])
	if got := sectionOf(retail, "card"); strings.Join(got, ",") != "CK" {
		t.Errorf("retail: card at %q, want CK", got)
	}
}

// A card moved to Not bought is marked as moved there, with a Move to
// button that leads back out; a card no store buys has none.
func TestNotBoughtMoveMenu(t *testing.T) {
	out := renderUpload(t, PageVars{UploadVars: UploadVars{
		IsBuylist:     true,
		ScraperKeys:   []string{"CK", "SCG"},
		UploadEntries: []UploadEntry{{CardID: "a"}, {CardID: "b"}},
		ResultPrices:  map[string]map[string]float64{"a": {"CK": 5}},
		NotBought: []LeftoverEntry{
			{CardID: "a", Quantity: 1, Moved: true},
			{CardID: "b", Quantity: 1},
		},
	}})
	section := leftoverRows(out, "opt-not-bought")
	if strings.Count(section, `class="opt-move-btn"`) != 1 {
		t.Errorf("want a button on a alone: %s", section)
	}
	for _, want := range []string{
		`data-opt-id="a" data-opt-cond="" class="opt-moved" data-opt-moved="-" data-move="CK:5.00"`,
		`data-opt-id="b" data-opt-cond="" data-k-name`,
		`popovertarget="opt-not-bought-move-0" title="Moved here by you"`,
	} {
		if !strings.Contains(section, want) {
			t.Errorf("no %s", want)
		}
	}
}

// A card moved to Not bought goes to no store, so it adds to no store's
// share of the list: CK's sole offer on it would win the tie on "tied" for
// CK, where SCG's sole offer on "scg" wins it without.
func TestNotBoughtMoveTipsNoTie(t *testing.T) {
	prices := uploadPrices{
		results: map[string]map[string]*BanPrice{
			"moved": {"CK": {Regular: 5}},
			"tied":  {"CK": {Regular: 3}, "SCG": {Regular: 3}},
			"scg":   {"SCG": {Regular: 2}},
		},
		enabledStores: []string{"CK", "SCG"},
	}
	entries := []UploadEntry{{CardID: "moved"}, {CardID: "tied"}, {CardID: "scg"}}
	for _, tc := range []struct {
		moves map[string]string
		want  string
	}{
		{nil, "CK"},
		{map[string]string{"moved": notBoughtMove}, "SCG"},
	} {
		st := uploadSettings{moves: tc.moves, percMargin: 1, multiplier: 1, tiebreak: uploadtie.Consolidate}
		rows := priceUploadRows(backend(), true, st, prices, uploadIndexes{}, nil, entries)
		if got := sectionOf(rows, "tied"); strings.Join(got, ",") != tc.want {
			t.Errorf("moves %v: tied at %q, want %s", tc.moves, got, tc.want)
		}
	}
}

// A card's lines at two prices share the copies cap: the later line adds
// only what the earlier one left, and nothing past it.
func TestOptimizerCapsACardsLinesTogether(t *testing.T) {
	entries := []UploadEntry{
		{CardID: "card", Quantity: 3, HasQuantity: true, OriginalPrice: 1},
		{CardID: "card", Quantity: 3, HasQuantity: true, OriginalPrice: 2},
		{CardID: "card", Quantity: 3, HasQuantity: true, OriginalPrice: 3},
	}
	rows := moveRows(t, entries, uploadSettings{maxQty: 4})
	var got []string
	for _, entry := range rows.optimizedResults["CK"] {
		got = append(got, fmt.Sprintf("%v x%d", entry.LoadedPrice, entry.Quantity))
	}
	if !slices.Equal(got, []string{"1 x3", "2 x1"}) {
		t.Errorf("CK lists %q, want the $1 line's 3 and the $2 line's 1", got)
	}
	if rows.optimizedQtys["CK"] != 4 {
		t.Errorf("CK counts %d copies, want the cap's 4", rows.optimizedQtys["CK"])
	}
}
