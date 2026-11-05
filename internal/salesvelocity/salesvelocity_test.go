package salesvelocity

import (
	"strings"
	"testing"
	"time"
)

// storeOf is a store whose last load is cards.
func storeOf(cards map[string]*Sales) *Store {
	s := &Store{}
	s.Publish(&Snapshot{Day: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), Cards: cards, Window: Window})
	return s
}

// TestBuild keys the pairs by card, adds up pairs on one card,
// keeps a year's sale with no sale in the window, and drops unmatched pairs.
func TestBuild(t *testing.T) {
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }
	rows := []salesRow{
		{ProductID: 1, Variant: "Normal", Copies: 69, Orders: 31, Days: 18},
		{ProductID: 2, Variant: "Foil", Copies: 12, Orders: 9, Days: 4},
		// Two products filed under one card: copies and orders add up.
		{ProductID: 3, Variant: "Normal", Copies: 2, Orders: 2, Days: 2},
		{ProductID: 4, Variant: "Normal", Copies: 3, Orders: 1, Days: 1},
		// Their days keep the larger count, not the sum: the rows can't say which days overlap.
		{ProductID: 7, Variant: "Normal", Copies: 40, Orders: 40, Days: 12},
		{ProductID: 8, Variant: "Normal", Copies: 40, Orders: 40, Days: 20},
		// No card.
		{ProductID: 5, Variant: "Normal", Copies: 1, Orders: 1, Days: 1},
	}
	last := []lastRow{
		{ProductID: 1, Variant: "Normal", Last: day(10, 11)},
		{ProductID: 2, Variant: "Foil", Last: day(10, 12)},
		{ProductID: 3, Variant: "Normal", Last: day(10, 10)},
		{ProductID: 4, Variant: "Normal", Last: day(10, 12)},
		{ProductID: 7, Variant: "Normal", Last: day(10, 12)},
		{ProductID: 8, Variant: "Normal", Last: day(10, 11)},
		{ProductID: 5, Variant: "Normal", Last: day(10, 12)},
		// Sold in the year, not in the window.
		{ProductID: 6, Variant: "Normal", Last: day(8, 2)},
		// No card, and no sale in the window.
		{ProductID: 9, Variant: "Foil", Last: day(3, 1)},
	}
	ids := map[salesPair]string{
		{1, "Normal"}: "steady", {2, "Foil"}: "foil",
		{3, "Normal"}: "merged", {4, "Normal"}: "merged",
		{6, "Normal"}: "zero", {7, "Normal"}: "busy", {8, "Normal"}: "busy",
	}
	asked := map[salesPair]int{}
	match := func(productID int64, variant string) string {
		asked[salesPair{productID, variant}]++
		return ids[salesPair{productID, variant}]
	}

	cards, unmatched := build(rows, last, match)
	if unmatched != 2 {
		t.Errorf("unmatched: got %d, want 2", unmatched)
	}
	want := map[string]Sales{
		"steady": {Copies: 69, Orders: 31, Days: 18, LastSale: day(10, 11)},
		"foil":   {Copies: 12, Orders: 9, Days: 4, LastSale: day(10, 12)},
		"merged": {Copies: 5, Orders: 3, Days: 2, LastSale: day(10, 12)},
		"busy":   {Copies: 80, Orders: 80, Days: 20, LastSale: day(10, 12)},
		"zero":   {LastSale: day(8, 2)},
	}
	if len(cards) != len(want) {
		t.Fatalf("got %d cards, want %d: %+v", len(cards), len(want), cards)
	}
	for id, w := range want {
		got := cards[id]
		if got == nil || *got != w {
			t.Errorf("%s: got %+v, want %+v", id, got, w)
		}
	}
	for pair, n := range asked {
		if n != 1 {
			t.Errorf("%v: matched %d times, want once", pair, n)
		}
	}
}

// TestDue loads a sale day once, and retries a day whose load
// failed only after retryAfter.
func TestDue(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	prev := day.AddDate(0, 0, -1)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	loaded := func(d time.Time) *Snapshot { return &Snapshot{Day: d} }
	failed := func(d time.Time, ago time.Duration) *failure {
		return &failure{Day: d, At: now.Add(-ago)}
	}
	for _, tc := range []struct {
		desc    string
		current *Snapshot
		failed  *failure
		want    bool
	}{
		{"nothing loaded yet", nil, nil, true},
		{"the day is loaded", loaded(day), nil, false},
		{"a newer sale day landed", loaded(prev), nil, true},
		{"the day failed an hour ago", loaded(prev), failed(day, time.Hour), false},
		{"the day failed long enough ago", loaded(prev), failed(day, retryAfter), true},
		{"an older day failed", loaded(prev), failed(prev, time.Hour), true},
		{"the first load failed an hour ago", nil, failed(day, time.Hour), false},
	} {
		got := due(tc.current, tc.failed, day, now)
		if got != tc.want {
			t.Errorf("%s: due = %v, want %v", tc.desc, got, tc.want)
		}
	}
}

// TestFor answers a loaded card's sales, and nothing for a card
// not loaded or before any load.
func TestFor(t *testing.T) {
	s := storeOf(map[string]*Sales{"card": {Copies: 69, Orders: 31, Days: 18}})
	got, found := s.For("card")
	if !found || got != (Sales{Copies: 69, Orders: 31, Days: 18}) {
		t.Errorf("card: got %+v, %v", got, found)
	}
	_, found = s.For("missing")
	if found {
		t.Error("missing: found")
	}
	_, found = (&Store{}).For("card")
	if found {
		t.Error("nothing loaded: found")
	}
}

// TestReport is the line the admin dashboard shows for a load.
func TestReport(t *testing.T) {
	snap := &Snapshot{
		Day:    time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
		Cards:  map[string]*Sales{"a": {Copies: 3}, "b": {Copies: 9}, "c": {}},
		Window: Window,
	}
	got := report(snap, 7)
	want := "3 cards over the 30 days to 2026-10-12, 7 not matched"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestQueries keeps both queries bounded on both ends by the
// arguments and to one game's products.
func TestQueries(t *testing.T) {
	for name, query := range map[string]string{"window": WindowQuery, "lookback": LastQuery} {
		for _, part := range []string{
			"sale_date BETWEEN $1::date AND $2::date",
			"product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $3)",
		} {
			if !strings.Contains(query, part) {
				t.Errorf("%s: missing %q", name, part)
			}
		}
	}
}

// TestText words each state: a rate to one decimal, under a tenth, and
// zero with the last sale.
func TestText(t *testing.T) {
	last := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	const head = "**Sold on TCGplayer, last 30 days**\n"
	for _, tc := range []struct {
		desc         string
		v            Sales
		window       int
		rate, detail string
	}{
		{"a rate", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last}, 30, "2.3/day",
			head + "|copies|69\n|orders|31\n|days with a sale|18\n|last sale|2026-10-11"},
		{"rounded to one decimal", Sales{Copies: 74, Orders: 60, Days: 25, LastSale: last}, 30, "2.5/day",
			head + "|copies|74\n|orders|60\n|days with a sale|25\n|last sale|2026-10-11"},
		{"a whole number keeps its decimal", Sales{Copies: 60, Orders: 50, Days: 30, LastSale: last}, 30, "2.0/day",
			head + "|copies|60\n|orders|50\n|days with a sale|30\n|last sale|2026-10-11"},
		{"a tenth", Sales{Copies: 3, Orders: 3, Days: 3, LastSale: last}, 30, "0.1/day",
			head + "|copies|3\n|orders|3\n|days with a sale|3\n|last sale|2026-10-11"},
		{"under a tenth", Sales{Copies: 2, Orders: 2, Days: 1, LastSale: last}, 30, "<0.1/day",
			head + "|copies|2\n|orders|2\n|days with a sale|1\n|last sale|2026-10-11"},
		{"zero", Sales{LastSale: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}, 30, "0/day",
			head + "no sale in the window; last sold 2026-09-02"},
		{"another window", Sales{Copies: 7, Orders: 7, Days: 5, LastSale: last}, 7, "1.0/day",
			"**Sold on TCGplayer, last 7 days**\n|copies|7\n|orders|7\n|days with a sale|5\n|last sale|2026-10-11"},
	} {
		rate, detail := text(tc.v, tc.window)
		if rate != tc.rate || detail != tc.detail {
			t.Errorf("%s: got %q, %q; want %q, %q", tc.desc, rate, detail, tc.rate, tc.detail)
		}
	}
}

// TestView words a loaded card and leaves a card with no data blank.
func TestView(t *testing.T) {
	v := Sales{Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	s := storeOf(map[string]*Sales{"card": &v})
	wantRate, wantDetail := text(v, Window)
	rate, detail := s.View("card")
	if rate != wantRate || detail != wantDetail {
		t.Errorf("card: got %q, %q; want %q, %q", rate, detail, wantRate, wantDetail)
	}
	rate, detail = s.View("missing")
	if rate != "" || detail != "" {
		t.Errorf("missing: got %q, %q; want nothing", rate, detail)
	}
}
