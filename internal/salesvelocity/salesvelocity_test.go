package salesvelocity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// snapshotOf is a load of cards.
func snapshotOf(cards map[string]*Sales) *Snapshot {
	return &Snapshot{Day: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), Cards: cards, Window: Window}
}

// TestBuild keys the pairs by card, adds up pairs on one card,
// keeps a year's sale with no sale in the window, and drops unmatched pairs.
func TestBuild(t *testing.T) {
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }
	rows := []salesRow{
		{ProductID: 1, Variant: "Normal", Copies: 69, Orders: 31, Days: 18, Price: 1.5},
		{ProductID: 2, Variant: "Foil", Copies: 12, Orders: 9, Days: 4, Price: 40},
		// Two products filed under one card: copies and orders add up, and
		// the price is their mean weighted by orders.
		{ProductID: 3, Variant: "Normal", Copies: 2, Orders: 2, Days: 2, Price: 2, RecentOrders: 1},
		{ProductID: 4, Variant: "Normal", Copies: 3, Orders: 1, Days: 1, Price: 5, RecentOrders: 1},
		// Their days keep the larger count, not the sum: the rows can't say which days overlap.
		{ProductID: 7, Variant: "Normal", Copies: 40, Orders: 40, Days: 12, Price: 1},
		{ProductID: 8, Variant: "Normal", Copies: 40, Orders: 40, Days: 20, Price: 1},
		// No card.
		{ProductID: 5, Variant: "Normal", Copies: 1, Orders: 1, Days: 1},
	}
	last := []lastRow{
		{ProductID: 1, Variant: "Normal", Last: day(10, 11), First: day(1, 5)},
		{ProductID: 2, Variant: "Foil", Last: day(10, 12), First: day(10, 1)},
		// The first sale is the earlier of the two.
		{ProductID: 3, Variant: "Normal", Last: day(10, 10), First: day(4, 2)},
		{ProductID: 4, Variant: "Normal", Last: day(10, 12), First: day(3, 9)},
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

	cards, unmatched := build(rows, last, nil, match)
	if unmatched != 2 {
		t.Errorf("unmatched: got %d, want 2", unmatched)
	}
	want := map[string]Sales{
		"steady": {Copies: 69, Orders: 31, Days: 18, FirstSale: day(1, 5), LastSale: day(10, 11), Price: 1.5},
		"foil":   {Copies: 12, Orders: 9, Days: 4, FirstSale: day(10, 1), LastSale: day(10, 12), Price: 40},
		"merged": {Copies: 5, Orders: 3, Days: 2, FirstSale: day(3, 9), LastSale: day(10, 12), Price: 3, RecentOrders: 2},
		"busy":   {Copies: 80, Orders: 80, Days: 20, LastSale: day(10, 12), Price: 1},
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

// TestBuildOrders attaches the newest order to a card with a sale in the lookback.
func TestBuildOrders(t *testing.T) {
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }
	at := func(m time.Month, d, h int) time.Time { return time.Date(2026, m, d, h, 4, 0, 0, time.UTC) }
	ids := map[salesPair]string{{1, "Normal"}: "card", {2, "Normal"}: "card", {3, "Normal"}: "other"}
	match := func(productID int64, variant string) string { return ids[salesPair{productID, variant}] }
	one := []lastRow{{ProductID: 1, Variant: "Normal", Last: day(11, 17)}}
	two := []lastRow{
		{ProductID: 1, Variant: "Normal", Last: day(11, 17)},
		{ProductID: 2, Variant: "Normal", Last: day(11, 17)},
	}
	for _, tc := range []struct {
		desc      string
		last      []lastRow
		orders    []orderRow
		want      Sales
		unmatched int
		cards     int
	}{
		{"same day", one, []orderRow{{1, "Normal", at(11, 17, 15), "Lightly Played", 12.34}},
			Sales{LastSale: day(11, 17), LastPrice: 12.34, LastCondition: "LP"}, 0, 1},
		{"a later day moves the date", one, []orderRow{{1, "Normal", time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC), "Near Mint", 3}},
			Sales{LastSale: day(11, 18), LastPrice: 3, LastCondition: "NM"}, 0, 1},
		{"an earlier day is left out", one, []orderRow{{1, "Normal", at(11, 10, 1), "Near Mint", 3}},
			Sales{LastSale: day(11, 17)}, 0, 1},
		{"the later of two pairs", two, []orderRow{
			{1, "Normal", at(11, 17, 10), "Near Mint", 5},
			{2, "Normal", at(11, 17, 12), "Near Mint", 6},
		}, Sales{LastSale: day(11, 17), LastPrice: 6, LastCondition: "NM"}, 0, 1},
		{"the same instant keeps the first", two, []orderRow{
			{1, "Normal", at(11, 17, 10), "Near Mint", 5},
			{2, "Normal", at(11, 17, 10), "Near Mint", 6},
		}, Sales{LastSale: day(11, 17), LastPrice: 5, LastCondition: "NM"}, 0, 1},
		{"a matched pair with no lookback row", one, []orderRow{{3, "Normal", at(11, 17, 10), "Near Mint", 5}},
			Sales{LastSale: day(11, 17)}, 0, 1},
		{"no price", one, []orderRow{{1, "Normal", at(11, 17, 10), "Near Mint", 0}},
			Sales{LastSale: day(11, 17)}, 0, 1},
		{"a moved date does not disqualify the other pair", two, []orderRow{
			{1, "Normal", at(11, 18, 3), "Near Mint", 7},
			{2, "Normal", at(11, 17, 3), "Near Mint", 4},
		}, Sales{LastSale: day(11, 18), LastPrice: 7, LastCondition: "NM"}, 0, 1},
	} {
		cards, unmatched := build(nil, tc.last, tc.orders, match)
		if unmatched != tc.unmatched || len(cards) != tc.cards {
			t.Errorf("%s: %d cards, %d unmatched; want %d, %d", tc.desc, len(cards), unmatched, tc.cards, tc.unmatched)
		}
		got := cards["card"]
		if got == nil || got.LastSale != tc.want.LastSale || got.LastPrice != tc.want.LastPrice || got.LastCondition != tc.want.LastCondition {
			t.Errorf("%s: got %+v, want %+v", tc.desc, got, tc.want)
		}
	}
}

// TestBuildOrdersUnmatched counts a pair no card matches once, by its sales row.
func TestBuildOrdersUnmatched(t *testing.T) {
	at := time.Date(2026, 11, 17, 10, 4, 0, 0, time.UTC)
	match := func(int64, string) string { return "" }
	last := []lastRow{{ProductID: 9, Variant: "Normal", Last: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}}
	orders := []orderRow{{9, "Normal", at, "Near Mint", 5}}
	cards, unmatched := build(nil, last, orders, match)
	if unmatched != 1 || len(cards) != 0 {
		t.Errorf("got %d cards, %d unmatched; want 0, 1", len(cards), unmatched)
	}
}

// TestShortCondition abbreviates TCGplayer's grades, drops a sealed product's
// and leaves the rest as sent.
func TestShortCondition(t *testing.T) {
	for in, want := range map[string]string{
		"Near Mint": "NM", "Lightly Played": "LP", "Moderately Played": "MP",
		"Heavily Played": "HP", "Damaged": "DMG", "Unopened": "", "Other": "Other", "": "",
	} {
		if got := shortCondition(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// pricedCards is n cards at price, selling 1 to n copies, keyed prefix and copies.
func pricedCards(cards map[string]*Sales, prefix string, n int, price float64) {
	for k := 1; k <= n; k++ {
		cards[fmt.Sprintf("%s%d", prefix, k)] = &Sales{Copies: int32(k), Price: price}
	}
}

// TestGrade judges each card against its own price band: the fastest tenth,
// the next three, the bottom quarter, and no sale in the window as slow. A
// band too small to grade joins the one below it.
func TestGrade(t *testing.T) {
	cards := map[string]*Sales{"zero": {}}
	pricedCards(cards, "cheap", 200, 0.5)
	// Too few to grade apart, so they join the band below, down to the cheap one.
	pricedCards(cards, "mid", 10, 50)
	// A band of their own, selling a tenth as many copies.
	for k := range 200 {
		cards[fmt.Sprintf("rare%d-%d", k/10+1, k%10)] = &Sales{Copies: int32(k/10 + 1), Price: 500}
	}

	bands := grade(cards)
	want := []Band{{0, 300}, {300, 0}}
	if !slices.Equal(bands, want) {
		t.Fatalf("bands: got %v, want %v", bands, want)
	}
	for _, tc := range []struct {
		card string
		pace Pace
		band int8
	}{
		{"zero", PaceSlow, 0},
		// 210 cards, the mid ones among them: the fastest 21, the next 63,
		// down to the slowest 52.
		{"cheap180", PaceFastest, 0},
		{"cheap179", PaceFast, 0},
		{"cheap117", PaceFast, 0},
		{"cheap116", PaceSteady, 0},
		{"cheap44", PaceSteady, 0},
		{"cheap43", PaceSlow, 0},
		{"cheap1", PaceSlow, 0},
		{"mid10", PaceSlow, 0},
		// Twenty copies is slow for a cheap card, the fastest for a $500 one.
		{"cheap20", PaceSlow, 0},
		{"rare20-0", PaceFastest, 1},
		{"rare6-0", PaceSteady, 1},
		{"rare5-0", PaceSlow, 1},
	} {
		v := cards[tc.card]
		if v.Pace != tc.pace || v.Band != tc.band {
			t.Errorf("%s: got %v in band %d, want %v in band %d", tc.card, v.Pace, v.Band, tc.pace, tc.band)
		}
	}

	// A lowest band too small joins the one above it.
	cards = map[string]*Sales{}
	pricedCards(cards, "cheap", 10, 0.5)
	pricedCards(cards, "pricey", 200, 50)
	bands = grade(cards)
	if !slices.Equal(bands, []Band{{0, 0}}) {
		t.Errorf("one band: got %v", bands)
	}
}

// TestBandString names a band's prices for the details.
func TestBandString(t *testing.T) {
	for band, want := range map[Band]string{
		{0, 1}:      "under $1",
		{10, 30}:    "at $10–30",
		{300, 0}:    "at $300+",
		{0.5, 2.25}: "at $0.5–2.25",
		{0, 0}:      "",
	} {
		got := band.String()
		if got != want {
			t.Errorf("%v: got %q, want %q", band, got, want)
		}
	}
}

// TestRising flags a card selling at least twice as fast in the last week, in
// orders, once it has enough of them to tell from noise and sold before the window.
func TestRising(t *testing.T) {
	start := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	before, inside := start.AddDate(0, -2, 0), start.AddDate(0, 0, 3)
	for _, tc := range []struct {
		desc           string
		orders, recent int32
		first          time.Time
		window         int
		want           float64
	}{
		{"twice as fast", 37, 14, before, 30, 2},
		{"faster still", 30, 14, before, 30, 14.0 / 7 / (16.0 / 23)},
		{"just under twice", 37, 13, before, 30, 0},
		{"too few orders", 29, 14, before, 30, 0},
		{"steady", 30, 8, before, 30, 0},
		{"no sale before the week", 40, 40, before, 30, 0},
		{"one order before the week", 30, 29, before, 30, 29.0 / 7 * 23},
		{"first sold in the window", 37, 14, inside, 30, 0},
		{"first sold on the window's first day", 37, 14, start, 30, 0},
		{"a window no longer than the week", 40, 20, before, 7, 0},
	} {
		got := Sales{Orders: tc.orders, RecentOrders: tc.recent, FirstSale: tc.first}.Rising(tc.window, start)
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.desc, got, tc.want)
		}
	}
	// snapshotOf's window starts on start.
	s := snapshotOf(map[string]*Sales{
		"up":    {Copies: 40, Orders: 37, RecentOrders: 14, Days: 20, FirstSale: before},
		"new":   {Copies: 40, Orders: 37, RecentOrders: 14, Days: 20, FirstSale: inside},
		"flat":  {Orders: 30, RecentOrders: 7, FirstSale: before},
		"spike": {Copies: 30, Orders: 30, RecentOrders: 29, Days: 8, FirstSale: before},
	})
	if !s.Rising("up") || s.Rising("new") || s.Rising("flat") || s.Rising("missing") || (*Snapshot)(nil).Rising("up") {
		t.Error("Snapshot.Rising disagrees with Sales.Rising")
	}
	_, detail, _ := s.View("up")
	if !strings.Contains(detail, "|orders|37|7-day trend|2.0×") {
		t.Errorf("up: no trend ending the orders row: %q", detail)
	}
	_, detail, _ = s.View("new")
	if strings.Contains(detail, "7-day trend") {
		t.Errorf("new: a trend line: %q", detail)
	}
	// One order before the week makes 95×, which the details cap.
	_, detail, _ = s.View("spike")
	if !s.Rising("spike") || !strings.Contains(detail, "|7-day trend|over 5×") {
		t.Errorf("spike: got %q", detail)
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
	s := snapshotOf(map[string]*Sales{"card": {Copies: 69, Orders: 31, Days: 18}})
	got, found := s.For("card")
	if !found || got != (Sales{Copies: 69, Orders: 31, Days: 18}) {
		t.Errorf("card: got %+v, %v", got, found)
	}
	_, found = s.For("missing")
	if found {
		t.Error("missing: found")
	}
	_, found = (*Snapshot)(nil).For("card")
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
		Priced: 2,
	}
	got := report(snap, 7)
	want := "3 cards over the 30 days to 2026-10-12, 7 not matched, 2 with a last sale price"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = alreadyLoadedLine(snap)
	want = "3 cards over the 30 days to 2026-10-12, already loaded, 2 with a last sale price"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	note := `last sale prices unavailable: relation "tcgplayerlastsalemodel" does not exist`
	snap.Priced, snap.Note = 0, note
	got = alreadyLoadedLine(snap)
	want = "3 cards over the 30 days to 2026-10-12, already loaded, 0 with a last sale price; " + note
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = report(snap, 3)
	want = "3 cards over the 30 days to 2026-10-12, 3 not matched, 0 with a last sale price; " + note
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestOrdersUnavailable notes a missing table and a denied read, nothing else.
func TestOrdersUnavailable(t *testing.T) {
	absent := `relation "tcgplayerlastsalemodel" does not exist`
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&pq.Error{Code: "42P01", Message: absent}, "last sale prices unavailable: " + absent},
		{&pq.Error{Code: "42501", Message: "denied"}, "last sale prices unavailable: denied"},
		{fmt.Errorf("x: %w", &pq.Error{Code: "42P01", Message: absent}), "last sale prices unavailable: " + absent},
		{fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: "denied"}), "last sale prices unavailable: denied"},
		{&pq.Error{Code: "57014"}, ""},
		{sql.ErrNoRows, ""},
		{nil, ""},
	} {
		if got := ordersUnavailable(tc.err); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestOrdersOrNote keeps the orders, or loads without them on an absent table.
func TestOrdersOrNote(t *testing.T) {
	ctx := context.Background()
	rows := []orderRow{{ProductID: 1, Variant: "Normal", Price: 2.5}}
	got, note, err := ordersOrNote(ctx, rows, nil)
	if err != nil || note != "" || !slices.Equal(got, rows) {
		t.Errorf("rows: got %v, %q, %v", got, note, err)
	}
	// Rows read before the table went missing are dropped with it.
	absent := &pq.Error{Code: "42P01", Message: `relation "tcgplayerlastsalemodel" does not exist`}
	got, note, err = ordersOrNote(ctx, rows, absent)
	if err != nil || got != nil || note != `last sale prices unavailable: relation "tcgplayerlastsalemodel" does not exist` {
		t.Errorf("absent: got %v, %q, %v", got, note, err)
	}
	boom := errors.New("boom")
	got, note, err = ordersOrNote(ctx, nil, boom)
	if !errors.Is(err, boom) || got != nil || note != "" {
		t.Errorf("other: got %v, %q, %v", got, note, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	got, note, err = ordersOrNote(cancelled, nil, absent)
	if !errors.Is(err, absent) || got != nil || note != "" {
		t.Errorf("cancelled: got %v, %q, %v", got, note, err)
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

// TestLastOrderQuery reads one game's newest orders, whatever their date.
func TestLastOrderQuery(t *testing.T) {
	for _, part := range []string{
		"tcgplayerlastsalemodel",
		"ORDER BY product_id, variant",
		"product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1)",
	} {
		if !strings.Contains(LastOrderQuery, part) {
			t.Errorf("missing %q", part)
		}
	}
	if strings.Contains(LastOrderQuery, "BETWEEN") || strings.Contains(LastOrderQuery, "$2") {
		t.Error("the order query is bound by a date")
	}
}

// TestDayQueries keeps both day queries to an index walk over the window,
// and only the game's own to its products: the complete day is every game's.
func TestDayQueries(t *testing.T) {
	semiJoin := "SELECT product_id FROM tcgplayerproductinfomodel"
	for _, tc := range []struct {
		name, query, bound string
		ownGame            bool
	}{
		{"game", DayQuery, "sale_date > current_date - $2::int", true},
		{"global", GlobalDayQuery, "sale_date > current_date - $1::int", false},
	} {
		if !strings.Contains(tc.query, tc.bound) || !strings.Contains(tc.query, "ORDER BY sale_date DESC") {
			t.Errorf("%s: not a walk down the date index over the window", tc.name)
		}
		if strings.Contains(tc.query, "max(") {
			t.Errorf("%s: reads every row with a max()", tc.name)
		}
		if strings.Contains(tc.query, semiJoin) != tc.ownGame {
			t.Errorf("%s: keeps to one game %v, want %v", tc.name, !tc.ownGame, tc.ownGame)
		}
	}
}

// TestText words each state: a rate to one decimal, under a tenth, and
// zero with the last sale, the counts as pairs and the last sale after a rule.
func TestText(t *testing.T) {
	day := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	last := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		desc         string
		v            Sales
		window       int
		trend        string
		rate, detail string
	}{
		{"a rate", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last}, 30, "", "2.3/day",
			"|copies|69|days|18/30\n|orders|31\n\n|last sale|Oct 11"},
		{"rounded to one decimal", Sales{Copies: 74, Orders: 60, Days: 25, LastSale: last}, 30, "", "2.5/day",
			"|copies|74|days|25/30\n|orders|60\n\n|last sale|Oct 11"},
		{"a whole number keeps its decimal", Sales{Copies: 60, Orders: 50, Days: 30, LastSale: last}, 30, "", "2.0/day",
			"|copies|60|days|30/30\n|orders|50\n\n|last sale|Oct 11"},
		{"a tenth", Sales{Copies: 3, Orders: 3, Days: 3, LastSale: last}, 30, "", "0.1/day",
			"|copies|3|days|3/30\n|orders|3\n\n|last sale|Oct 11"},
		{"under a tenth", Sales{Copies: 2, Orders: 2, Days: 1, LastSale: last}, 30, "", "<0.1/day",
			"|copies|2|days|1/30\n|orders|2\n\n|last sale|Oct 11"},
		{"a trend", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last}, 30, "|7-day trend|2.1×", "2.3/day",
			"|copies|69|days|18/30\n|orders|31|7-day trend|2.1×\n\n|last sale|Oct 11"},
		{"no last sale", Sales{Copies: 69, Orders: 31, Days: 18}, 30, "", "2.3/day",
			"|copies|69|days|18/30\n|orders|31"},
		{"zero", Sales{LastSale: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}, 30, "", "0/day",
			"no sale in 30 days\n|last sale|Sep 2"},
		{"zero with no sale in the year", Sales{}, 30, "", "0/day", "no sale in 30 days"},
		{"a sale last year", Sales{LastSale: time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC)}, 30, "", "0/day",
			"no sale in 30 days\n|last sale|Nov 20, 2025"},
		{"a price and condition", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last, LastPrice: 12.34, LastCondition: "LP"}, 30, "", "2.3/day",
			"|copies|69|days|18/30\n|orders|31\n\n|last sale|$12.34 LP · Oct 11"},
		{"a price with no condition", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last, LastPrice: 12.34}, 30, "", "2.3/day",
			"|copies|69|days|18/30\n|orders|31\n\n|last sale|$12.34 · Oct 11"},
		{"a price under a dollar", Sales{Copies: 69, Orders: 31, Days: 18, LastSale: last, LastPrice: 0.5}, 30, "", "2.3/day",
			"|copies|69|days|18/30\n|orders|31\n\n|last sale|$0.50 · Oct 11"},
		{"zero with a price", Sales{LastSale: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), LastPrice: 12.34, LastCondition: "LP"}, 30, "", "0/day",
			"no sale in 30 days\n|last sale|$12.34 LP · Aug 2"},
		{"another window", Sales{Copies: 7, Orders: 7, Days: 5, LastSale: last}, 7, "", "1.0/day",
			"|copies|7|days|5/7\n|orders|7\n\n|last sale|Oct 11"},
	} {
		rate, detail := text(tc.v, tc.window, day, tc.trend)
		if rate != tc.rate || detail != tc.detail {
			t.Errorf("%s: got %q, %q; want %q, %q", tc.desc, rate, detail, tc.rate, tc.detail)
		}
	}
}

// TestPaceNote names the band a graded card's pace was judged in, and
// leaves the details without it.
func TestPaceNote(t *testing.T) {
	last := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	s := snapshotOf(map[string]*Sales{
		"fastest":  {Copies: 69, Orders: 31, Days: 18, LastSale: last, Pace: PaceFastest, Band: 1},
		"fast":     {Copies: 9, Pace: PaceFast, Band: 1},
		"steady":   {Copies: 3, Pace: PaceSteady},
		"slow":     {Copies: 1, Pace: PaceSlow},
		"zero":     {LastSale: last, Pace: PaceSlow},
		"ungraded": {Copies: 1},
		"no band":  {Copies: 1, Pace: PaceSlow, Band: 2},
	})
	s.Bands = []Band{{0, 30}, {30, 100}}
	for card, want := range map[string]string{
		"fastest":  "Among the fastest $30–100 cards",
		"fast":     "Fast for a $30–100 card",
		"steady":   "Steady for a card under $30",
		"slow":     "Slow for a card under $30",
		"zero":     "",
		"ungraded": "",
		"no band":  "",
		"missing":  "",
	} {
		got := s.PaceNote(card)
		if got != want {
			t.Errorf("%s: got %q, want %q", card, got, want)
		}
	}
	s.Bands = []Band{{0, 30}, {30, 0}}
	got := s.PaceNote("fastest")
	if got != "Among the fastest $30+ cards" {
		t.Errorf("open band: got %q", got)
	}
	s.Bands = []Band{{}}
	got = s.PaceNote("slow")
	if got != "Slow for a card" {
		t.Errorf("one band: got %q", got)
	}
	s.Bands = []Band{{0, 30}, {30, 100}}
	_, detail, _ := s.View("fastest")
	if detail != "|copies|69|days|18/30\n|orders|31\n\n|last sale|Oct 11" {
		t.Errorf("details: got %q", detail)
	}
	if s.Pace("fast") != PaceFast || s.Pace("missing") != PaceNone || (*Snapshot)(nil).Pace("card") != PaceNone {
		t.Error("a card's pace is not the one graded, or a card with no data has one")
	}
	if (*Snapshot)(nil).PaceNote("card") != "" {
		t.Error("nothing loaded: a note")
	}
}

// TestView words a loaded card and leaves a card with no data blank.
func TestView(t *testing.T) {
	v := Sales{Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	s := snapshotOf(map[string]*Sales{"card": &v})
	wantRate, wantDetail := text(v, Window, s.Day, "")
	rate, detail, _ := s.View("card")
	if rate != wantRate || detail != wantDetail {
		t.Errorf("card: got %q, %q; want %q, %q", rate, detail, wantRate, wantDetail)
	}
	rate, detail, _ = s.View("missing")
	if rate != "" || detail != "" {
		t.Errorf("missing: got %q, %q; want nothing", rate, detail)
	}
	rate, detail, _ = (*Snapshot)(nil).View("card")
	if rate != "" || detail != "" {
		t.Errorf("nothing loaded: got %q, %q; want nothing", rate, detail)
	}
	if rates := (*Snapshot)(nil).Rates([]string{"card"}); len(rates) != 0 {
		t.Errorf("nothing loaded: got rates %v", rates)
	}
}

// TestViewNotable leaves out every rate that prints as 0.1/day or less.
func TestViewNotable(t *testing.T) {
	s := snapshotOf(map[string]*Sales{
		"zero":  {},
		"tenth": {Copies: 3},
		"round": {Copies: 4},
		"low":   {Copies: 5},
		"fast":  {Copies: 69},
	})
	for _, tc := range []struct {
		card, rate string
		notable    bool
	}{
		{"zero", "0/day", false},
		{"tenth", "0.1/day", false},
		{"round", "0.1/day", false},
		{"low", "0.2/day", true},
		{"fast", "2.3/day", true},
		{"missing", "", false},
	} {
		rate, _, notable := s.View(tc.card)
		if rate != tc.rate || notable != tc.notable {
			t.Errorf("%s: got %q, %v; want %q, %v", tc.card, rate, notable, tc.rate, tc.notable)
		}
	}
}
