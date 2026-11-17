package salesvelocity

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
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

	cards, unmatched := build(rows, last, match)
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
	if cards["cheap1"].Outsells != 0 || cards["rare20-0"].Outsells != 95 {
		t.Errorf("outsells: got %v and %v, want 0 and 95", cards["cheap1"].Outsells, cards["rare20-0"].Outsells)
	}

	// A lowest band too small joins the one above it.
	cards = map[string]*Sales{}
	pricedCards(cards, "cheap", 10, 0.5)
	pricedCards(cards, "pricey", 200, 50)
	bands = grade(cards)
	if !slices.Equal(bands, []Band{{0, 0}}) {
		t.Errorf("one band: got %v", bands)
	}

	// Outselling 106 of 200 is 53%, which a float share times 100 puts at 52.99.
	cards = map[string]*Sales{}
	pricedCards(cards, "card", 200, 1)
	grade(cards)
	got := cards["card107"].Outsells
	if got != 53 {
		t.Errorf("card107: outsells %d%%, want 53%%", got)
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
	if !strings.Contains(detail, "|days with a sale|20\n|last 7 days|2.0× the pace before") {
		t.Errorf("up: no trend line before the last sale: %q", detail)
	}
	_, detail, _ = s.View("new")
	if strings.Contains(detail, "last 7 days") {
		t.Errorf("new: a trend line: %q", detail)
	}
	// One order before the week makes 95×, which the details cap.
	_, detail, _ = s.View("spike")
	if !s.Rising("spike") || !strings.Contains(detail, "|last 7 days|over 5× the pace before") {
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

// TestViewPace words a graded card's band in its details, before the last sale.
func TestViewPace(t *testing.T) {
	last := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	s := snapshotOf(map[string]*Sales{
		"fast":    {Copies: 69, Orders: 31, Days: 18, LastSale: last, Pace: PaceFastest, Band: 1, Outsells: 92},
		"slowest": {Copies: 1, Orders: 1, Days: 1, LastSale: last, Pace: PaceSlow},
		"all":     {Copies: 1, Orders: 1, Days: 1, LastSale: last, Pace: PaceSlow},
		"zero":    {LastSale: last, Pace: PaceSlow},
	})
	s.Bands = []Band{{0, 30}, {30, 0}}
	const head = "**Sold on TCGplayer, last 30 days**\n"
	for card, want := range map[string]string{
		"fast":    head + "|copies|69\n|orders|31\n|days with a sale|18\n|vs. cards at $30+|faster than 92%\n|last sale|2026-10-11",
		"slowest": head + "|copies|1\n|orders|1\n|days with a sale|1\n|vs. cards under $30|among the slowest\n|last sale|2026-10-11",
		"zero":    head + "no sale in the window; last sold 2026-10-11",
	} {
		_, detail, _ := s.View(card)
		if detail != want {
			t.Errorf("%s: got %q, want %q", card, detail, want)
		}
		if s.Pace(card) != s.Cards[card].Pace {
			t.Errorf("%s: pace %v", card, s.Pace(card))
		}
	}
	s.Bands = []Band{{}}
	_, detail, _ := s.View("all")
	if !strings.Contains(detail, "|vs. all cards|among the slowest\n") {
		t.Errorf("one band: got %q", detail)
	}
	if s.Pace("missing") != PaceNone || (*Snapshot)(nil).Pace("card") != PaceNone {
		t.Error("a card with no data has a pace")
	}
}

// TestView words a loaded card and leaves a card with no data blank.
func TestView(t *testing.T) {
	v := Sales{Copies: 69, Orders: 31, Days: 18, LastSale: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	s := snapshotOf(map[string]*Sales{"card": &v})
	wantRate, wantDetail := text(v, Window)
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
