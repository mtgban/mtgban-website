package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// setTestTCGListings files cards as the loaded counts, as of 2026-09-28,
// restoring whatever was loaded when the test ends.
func setTestTCGListings(t *testing.T, cards map[string]*tcgListings) {
	t.Helper()
	setTestTCGListingsOn(t, time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), cards)
}

// setTestTCGDirect files cards as counts scraped today, so Direct's stock in
// them is current.
func setTestTCGDirect(t *testing.T, cards map[string]*tcgListings) {
	t.Helper()
	setTestTCGListingsOn(t, time.Now().UTC().Truncate(24*time.Hour), cards)
}

func setTestTCGListingsOn(t *testing.T, day time.Time, cards map[string]*tcgListings) {
	t.Helper()
	prev := tcgListingsPtr.Load()
	t.Cleanup(func() { tcgListingsPtr.Store(prev) })
	tcgListingsPtr.Store(&tcgListingsSnapshot{Date: day, Cards: cards})
}

// TestBuildTCGListings groups the rows by printing, keeps the grades
// TCGplayer names, totals every printing's listings, and marks the
// printings the scrape cut short.
func TestBuildTCGListings(t *testing.T) {
	reported := func(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }
	rows := []tcgListingsRow{
		// Complete: 195 listings stored of the 195 TCGplayer counts.
		{1, "Normal", "Near Mint", 51, 60, 83, reported(195), 7},
		{1, "Normal", "Lightly Played", 77, 88, 135, reported(195), 3},
		{1, "Normal", "Moderately Played", 27, 30, 37, reported(195), 0},
		{1, "Normal", "Heavily Played", 11, 12, 19, reported(195), 0},
		{1, "Normal", "Damaged", 5, 5, 5, reported(195), 0},
		// Cut short: 88 stored of 2,357, and the foil 11 of 966.
		{2, "Normal", "Near Mint", 75, 76, 704, reported(2357), 0},
		{2, "Normal", "Lightly Played", 12, 12, 93, reported(2357), 0},
		{2, "Foil", "Near Mint", 4, 4, 6, reported(966), 0},
		{2, "Foil", "Lightly Played", 6, 7, 12, reported(966), 0},
		// A condition that is no grade still counts as stored.
		{3, "Normal", "Near Mint", 2, 2, 2, reported(3), 0},
		{3, "Normal", "Unopened", 1, 1, 1, reported(3), 0},
		// No price row to compare with.
		{4, "Foil", "Near Mint", 1, 1, 1, sql.NullInt64{}, 0},
		// None stored: the valuable foil a bulk nonfoil crowded out.
		{6, "Foil", "", 0, 0, 0, reported(46), 0},
		// Two short, listings that changed during the scrape.
		{7, "Normal", "Near Mint", 40, 40, 60, reported(42), 0},
		// No card.
		{5, "Normal", "Near Mint", 9, 9, 9, reported(9), 0},
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
		"complete":     {Sellers: [5]int32{51, 77, 27, 11, 5}, Copies: [5]int32{83, 135, 37, 19, 5}, Direct: [5]int32{7, 3}, Total: 195},
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

// TestTCGListingsFor checks what each grade's row shows, and that a
// printing the scrape cut short shows TCGplayer's own count on NM only.
func TestTCGListingsFor(t *testing.T) {
	setTestTCGListings(t, map[string]*tcgListings{
		"complete": {Sellers: [5]int32{51, 1, 0, 11, 5}, Copies: [5]int32{83, 1, 0, 19, 1204}, Total: 195},
		"single":   {Sellers: [5]int32{1}, Copies: [5]int32{1}, Total: 1},
		"bulk":     {Sellers: [5]int32{75, 12}, Copies: [5]int32{704, 93}, Capped: true, Total: 2357},
		"damaged":  {Sellers: [5]int32{0, 0, 0, 0, 3}, Copies: [5]int32{0, 0, 0, 0, 4}, Total: 3},
	})
	const head = "|# Condition | Sellers | Copies\n"
	for _, tc := range []struct {
		card        string
		grade       mtgban.Condition
		text, title string
	}{
		{"complete", "NM", "51/83", head + "| **Near Mint** | **51** | **83**\n| Lightly Played | 1 | 1\n| Heavily Played | 11 | 19\n" +
			"195 listings across conditions · Sep 28"},
		{"complete", "SP", "1/1", head + "| Near Mint | 51 | 83\n| **Lightly Played** | **1** | **1**\n| Heavily Played | 11 | 19\n" +
			"195 listings across conditions · Sep 28"},
		{"complete", "MP", "", ""},
		// Damaged is never a row, its own included.
		{"complete", "PO", "5/1204", head + "| Near Mint | 51 | 83\n| Lightly Played | 1 | 1\n| Heavily Played | 11 | 19\n" +
			"195 listings across conditions · Sep 28"},
		{"damaged", "PO", "3/4", "3 listings across conditions · Sep 28"},
		{"single", "NM", "1/1", head + "| **Near Mint** | **1** | **1**\n1 listing across conditions · Sep 28"},
		{"complete", "INDEX", "", ""},
		{"bulk", "NM", "2357*", "2357 total listings across conditions\nPer-condition counts unavailable\n(as of Sep 28)"},
		{"bulk", "SP", "", ""},
		{"missing", "NM", "", ""},
	} {
		text, title := tcgListingsFor(tc.card, tc.grade)
		if text != tc.text || title != tc.title {
			t.Errorf("%s %s: got %q, %q; want %q, %q", tc.card, tc.grade, text, title, tc.text, tc.title)
		}
	}

	tcgListingsPtr.Store(nil)
	text, _ := tcgListingsFor("complete", "NM")
	if text != "" {
		t.Errorf("nothing loaded: got %q", text)
	}
}

// TestSearchSellersCarryTCGListings checks the counts go on the TCGplayer
// store's rows and no other store's.
func TestSearchSellersCarryTCGListings(t *testing.T) {
	prevSellers := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers) })
	now := time.Now()
	inv := mtgban.InventoryRecord{"complete": {{Conditions: "NM", Price: 7.5, Quantity: 1}}}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "TCGplayer", Shorthand: tcgListingsStore, NoQuantityInventory: true, InventoryTimestamp: &now}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Other Store", Shorthand: "OS", InventoryTimestamp: &now}),
	}
	sellersPtr.Store(&sellers)
	setTestTCGListings(t, map[string]*tcgListings{
		"complete": {Sellers: [5]int32{51}, Copies: [5]int32{83}, Total: 60},
	})

	found := searchSellersNG([]string{"complete"}, SearchConfig{})
	entries := found["complete"]["NM"]
	if len(entries) != 2 {
		t.Fatalf("got %d NM entries, want 2: %+v", len(entries), entries)
	}
	for _, entry := range entries {
		want := ""
		if entry.Shorthand == tcgListingsStore {
			want = "51/83"
		}
		if entry.Listings != want {
			t.Errorf("%s: got listings %q, want %q", entry.Shorthand, entry.Listings, want)
		}
	}
}

// TestSearchShowsTCGListings renders the counts in the TCGplayer row's
// quantity cell, desktop and mobile, and leaves a store's own quantity alone.
func TestSearchShowsTCGListings(t *testing.T) {
	const cardID = "tcg-listings-card"
	const title = "|# Condition | Sellers | Copies\n| **Near Mint** | **51** | **83**\n60 listings across conditions · Sep 28"
	const plain = "Condition\nNear Mint: sellers 51, copies 83\n60 listings across conditions · Sep 28"
	pageVars := PageVars{
		SearchVars: SearchVars{
			CondKeys: []mtgban.Condition{"NM"},
			AllKeys:  []string{cardID},
			FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{cardID: {
				"NM": {
					{ScraperName: "TCGplayer", Shorthand: tcgListingsStore, Price: 7.5, NoQuantity: true, URL: "https://example.test",
						Listings: "51/83", ListingsTitle: title},
					{ScraperName: "Other Store", Shorthand: "OS", Price: 8, Quantity: 3, URL: "https://example.test"},
				},
			}},
			FoundVendors: map[string]map[mtgban.Condition][]SearchEntry{},
		},
		Metadata: map[string]GenericCard{cardID: {Name: "Some Card", Edition: "Some Set"}},
	}
	// Desktop hovers the table; mobile, which cannot, keeps the sentences.
	for name, tc := range map[string]struct{ page, want string }{
		"desktop": {renderDesktopSearch(t, pageVars), `<span class="tcg-listings" title="` + plain + `" data-tip="` + title + `">51/83</span>`},
		"mobile":  {renderMobileSearch(t, pageVars), `<span class="tcg-listings" title="` + plain + `">51/83</span>`},
	} {
		page := tc.page
		if strings.Count(page, tc.want) != 1 {
			t.Errorf("%s: want the counts once in the TCGplayer row, rendered:\n%s", name, page)
		}
		if strings.Count(page, `class="tcg-listings"`) != 1 {
			t.Errorf("%s: counts on more than the TCGplayer row", name)
		}
	}
}

// TestPlural spells the counts' nouns, singular for one.
func TestPlural(t *testing.T) {
	for _, tc := range []struct {
		n    int
		noun string
		want string
	}{
		{1, "seller", "1 seller"},
		{0, "seller", "0 sellers"},
		{1, "copy", "1 copy"},
		{14, "copy", "14 copies"},
		{1204, "copy", "1204 copies"},
		{2374, "total listing", "2374 total listings"},
		{1, "total listing", "1 total listing"},
	} {
		got := plural(tc.n, tc.noun)
		if got != tc.want {
			t.Errorf("plural(%d, %q): got %q, want %q", tc.n, tc.noun, got, tc.want)
		}
	}
}

// TestTCGListingsDue loads a scrape day once, and retries a day whose load
// failed only after tcgListingsRetryAfter, so the 40-90s query runs once a
// day rather than on every datastore reload or every hour after a failure.
func TestTCGListingsDue(t *testing.T) {
	day := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	prev := day.AddDate(0, 0, -1)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	loaded := func(d time.Time) *tcgListingsSnapshot { return &tcgListingsSnapshot{Date: d} }
	failed := func(d time.Time, ago time.Duration) *tcgListingsFailure {
		return &tcgListingsFailure{Day: d, At: now.Add(-ago)}
	}
	for _, tc := range []struct {
		desc    string
		current *tcgListingsSnapshot
		failed  *tcgListingsFailure
		want    bool
	}{
		{"nothing loaded yet", nil, nil, true},
		{"the day is loaded", loaded(day), nil, false},
		{"a newer scrape finished", loaded(prev), nil, true},
		{"the day failed an hour ago", loaded(prev), failed(day, time.Hour), false},
		{"the day failed long enough ago", loaded(prev), failed(day, tcgListingsRetryAfter), true},
		{"an older day failed", loaded(prev), failed(prev, time.Hour), true},
		{"the first load failed an hour ago", nil, failed(day, time.Hour), false},
	} {
		got := tcgListingsDue(tc.current, tc.failed, day, now)
		if got != tc.want {
			t.Errorf("%s: due = %v, want %v", tc.desc, got, tc.want)
		}
	}
}

// refusingConnector is a database that counts the connections asked of it
// and refuses each one.
type refusingConnector struct{ dials atomic.Int32 }

func (c *refusingConnector) Connect(context.Context) (driver.Conn, error) {
	c.dials.Add(1)
	return nil, errors.New("no database here")
}

func (c *refusingConnector) Driver() driver.Driver { return nil }

// TestLoadTCGListingsWaitsForADatastore keeps the hourly run from querying
// before a datastore is loaded: it would match nothing, and hold off the
// run the datastore's own load starts.
func TestLoadTCGListingsWaitsForADatastore(t *testing.T) {
	prevDB, prevGame, prevSkip := NewNewspaperDB, Config().Game, SkipNewspaper
	t.Cleanup(func() { NewNewspaperDB, Config().Game, SkipNewspaper = prevDB, prevGame, prevSkip })
	conn := &refusingConnector{}
	NewNewspaperDB, Config().Game, SkipNewspaper = sql.OpenDB(conn), DefaultGame, false

	s := newSite()
	s.loadTCGListings()
	if n := conn.dials.Load(); n != 0 {
		t.Errorf("queried the newspaper %d times with no datastore loaded", n)
	}

	s.ds.Store(&datastore{backend: &mtgmatcher.Backend{AllUUIDs: []string{"a-card"}}})
	s.loadTCGListings()
	if conn.dials.Load() == 0 {
		t.Error("did not query the newspaper once a datastore was loaded")
	}
}

// TestWithDirectStock gives arbitrage TCGplayer Direct's entries with
// Direct's stock as their quantity where the listings saw some, and leaves
// the store's own entries, which search reads, and other sellers alone.
func TestWithDirectStock(t *testing.T) {
	setTestTCGDirect(t, map[string]*tcgListings{"card": {Direct: [5]int32{7, 0, 2}}})
	inv := mtgban.InventoryRecord{
		"card": {
			{Conditions: "NM", Price: 3, Quantity: 1},
			{Conditions: "SP", Price: 2, Quantity: 1},
			{Conditions: "MP", Price: 1, Quantity: 1},
		},
		"other": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}
	direct := mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: tcgDirectStore, NoQuantityInventory: true})

	stocked := withDirectStock(direct)
	got := stocked.Inventory()
	for _, tc := range []struct {
		cardID    string
		i, want   int
		condition string
	}{
		{"card", 0, 7, "NM"},
		{"card", 1, 1, "SP, which Direct has none of"},
		{"card", 2, 2, "MP"},
		{"other", 0, 1, "NM of a card the listings did not see"},
	} {
		if q := got[tc.cardID][tc.i].Quantity; q != tc.want {
			t.Errorf("%s %s: quantity %d, want %d", tc.cardID, tc.condition, q, tc.want)
		}
	}
	if !stocked.Info().NoQuantityInventory || stocked.Info().Shorthand != tcgDirectStore {
		t.Errorf("stocked info: got %+v, want Direct's own", stocked.Info())
	}
	if q := direct.Inventory()["card"][0].Quantity; q != 1 {
		t.Errorf("the store's own NM entry: quantity %d, want 1 untouched", q)
	}

	scg := mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: "SCG"})
	if withDirectStock(scg) != scg {
		t.Error("wrapped a seller other than Direct")
	}
}

// TestBanPricesTakeTCGDirectStock gives the price API TCGplayer Direct's own
// stock as its quantity where the listings saw some, and none where they did
// not, as for any store without quantities.
func TestBanPricesTakeTCGDirectStock(t *testing.T) {
	regular, foil, _ := parityCards(t)
	setTestTCGDirect(t, map[string]*tcgListings{regular: {Direct: [5]int32{7, 2}}})

	found := map[string]map[mtgban.Condition][]SearchEntry{
		regular: {
			"NM": {{Shorthand: tcgDirectStore, Price: 3, Quantity: 1, NoQuantity: true}},
			"SP": {{Shorthand: tcgDirectStore, Price: 2, Quantity: 1, NoQuantity: true}},
		},
		foil: {"NM": {{Shorthand: tcgDirectStore, Price: 9, Quantity: 1, NoQuantity: true}}},
	}
	out := banPricesFromRows(backend(), []string{regular, foil}, found, "", "", true, false, false)

	for _, tc := range []struct {
		cardID string
		want   int
	}{
		{regular, 9},
		{foil, 0},
	} {
		co, err := backend().GetUUID(tc.cardID)
		if err != nil {
			t.Fatal(err)
		}
		price := out[getIDFromMode(backend(), "", co)][tcgDirectStore]
		if price == nil {
			t.Fatalf("%s: no Direct price", tc.cardID)
		}
		if got := price.Qty + price.QtyFoil; got != tc.want {
			t.Errorf("%s: quantity %d, want %d", tc.cardID, got, tc.want)
		}
	}
}

// TestRankDirectAsOneCopy ranks a trade bought from Direct by its unit
// profitability, whatever stock caps it, and drops one that was profitable
// enough only on its stock.
func TestRankDirectAsOneCopy(t *testing.T) {
	arbit := []mtgban.ArbitEntry{
		{CardID: "stocked", Quantity: 4, Profitability: 6},
		{CardID: "single", Quantity: 1, Profitability: 3},
		{CardID: "thin", Quantity: 4, Profitability: 4},
	}
	got := rankDirectAsOneCopy(arbit, 2.5)
	if len(got) != 2 || got[0].CardID != "stocked" || got[1].CardID != "single" {
		t.Fatalf("kept %+v, want stocked and single", got)
	}
	if got[0].Profitability != 3 || got[0].Quantity != 4 {
		t.Errorf("stocked: profitability %v quantity %d, want 3 and the trade's 4", got[0].Profitability, got[0].Quantity)
	}
	if got[1].Profitability != 3 {
		t.Errorf("single: profitability %v, want 3 untouched", got[1].Profitability)
	}
}

// TestFullDumpTakesTCGDirectStock quotes Direct's stock in a full dump as
// the filtered requests do.
func TestFullDumpTakesTCGDirectStock(t *testing.T) {
	regular, foil, _ := parityCards(t)
	setTestTCGDirect(t, map[string]*tcgListings{regular: {Direct: [5]int32{7, 2}}})
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })
	inv := mtgban.InventoryRecord{
		regular: {{Conditions: "NM", Price: 3, Quantity: 1}, {Conditions: "SP", Price: 2, Quantity: 1}},
		foil:    {{Conditions: "NM", Price: 9, Quantity: 1}},
	}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Shorthand: tcgDirectStore, NoQuantityInventory: true})}
	sellersPtr.Store(&sellers)

	out := getSellerPrices(backend(), "", []string{tcgDirectStore}, "", nil, "", true, false, false, "")
	for _, tc := range []struct {
		cardID string
		want   int
	}{
		{regular, 9},
		{foil, 0},
	} {
		co, err := backend().GetUUID(tc.cardID)
		if err != nil {
			t.Fatal(err)
		}
		price := out[getIDFromMode(backend(), "", co)][tcgDirectStore]
		if price == nil {
			t.Fatalf("%s: no Direct price", tc.cardID)
		}
		if got := price.Qty + price.QtyFoil; got != tc.want {
			t.Errorf("%s: quantity %d, want %d", tc.cardID, got, tc.want)
		}
	}
}

// TestTCGDirectStockOnTheArbitPages shows reverse's TCGplayer Direct table
// its quantity column once Direct's stock is loaded, keeps it off Global
// and off other stores without quantities, and dates the stock's tooltip.
func TestTCGDirectStockOnTheArbitPages(t *testing.T) {
	info := mtgban.ScraperInfo{Shorthand: tcgDirectStore, NoQuantityInventory: true}
	direct := withDirectStock(mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, info))
	other := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCGLow", NoQuantityInventory: true})

	setTestTCGDirect(t, nil)
	tcgListingsPtr.Store(nil)
	if !hasNoQty(direct, true) || tcgDirectStockNote() != "" {
		t.Error("before the listings load: Direct has a quantity column or a note")
	}

	setTestTCGDirect(t, map[string]*tcgListings{})
	for _, tc := range []struct {
		name    string
		scraper mtgban.Scraper
		reverse bool
		want    bool
	}{
		{"Direct on reverse", direct, true, false},
		{"Direct on Global", direct, false, true},
		{"another store without quantities", other, true, true},
	} {
		if got := hasNoQty(tc.scraper, tc.reverse); got != tc.want {
			t.Errorf("%s: hasNoQty %v, want %v", tc.name, got, tc.want)
		}
	}
	want := "Direct stock as of " + time.Now().UTC().Format("Jan 2")
	if note := tcgDirectStockNote(); note != want {
		t.Errorf("note: got %q, want %q", note, want)
	}
}

// TestTCGDirectStockLastsADay keeps Direct's stock through the day after its
// scrape and drops it after, as if never loaded.
func TestTCGDirectStockLastsADay(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		day     time.Time
		current bool
	}{
		{time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		setTestTCGListingsOn(t, tc.day, map[string]*tcgListings{"card": {Direct: [5]int32{7}}})
		if got := tcgDirectSnapshot(now) != nil; got != tc.current {
			t.Errorf("scraped %s: current %v, want %v", tc.day.Format(time.DateOnly), got, tc.current)
		}
	}

	setTestTCGListingsOn(t, time.Now().UTC().AddDate(0, 0, -2), map[string]*tcgListings{"card": {Direct: [5]int32{7}}})
	_, found := tcgDirectStock("card", "NM")
	direct := withDirectStock(mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: tcgDirectStore, NoQuantityInventory: true}))
	if found || tcgDirectStockNote() != "" || !hasNoQty(direct, true) {
		t.Error("stock scraped two days ago is still quoted, dated or given a column")
	}
}
