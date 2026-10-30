package timeseries

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPartitionMonthsCoversRowsAndTheNextMonth(t *testing.T) {
	rows := []LongPrice{
		{Date: "2026-11-30"}, {Date: "2026-10-01"}, {Date: "2026-11-02"},
	}
	got := partitionMonths(rows)
	want := []time.Time{
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	}
	if !slices.Equal(got, want) {
		t.Errorf("partitionMonths = %v, want %v", got, want)
	}
	if partitionMonths(nil) != nil {
		t.Error("no rows should need no partitions")
	}
	if got := partitionMonths([]LongPrice{{Date: "garbage"}, {Date: ""}}); got != nil {
		t.Errorf("unparseable dates gave %v, want none", got)
	}
}

func TestUpsertRefusesFarFutureDates(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		date string
		bad  bool
	}{
		{"2026-10-30", false},
		{"2026-11-15", false},
		{"2026-12-31", false},
		{"2027-01-01", true},
		{"2031-06-15", true},
		{"garbage", false},
	}
	for _, tc := range cases {
		got, bad := futureDated([]LongPrice{{Date: "2026-10-01"}, {Date: tc.date}}, now)
		if bad != tc.bad || (bad && got != tc.date) {
			t.Errorf("futureDated(%q) = %q, %v; want bad=%v", tc.date, got, bad, tc.bad)
		}
	}
	// The refusal comes before any database work, so a nil-db client shows it.
	c := &Client{}
	far := time.Now().UTC().AddDate(5, 0, 0).Format("2006-01-02")
	_, err := c.UpsertLongPrices(context.Background(), []LongPrice{{BanID: 1, Date: far, Provider: 1, Price: 1}}, 0)
	if err == nil || !strings.Contains(err.Error(), far) {
		t.Errorf("UpsertLongPrices err = %v, want one naming %s", err, far)
	}
}

func TestDedupeLongPrices(t *testing.T) {
	rows := []LongPrice{
		{BanID: 1, Date: "2024-02-08", Provider: ProviderTCGLow, Price: 1.00},
		{BanID: 1, Date: "2024-02-08", Provider: ProviderTCGMarket, Price: 2.00},
		{BanID: 1, Date: "2024-02-08", Provider: ProviderTCGLow, Price: 1.50}, // dup key, later wins
		{BanID: 2, Date: "2024-02-08", Provider: ProviderTCGLow, Price: 9.00},
	}
	out := dedupeLongPrices(rows)
	if len(out) != 3 {
		t.Fatalf("dedupe len = %d, want 3: %+v", len(out), out)
	}
	// The (1, 2024-02-08, TCGLow) entry keeps its first slot but the later price.
	if out[0].BanID != 1 || out[0].Provider != ProviderTCGLow || out[0].Price != 1.50 {
		t.Errorf("first row = %+v, want ban 1 TCGLow price 1.50 (last wins)", out[0])
	}
	if out[1].Provider != ProviderTCGMarket || out[2].BanID != 2 {
		t.Errorf("ordering not preserved: %+v", out)
	}
}

func TestBuildLongUpsertQuery(t *testing.T) {
	batch := []LongPrice{
		{BanID: 10, Date: "2024-02-08", Provider: ProviderCKRetail, Price: 3.00},
		{BanID: 11, Date: "2024-02-08", Provider: ProviderCKBuylist, Price: 1.00},
	}
	q, args := buildLongUpsertQuery(batch)
	if len(args) != len(batch)*longColsPerRow {
		t.Fatalf("args len = %d, want %d", len(args), len(batch)*longColsPerRow)
	}
	if !strings.Contains(q, "ON CONFLICT (ban_id, date, provider) DO UPDATE SET price = EXCLUDED.price WHERE prices.price IS DISTINCT FROM EXCLUDED.price") {
		t.Errorf("missing conflict clause: %s", q)
	}
	if !strings.Contains(q, "($1,$2,$3,$4)") || !strings.Contains(q, "($5,$6,$7,$8)") {
		t.Errorf("placeholder layout wrong: %s", q)
	}
	// args are laid out ban_id, date, provider, price per row.
	if args[0] != int64(10) || args[3] != 3.00 || args[4] != int64(11) {
		t.Errorf("args order wrong: %+v", args[:5])
	}
}

// price_dates has to file exactly the rows the rows query reads, or an anchor
// names a day the game holds nothing on. The backfill script states the same
// predicate in SQL, so hold its text to the writer's.
func TestPriceDatesBackfillMatchesWriter(t *testing.T) {
	script, err := os.ReadFile("../db_migration/price_dates/price_dates.sql")
	if err != nil {
		t.Fatal(err)
	}
	game, scope := priceDatesGame()
	for _, want := range []string{game, "(" + scope + ")"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("backfill does not file rows as the writer does, missing:\n%s", want)
		}
	}
	if !strings.Contains(recordPriceDatesQuery(), scope) {
		t.Errorf("writer does not carry its own scope:\n%s", recordPriceDatesQuery())
	}
}

// A mover row is keyed by (uuid, foil, etched), and an Alternate Fourth
// Edition copy shares its original's uuid, so the copy's move would be shown
// as the original's.
func TestMagicMoversLeaveAltCopiesOut(t *testing.T) {
	scope, _ := moverScope(CategoryMagic, 1)
	if !strings.Contains(scope, "NOT v.is_alt") {
		t.Errorf("Magic mover scope keeps the is_alt copies: %q", scope)
	}
}

// The rows query carries five parameters of its own before the scope, so a
// non-Magic category lands on $6.
func TestBuildMoverRowsQueryArgs(t *testing.T) {
	latest := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	prior := latest.AddDate(0, 0, -30)

	query, args := buildMoverRowsQuery(ProviderTCGLow, 71, latest, prior, 5, 1)
	if !strings.Contains(query, "v.tcgp_category_id = $6") {
		t.Errorf("category is not numbered after the row parameters:\n%s", query)
	}
	want := []any{ProviderTCGLow, latest, prior, 5.0, 1.0, 71}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

// And both arms have to be materialized, the same way the wide query's are.
// old is referenced once, so without the keyword PG12+ inlines it and the
// planner is back to a self-join on prices with an estimate an order of
// magnitude low.
func TestBuildMoverRowsQueryMaterializes(t *testing.T) {
	query, _ := buildMoverRowsQuery(ProviderTCGLow, CategoryMagic, time.Now(), time.Now(), 0, 0)
	if n := strings.Count(query, "AS MATERIALIZED ("); n != 2 {
		t.Errorf("query materializes %d of its two arms:\n%s", n, query)
	}
}
