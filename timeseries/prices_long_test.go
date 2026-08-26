package timeseries

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

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
	if !strings.Contains(q, "ON CONFLICT (ban_id, date, provider) DO UPDATE SET price = EXCLUDED.price") {
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

// normalizeParams makes two renderings of the same predicate comparable when
// they sit at different parameter positions.
var paramRE = regexp.MustCompile(`\$\d+`)

func normalizeParams(s string) string { return paramRE.ReplaceAllString(s, "$?") }

// TestMoverQueriesShareGameScope guards the drift that let the anchors and the
// result set disagree: the anchor dates were provider-wide while the rows were
// game-scoped, so a game a day behind its provider's newest date resolved to an
// anchor holding none of its rows. Behavior lives in
// TestMoversLongGameScopingLive; this keeps the three queries tied together
// without needing a database.
func TestMoverQueriesShareGameScope(t *testing.T) {
	// A category that is not Magic; the exact number does not matter here.
	const someCategory = 71
	before := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		category int
	}{
		{"magic", CategoryMagic},
		{"non-magic", someCategory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			latest, _ := buildMoverAnchorQuery(ProviderTCGLow, tc.category, nil)
			prior, _ := buildMoverAnchorQuery(ProviderTCGLow, tc.category, &before)
			rows, _ := buildMoverRowsQuery(ProviderTCGLow, tc.category, before, before, 0, 0)

			scope, _ := moverScope(tc.category, 1)
			want := normalizeParams(scope)
			for _, q := range []struct {
				name  string
				query string
			}{{"latest", latest}, {"prior", prior}, {"rows", rows}} {
				if !strings.Contains(normalizeParams(q.query), want) {
					t.Errorf("%s query does not carry the game scope %q:\n%s", q.name, want, q.query)
				}
			}
		})
	}
}

// The anchors used to aggregate: max(date) over a join has to visit every price
// row the provider holds, across every monthly partition, before it can name
// the largest - so a screener page paid two full scans before it read a single
// price. Reading the date off the first row instead lets the planner walk
// prices_provider_date backwards and stop as soon as a row belongs to this
// game.
func TestMoverAnchorStopsAtTheFirstRow(t *testing.T) {
	query, args := buildMoverAnchorQuery(ProviderTCGLow, CategoryMagic, nil)

	if strings.Contains(query, "max(") {
		t.Errorf("anchor aggregates instead of stopping at the first row:\n%s", query)
	}
	if !strings.Contains(query, "ORDER BY p.date DESC") || !strings.Contains(query, "LIMIT 1") {
		t.Errorf("anchor is not ordered and bounded:\n%s", query)
	}
	if len(args) != 1 || args[0] != ProviderTCGLow {
		t.Errorf("args = %v, want the provider alone on Magic", args)
	}

	// The bound and the category are both parameters, numbered in the order
	// they are appended, so the scope keeps $2 and the bound takes $3.
	before := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	query, args = buildMoverAnchorQuery(ProviderTCGLow, 71, &before)
	if !strings.Contains(query, "v.tcgp_category_id = $2") || !strings.Contains(query, "p.date <= $3") {
		t.Errorf("parameters are not numbered as laid out:\n%s", query)
	}
	if len(args) != 3 || args[1] != 71 || args[2] != before {
		t.Errorf("args = %v, want provider, category, bound", args)
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
