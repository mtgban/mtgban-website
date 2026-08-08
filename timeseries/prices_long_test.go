package timeseries

import (
	"strings"
	"testing"
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

// TestMoverQueriesShareGameScope guards the drift that let the anchors and the
// result set disagree: the anchor dates were provider-wide while the rows were
// game-scoped, so a game a day behind its provider's newest date resolved to an
// anchor holding none of its rows. Behavior lives in
// TestMoversLongGameScopingLive; this keeps the three queries textually tied
// together without needing a database.
func TestMoverQueriesShareGameScope(t *testing.T) {
	for _, q := range []struct {
		name  string
		query string
	}{
		{"latest", moverLatestQuery},
		{"prior", moverPriorQuery},
		{"rows", moverRowsQuery},
	} {
		if !strings.Contains(q.query, moverGameScope) {
			t.Errorf("%s query does not carry moverGameScope:\n%s", q.name, q.query)
		}
	}
	// The scope owns $1 and $2 in every query, so the rest start at $3.
	if strings.Contains(moverRowsQuery, "provider=$1") || strings.Contains(moverLatestQuery, "provider = $1") {
		t.Error("provider must not reuse the game-scope parameters")
	}
}
