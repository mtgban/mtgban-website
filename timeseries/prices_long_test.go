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
