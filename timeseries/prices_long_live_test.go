package timeseries

import (
	"context"
	"testing"
	"time"
)

// TestLongFormLive exercises the long-form (variants + prices) code end to end
// against a real Postgres: ban_id minting + caching, the long upsert, and the
// four read paths (HGetAllLong canonical resolution, GetEarliestDateLong,
// GetAggregatePriceStatsLong, GetMoversLong).
//
// Like TestTCGPricesLive it is skipped unless TCGLIVE_HOST is set, and it only
// touches sentinel identities (a fake uuid, a sentinel category, and sentinel
// provider id 999) that never collide with real data, deleting them on
// completion. Using provider 999 keeps the per-provider aggregate/mover scans
// isolated to this test's rows, so they stay fast against the full table.
const (
	liveSentinelUUID     = "ffffffff-0000-0000-0000-000000000001"
	liveSentinelUUIDAlt  = "ffffffff-0000-0000-0000-000000000002"
	liveSentinelCatLong  = 999002
	liveSentinelProdLong = 888111
	liveSentinelProvider = int16(999)
)

func TestLongFormLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	clear := func() {
		// prices first (FK -> providers, variants), then variants, then provider.
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1`, liveSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE mtgjson_uuid IN ($1,$2) OR tcgp_category_id=$3`,
			liveSentinelUUID, liveSentinelUUIDAlt, liveSentinelCatLong)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, liveSentinelProvider)
	}
	clear() // start clean (removes any leftover sentinel rows from a prior run)
	t.Cleanup(clear)

	// Sentinel provider so per-provider scans only see this test's rows. Inserted
	// AFTER the initial clear so it survives into the test body.
	if _, err := c.db.ExecContext(ctx, `
		INSERT INTO providers (id, shorthand, public_name, kind, currency)
		VALUES ($1,'SENTINEL','Sentinel','retail','USD')
		ON CONFLICT (id) DO NOTHING`, liveSentinelProvider); err != nil {
		t.Fatalf("insert sentinel provider: %v", err)
	}

	// --- mint + cache idempotence ---
	base := MagicVariant{MtgjsonUUID: liveSentinelUUID} // lang="", alt=false (canonical)
	banBase, err := c.ResolveMagicBanID(ctx, base)
	if err != nil {
		t.Fatalf("ResolveMagicBanID: %v", err)
	}
	again, err := c.ResolveMagicBanID(ctx, base)
	if err != nil || again != banBase {
		t.Fatalf("resolve not idempotent: %d vs %d err=%v", banBase, again, err)
	}
	// A fresh client (cold cache) must resolve the same row via ON CONFLICT.
	c2, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient 2: %v", err)
	}
	defer c2.Close()
	if cold, err := c2.ResolveMagicBanID(ctx, base); err != nil || cold != banBase {
		t.Fatalf("cold resolve = %d, want %d (err=%v)", cold, banBase, err)
	}

	// A non-canonical sibling (Japanese) of the same (uuid, foil, etched).
	banJa, err := c.ResolveMagicBanID(ctx, MagicVariant{MtgjsonUUID: liveSentinelUUIDAlt, Language: "Japanese"})
	if err != nil {
		t.Fatalf("ResolveMagicBanID ja: %v", err)
	}
	// Give the sibling the SAME uuid so canonical resolution has to choose. We
	// can't via ResolveMagicBanID (different uuid), so insert a same-uuid ja row.
	var banBaseJa int64
	if err := c.db.QueryRowContext(ctx, `
		INSERT INTO variants (mtgjson_uuid, language) VALUES ($1,'Japanese') RETURNING ban_id`,
		liveSentinelUUID).Scan(&banBaseJa); err != nil {
		t.Fatalf("insert same-uuid ja variant: %v", err)
	}

	// --- upsert + overwrite in place ---
	rows := []LongPrice{
		{BanID: banBase, Date: "2024-02-08", Provider: liveSentinelProvider, Price: 5.00},
		{BanID: banBase, Date: "2024-02-20", Provider: liveSentinelProvider, Price: 7.00},
		{BanID: banBaseJa, Date: "2024-02-20", Provider: liveSentinelProvider, Price: 99.00}, // canonical must ignore
	}
	if _, err := c.UpsertLongPrices(ctx, rows, 0); err != nil {
		t.Fatalf("UpsertLongPrices: %v", err)
	}
	// Overwrite the 2024-02-20 base price; count must not grow.
	rows[1].Price = 8.00
	if _, err := c.UpsertLongPrices(ctx, []LongPrice{rows[1]}, 0); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	// --- HGetAllLong: canonical (lang='') series only ---
	hist, err := c.HGetAllLong(ctx, liveSentinelUUID, false, false, Lookback(3650))
	if err != nil {
		t.Fatalf("HGetAllLong: %v", err)
	}
	if got := hist["2024-02-20"][liveSentinelProvider]; got != 8.00 {
		t.Errorf("HGetAllLong 2024-02-20 = %v, want 8.00 (overwrite + canonical, not the 99.00 ja row)", got)
	}
	if got := hist["2024-02-08"][liveSentinelProvider]; got != 5.00 {
		t.Errorf("HGetAllLong 2024-02-08 = %v, want 5.00", got)
	}

	// --- GetEarliestDateLong: MIN across all matching ban_ids ---
	earliest, err := c.GetEarliestDateLong(ctx, liveSentinelUUID, false, false, Lookback(3650))
	if err != nil {
		t.Fatalf("GetEarliestDateLong: %v", err)
	}
	if got := earliest.Format("2006-01-02"); got != "2024-02-08" {
		t.Errorf("earliest = %s, want 2024-02-08", got)
	}

	// --- GetAggregatePriceStatsLong: isolated to sentinel provider ---
	sinceAll := Lookback(3650).Since()
	stats, err := c.GetAggregatePriceStatsLong(ctx, liveSentinelProvider, sinceAll)
	if err != nil {
		t.Fatalf("GetAggregatePriceStatsLong: %v", err)
	}
	s, ok := stats[AggregatePriceKey{MtgjsonUUID: liveSentinelUUID}]
	if !ok {
		t.Fatalf("no aggregate stats for sentinel; got %d keys", len(stats))
	}
	// Grouped by (uuid, foil, etched) ACROSS language (matching the legacy
	// GetAggregatePriceStats), so the same-uuid Japanese row (99.00) is included
	// alongside the base 5.00 and 8.00: max 99, min 5, count 3.
	if s.Max != 99.00 || s.Min != 5.00 || s.Count != 3 {
		t.Errorf("stats = %+v, want max 99 min 5 count 3", s)
	}

	// --- GetMoversLong: 2024-02-08 -> 2024-02-20 for the sentinel ---
	movers, err := c.GetMoversLong(ctx, liveSentinelProvider, 7, 0, 0, CategoryMagic)
	if err != nil {
		t.Fatalf("GetMoversLong: %v", err)
	}
	var found bool
	for _, m := range movers {
		if m.MtgjsonUUID == liveSentinelUUID {
			found = true
			if m.Current != 8.00 || m.Prior != 5.00 {
				t.Errorf("mover = %+v, want current 8 prior 5", m)
			}
		}
	}
	if !found {
		t.Errorf("sentinel not in movers: %+v", movers)
	}

	// --- non-Magic ban_id minting ---
	tcgBan, err := c.ResolveTCGBanID(ctx, TCGVariant{CategoryID: liveSentinelCatLong, ProductID: liveSentinelProdLong, SubType: "Normal"})
	if err != nil {
		t.Fatalf("ResolveTCGBanID: %v", err)
	}
	if tcgBan2, err := c.ResolveTCGBanID(ctx, TCGVariant{CategoryID: liveSentinelCatLong, ProductID: liveSentinelProdLong, SubType: "Normal"}); err != nil || tcgBan2 != tcgBan {
		t.Fatalf("tcg resolve not idempotent: %d vs %d err=%v", tcgBan, tcgBan2, err)
	}
	_ = banJa
}

// Sentinels for the game-scoping test, distinct from TestLongFormLive's so the
// two never see each other's rows regardless of order.
const (
	scopeSentinelUUID     = "ffffffff-0000-0000-0000-000000000011"
	scopeSentinelCat      = 999003
	scopeSentinelProd     = 888112
	scopeSentinelProvider = int16(998)
)

// TestMoversLongGameScopingLive pins the anchor dates to the requested game.
// One provider carries every game's rows, written by producers on unrelated
// schedules, so the games routinely sit a day apart. Here Magic is a day ahead
// of the sentinel TCG category, which is exactly the state that made the
// non-Magic screener return nothing: anchoring on the provider's newest date
// picked Magic's day, on which the TCG category has no rows at all.
func TestMoversLongGameScopingLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	clear := func() {
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1`, scopeSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE mtgjson_uuid=$1 OR tcgp_category_id=$2`,
			scopeSentinelUUID, scopeSentinelCat)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, scopeSentinelProvider)
	}
	clear()
	t.Cleanup(clear)

	if _, err := c.db.ExecContext(ctx, `
		INSERT INTO providers (id, shorthand, public_name, kind, currency)
		VALUES ($1,'SENTINEL2','Sentinel Scope','retail','USD')
		ON CONFLICT (id) DO NOTHING`, scopeSentinelProvider); err != nil {
		t.Fatalf("insert sentinel provider: %v", err)
	}

	// Magic runs a day ahead of the TCG category on both anchors.
	const (
		magicCur   = "2024-06-20"
		magicPrior = "2024-06-13"
		tcgCur     = "2024-06-19"
		tcgPrior   = "2024-06-12"
	)
	for _, day := range []string{magicCur, magicPrior, tcgCur, tcgPrior} {
		d, err := time.Parse("2006-01-02", day)
		if err != nil {
			t.Fatalf("parse %s: %v", day, err)
		}
		if err := c.EnsurePricePartition(ctx, d); err != nil {
			t.Fatalf("EnsurePricePartition %s: %v", day, err)
		}
	}

	magicBan, err := c.ResolveMagicBanID(ctx, MagicVariant{MtgjsonUUID: scopeSentinelUUID})
	if err != nil {
		t.Fatalf("ResolveMagicBanID: %v", err)
	}
	tcgBan, err := c.ResolveTCGBanID(ctx, TCGVariant{
		CategoryID: scopeSentinelCat, ProductID: scopeSentinelProd, SubType: "Normal",
	})
	if err != nil {
		t.Fatalf("ResolveTCGBanID: %v", err)
	}

	rows := []LongPrice{
		{BanID: magicBan, Date: magicCur, Provider: scopeSentinelProvider, Price: 10.00},
		{BanID: magicBan, Date: magicPrior, Provider: scopeSentinelProvider, Price: 5.00},
		{BanID: tcgBan, Date: tcgCur, Provider: scopeSentinelProvider, Price: 20.00},
		{BanID: tcgBan, Date: tcgPrior, Provider: scopeSentinelProvider, Price: 8.00},
	}
	if _, err := c.UpsertLongPrices(ctx, rows, 0); err != nil {
		t.Fatalf("UpsertLongPrices: %v", err)
	}

	// The regression: the TCG category must anchor on its own 06-19/06-12, not
	// on Magic's 06-20, which holds none of its rows.
	movers, err := c.GetMoversLong(ctx, scopeSentinelProvider, 7, 0, 0, scopeSentinelCat)
	if err != nil {
		t.Fatalf("GetMoversLong(tcg): %v", err)
	}
	if len(movers) != 1 {
		t.Fatalf("tcg movers = %+v, want exactly the sentinel product", movers)
	}
	if got := movers[0]; got.TCGProductID != scopeSentinelProd || got.Current != 20.00 || got.Prior != 8.00 {
		t.Errorf("tcg mover = %+v, want product %d current 20 prior 8", got, scopeSentinelProd)
	}

	// The Magic side keeps its own anchors and never sees the TCG rows.
	movers, err = c.GetMoversLong(ctx, scopeSentinelProvider, 7, 0, 0, CategoryMagic)
	if err != nil {
		t.Fatalf("GetMoversLong(magic): %v", err)
	}
	if len(movers) != 1 {
		t.Fatalf("magic movers = %+v, want exactly the sentinel uuid", movers)
	}
	if got := movers[0]; got.MtgjsonUUID != scopeSentinelUUID || got.Current != 10.00 || got.Prior != 5.00 {
		t.Errorf("magic mover = %+v, want uuid %s current 10 prior 5", got, scopeSentinelUUID)
	}
}
