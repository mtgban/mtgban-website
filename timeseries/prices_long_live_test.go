package timeseries

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// TestLongFormLive exercises the long-form (variants + prices) code end to end
// against a real Postgres: ban_id minting + caching, the long upsert, and the
// three read paths (HGetAllLong by mtgban_id, GetAggregatePriceStatsLong,
// GetMoversLong).
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
	// Inside the derived-id range, so its variants get category-block ids.
	liveSentinelCatDerived = 8190
	liveSentinelProvider   = int16(999)
)

func TestLongFormLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.EnsurePriceDatesSchema(ctx); err != nil {
		t.Fatalf("EnsurePriceDatesSchema: %v", err)
	}
	if err := c.EnsureVariantsSchema(ctx); err != nil {
		t.Fatalf("EnsureVariantsSchema: %v", err)
	}
	// As main.go does: a chart read over a column the ensure just added did not prepare in NewClient.
	err = c.PrepareStatements(ctx)
	if err != nil {
		t.Fatalf("PrepareStatements: %v", err)
	}
	var haveCol int
	var haveIdx bool
	if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='variants' AND column_name='mtgban_id'`).Scan(&haveCol); err != nil || haveCol != 1 {
		t.Fatalf("variants.mtgban_id column count = %d, err %v; want 1", haveCol, err)
	}
	if err := c.db.QueryRowContext(ctx, `SELECT to_regclass('variants_mtgban_id_uk') IS NOT NULL`).Scan(&haveIdx); err != nil || !haveIdx {
		t.Fatalf("variants_mtgban_id_uk missing: %v", err)
	}

	// Once both exist the ensure runs no DDL, checked through the lock: ADD
	// COLUMN waits behind any reader, so it would time out behind this one.
	reader, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin reader: %v", err)
	}
	if _, err := reader.ExecContext(ctx, `LOCK TABLE variants IN ACCESS SHARE MODE`); err != nil {
		t.Fatalf("lock variants: %v", err)
	}
	behind, cancel := context.WithTimeout(ctx, 2*time.Second)
	ensureErr := c.EnsureVariantsSchema(behind)
	ddlErr := c.execDDL(behind, variantsMtgbanIDSchemaSQL)
	cancel()
	_ = reader.Rollback()
	if ensureErr != nil {
		t.Fatalf("EnsureVariantsSchema behind a reader: %v; want no DDL", ensureErr)
	}
	if ddlErr == nil {
		t.Fatal("the DDL itself ran behind the reader, so the probe proves nothing")
	}

	// A client whose prepare failed gets its statements on a later call.
	unprepared := &Client{db: c.db}
	if err := unprepared.PrepareStatements(ctx); err != nil || unprepared.stmtHGetAllLong == nil || unprepared.stmtHGetAllByBanID == nil {
		t.Fatalf("PrepareStatements = %v, statements %v %v; want both", err, unprepared.stmtHGetAllLong, unprepared.stmtHGetAllByBanID)
	}
	_ = unprepared.stmtHGetAllLong.Close()
	_ = unprepared.stmtHGetAllByBanID.Close()

	// The month after next, so the write is accepted and its partition is new.
	scratch := os.Getenv("TCGLIVE_SCRATCH") == "1"
	now := time.Now().UTC()
	mon := time.Date(now.Year(), now.Month()+2, 1, 0, 0, 0, 0, time.UTC)
	monthDay, strayDay := mon.Format("2006-01")+"-15", mon.AddDate(0, 1, 0).Format("2006-01")+"-15"
	monthTable, strayTable := "prices_"+mon.Format("2006_01"), "prices_"+mon.AddDate(0, 1, 0).Format("2006_01")

	layout, err := c.priceLayout(ctx)
	if err != nil {
		t.Fatalf("priceLayout: %v", err)
	}
	catTable := fmt.Sprintf("prices_cat_%d", liveSentinelCatDerived)

	cleanup := func() {
		// prices first (FK -> providers, variants), then variants, then provider.
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1`, liveSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider BETWEEN $1 AND $2 AND ban_id IN (SELECT ban_id FROM variants WHERE tcgp_category_id=$3)`,
			ProviderTCGLow, ProviderTCGDirectLow, liveSentinelCatLong)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE category=$1`, liveSentinelCatLong)
		if scratch && layout == "date" {
			_, _ = c.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+monthTable+`, `+strayTable)
		}
		if scratch && layout == "ban_id" {
			_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE ban_id IN (SELECT ban_id FROM variants WHERE tcgp_category_id=$1)`, liveSentinelCatDerived)
			_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE tcgp_category_id=$1`, liveSentinelCatDerived)
			_, _ = c.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+catTable)
		}
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE provider=$1`, liveSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE mtgjson_uuid IN ($1,$2) OR tcgp_category_id=$3`,
			liveSentinelUUID, liveSentinelUUIDAlt, liveSentinelCatLong)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, liveSentinelProvider)
	}
	cleanup() // start clean (removes any leftover sentinel rows from a prior run)
	t.Cleanup(cleanup)

	// Sentinel provider so per-provider scans only see this test's rows. Inserted
	// AFTER the initial clear so it survives into the test body.
	if _, err := c.db.ExecContext(ctx, `
		INSERT INTO providers (id, shorthand, public_name, kind, currency)
		VALUES ($1,'SENTINEL','Sentinel','retail','USD')
		ON CONFLICT (id) DO NOTHING`, liveSentinelProvider); err != nil {
		t.Fatalf("insert sentinel provider: %v", err)
	}

	// --- mint + cache idempotence ---
	base := liveSentinelUUID
	banBase, err := c.ResolveMagicBanID(ctx, base, MagicVariant{MtgjsonUUID: base})
	if err != nil {
		t.Fatalf("ResolveMagicBanID: %v", err)
	}
	again, err := c.ResolveMagicBanID(ctx, base, MagicVariant{MtgjsonUUID: base})
	if err != nil || again != banBase {
		t.Fatalf("resolve not idempotent: %d vs %d err=%v", banBase, again, err)
	}
	// A fresh client (cold cache) must resolve the same row by its id.
	c2, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient 2: %v", err)
	}
	defer c2.Close()
	if cold, err := c2.ResolveMagicBanID(ctx, base, MagicVariant{MtgjsonUUID: base}); err != nil || cold != banBase {
		t.Fatalf("cold resolve = %d, want %d (err=%v)", cold, banBase, err)
	}

	// A Japanese printing has its own id.
	ja := liveSentinelUUIDAlt
	banJa, err := c.ResolveMagicBanID(ctx, ja, MagicVariant{MtgjsonUUID: liveSentinelUUIDAlt, Language: "Japanese"})
	if err != nil {
		t.Fatalf("ResolveMagicBanID ja: %v", err)
	}
	// An Alternate Fourth Edition copy keeps its original's uuid.
	alt := base + "_alt"
	banBaseAlt, err := c.ResolveMagicBanID(ctx, alt, MagicVariant{MtgjsonUUID: base, IsAlt: true})
	if err != nil {
		t.Fatalf("ResolveMagicBanID alt: %v", err)
	}

	// --- upsert + overwrite in place ---
	rows := []LongPrice{
		{BanID: banBase, Date: "2024-02-08", Provider: liveSentinelProvider, Price: 5.00},
		{BanID: banBase, Date: "2024-02-20", Provider: liveSentinelProvider, Price: 7.00},
		{BanID: banJa, Date: "2024-02-20", Provider: liveSentinelProvider, Price: 99.00},
		{BanID: banBaseAlt, Date: "2024-02-01", Provider: liveSentinelProvider, Price: 500.00},
	}
	if _, err := c.UpsertLongPrices(ctx, rows, 0); err != nil {
		t.Fatalf("UpsertLongPrices: %v", err)
	}
	// Overwrite the 2024-02-20 base price; count must not grow.
	rows[1].Price = 8.00
	if n, err := c.UpsertLongPrices(ctx, []LongPrice{rows[1]}, 0); err != nil || n != 1 {
		t.Fatalf("re-upsert = %d, %v; want 1 changed row", n, err)
	}
	// The same price again leaves the row alone.
	if n, err := c.UpsertLongPrices(ctx, []LongPrice{rows[1]}, 0); err != nil || n != 0 {
		t.Fatalf("unchanged re-upsert = %d, %v; want 0 rows", n, err)
	}

	// --- partition-creating cases, on the scratch database only ---
	if scratch && layout == "ban_id" {
		// The category's partition is made by the write, and no month's is.
		_, _ = c.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+catTable)
		catBan, err := c.ResolveTCGBanID(ctx, TCGVariant{CategoryID: liveSentinelCatDerived, ProductID: liveSentinelProdLong, SubType: "Normal"})
		if err != nil {
			t.Fatalf("ResolveTCGBanID: %v", err)
		}
		if _, err := c.UpsertLongPrices(ctx, []LongPrice{{BanID: catBan, Date: "2024-02-08", Provider: liveSentinelProvider, Price: 1}}, 0); err != nil {
			t.Fatalf("category upsert: %v", err)
		}
		var made bool
		var home string
		if err := c.db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, catTable).Scan(&made); err != nil || !made {
			t.Fatalf("%s exists = %v, %v; want true", catTable, made, err)
		}
		if err := c.db.QueryRowContext(ctx, `SELECT tableoid::regclass::text FROM prices WHERE ban_id=$1`, catBan).Scan(&home); err != nil || home != catTable {
			t.Fatalf("row lives in %q, %v; want %s", home, err, catTable)
		}
		if err := c.EnsurePricePartition(ctx, mon); err != nil {
			t.Fatalf("EnsurePricePartition on ban_id: %v", err)
		}
		var month bool
		if err := c.db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, monthTable).Scan(&month); err != nil || month {
			t.Fatalf("%s exists = %v, %v; want false on the ban_id layout", monthTable, month, err)
		}
		if n, err := c.StrayPriceRows(ctx); err != nil || n != 0 {
			t.Fatalf("StrayPriceRows = %d, %v; want 0", n, err)
		}
		// During the soak prices_default is prices_old's, and no partition of prices.
		var haveDefault bool
		if err := c.db.QueryRowContext(ctx, `SELECT to_regclass('public.prices_default') IS NOT NULL`).Scan(&haveDefault); err != nil {
			t.Fatalf("look for prices_default: %v", err)
		}
		if !haveDefault {
			if _, err := c.db.ExecContext(ctx, `CREATE TABLE prices_default (LIKE prices)`); err != nil {
				t.Fatalf("create a detached prices_default: %v", err)
			}
			t.Cleanup(func() { _, _ = c.db.ExecContext(ctx, `DROP TABLE IF EXISTS prices_default`) })
			if _, err := c.db.ExecContext(ctx, `INSERT INTO prices_default VALUES ($1, '2024-02-08', $2, 1)`, catBan, liveSentinelProvider); err != nil {
				t.Fatalf("fill the detached prices_default: %v", err)
			}
			if n, err := c.StrayPriceRows(ctx); err != nil || n != 0 {
				t.Fatalf("StrayPriceRows beside prices_old's default = %d, %v; want 0", n, err)
			}
		}
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE ban_id=$1`, catBan)
	} else if scratch {
		t.Log("ban_id cases skipped: prices is still partitioned by month")
		// A stray row in the month after does not stop the write.
		if _, err := c.db.ExecContext(ctx, `INSERT INTO prices (ban_id, date, provider, price) VALUES ($1, $2, $3, 1)`,
			banBase, strayDay, liveSentinelProvider); err != nil {
			t.Fatalf("insert stray row: %v", err)
		}
		var inDefault int
		if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM prices_default WHERE provider=$1`, liveSentinelProvider).Scan(&inDefault); err != nil || inDefault != 1 {
			t.Fatalf("stray rows in prices_default = %d, %v; want 1", inDefault, err)
		}
		if n, err := c.StrayPriceRows(ctx); err != nil || n < 1 {
			t.Fatalf("StrayPriceRows = %d, %v; want the stray row", n, err)
		}
		if _, err := c.UpsertLongPrices(ctx, []LongPrice{{BanID: banBase, Date: monthDay, Provider: liveSentinelProvider, Price: 1}}, 0); err != nil {
			t.Fatalf("upsert beside a stray row: %v", err)
		}
		var month, next bool
		if err := c.db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL, to_regclass($2) IS NOT NULL`, monthTable, strayTable).Scan(&month, &next); err != nil || !month || next {
			t.Fatalf("%s exists = %v, %s exists = %v, %v; want true, false", monthTable, month, strayTable, next, err)
		}
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices_default WHERE provider=$1`, liveSentinelProvider)

		// A write in the month after next creates its own partitions.
		if _, err := c.UpsertLongPrices(ctx, []LongPrice{{BanID: banBase, Date: monthDay, Provider: liveSentinelProvider, Price: 1}}, 0); err != nil {
			t.Fatalf("future upsert: %v", err)
		}
		var both bool
		if err := c.db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL AND to_regclass($2) IS NOT NULL`, monthTable, strayTable).Scan(&both); err != nil || !both {
			t.Fatalf("partitions %s and %s exist = %v, %v; want true", monthTable, strayTable, both, err)
		}
		// Later assertions read the sentinel's series, so take the probe row out.
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1 AND date=$2`, liveSentinelProvider, monthDay)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE provider=$1 AND date=$2`, liveSentinelProvider, monthDay)
	} else if !scratch {
		t.Log("partition-creating cases skipped: set TCGLIVE_SCRATCH=1 on a scratch database to run them")
	}

	// --- HGetAllLong: one printing's series by its id ---
	hist, err := c.HGetAllLong(ctx, base, Lookback(3650))
	if err != nil {
		t.Fatalf("HGetAllLong: %v", err)
	}
	if got := hist["2024-02-20"][liveSentinelProvider]; got != 8.00 {
		t.Errorf("HGetAllLong 2024-02-20 = %v, want 8.00 (the overwrite)", got)
	}
	if got := hist["2024-02-08"][liveSentinelProvider]; got != 5.00 {
		t.Errorf("HGetAllLong 2024-02-08 = %v, want 5.00", got)
	}
	if _, ok := hist["2024-02-01"]; ok {
		t.Error("HGetAllLong read the alt copy's 2024-02-01 row")
	}
	histAlt, err := c.HGetAllLong(ctx, alt, Lookback(3650))
	if err != nil {
		t.Fatalf("HGetAllLong alt: %v", err)
	}
	if len(histAlt) != 1 || histAlt["2024-02-01"][liveSentinelProvider] != 500.00 {
		t.Errorf("HGetAllLong alt = %v, want only 2024-02-01 at 500.00", histAlt)
	}

	// The read goes through the statement cache, which is what keeps its
	// hundred-partition plan from being rebuilt per call. A second read must
	// answer the same and must not add a second entry for the same text.
	histAgain, err := c.HGetAllLong(ctx, base, Lookback(3650))
	if err != nil {
		t.Fatalf("HGetAllLong (second): %v", err)
	}
	if histAgain["2024-02-08"][liveSentinelProvider] != hist["2024-02-08"][liveSentinelProvider] {
		t.Errorf("second read disagrees: %v vs %v", histAgain["2024-02-08"], hist["2024-02-08"])
	}
	if c.stmtHGetAllLong == nil {
		t.Error("NewClient did not keep the chart read prepared")
	}

	// --- GetAggregatePriceStatsLong: isolated to sentinel provider ---
	sinceAll := Lookback(3650).Since()
	cutoff := time.Date(2024, 2, 20, 0, 0, 0, 0, time.UTC)
	stats, err := c.GetAggregatePriceStatsLong(ctx, liveSentinelProvider, sinceAll, cutoff)
	if err != nil {
		t.Fatalf("GetAggregatePriceStatsLong: %v", err)
	}
	s, ok := stats[base]
	if !ok {
		t.Fatalf("no aggregate stats for sentinel; got %d keys", len(stats))
	}
	// Keyed per printing: 5.00 and 8.00, of which only 2024-02-08 is before the
	// cutoff.
	if s.Max != 8.00 || s.Min != 5.00 || s.Count != 2 || s.PriorMax != 5.00 {
		t.Errorf("stats = %+v, want max 8 min 5 count 2 prior max 5", s)
	}
	// The alt copy is its own card, so its 500.00 stays out of the above.
	sAlt, ok := stats[alt]
	if !ok {
		t.Fatalf("no aggregate stats for the sentinel's alt copy; got %d keys", len(stats))
	}
	if sAlt.Max != 500.00 || sAlt.Min != 500.00 || sAlt.Count != 1 || sAlt.PriorMax != 500.00 {
		t.Errorf("alt stats = %+v, want max 500 min 500 count 1 prior max 500", sAlt)
	}
	// So is the Japanese printing.
	if sJa, ok := stats[ja]; !ok || sJa.Max != 99.00 || sJa.Min != 99.00 || sJa.Count != 1 {
		t.Errorf("ja stats = %+v (ok=%v), want max 99 min 99 count 1", sJa, ok)
	}

	// --- adopts an alias-only row ---
	var banFoil int64
	if err := c.db.QueryRowContext(ctx, `INSERT INTO variants (mtgjson_uuid, is_foil) VALUES ($1, true) RETURNING ban_id`,
		liveSentinelUUID).Scan(&banFoil); err != nil {
		t.Fatalf("insert alias-only row: %v", err)
	}
	foil := base + "_f"
	if got, err := c.ResolveMagicBanID(ctx, foil, MagicVariant{MtgjsonUUID: base, IsFoil: true}); err != nil || got != banFoil {
		t.Fatalf("resolve over an alias-only row = %d, %v; want its ban_id %d", got, err, banFoil)
	}
	var adopted string
	if err := c.db.QueryRowContext(ctx, `SELECT mtgban_id FROM variants WHERE ban_id=$1`, banFoil).Scan(&adopted); err != nil || adopted != foil {
		t.Fatalf("alias-only row mtgban_id = %q, %v; want %q", adopted, err, foil)
	}

	// --- refuses a respelled id ---
	_, err = c.ResolveMagicBanID(ctx, base+"_x", MagicVariant{MtgjsonUUID: base, IsFoil: true})
	var respelled *ErrVariantRespelled
	if !errors.As(err, &respelled) || respelled.Stored != foil {
		t.Fatalf("respelled resolve err = %v, want an ErrVariantRespelled naming %q", err, foil)
	}
	var minted int
	if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM variants WHERE mtgban_id=$1`, base+"_x").Scan(&minted); err != nil || minted != 0 {
		t.Fatalf("rows filed under the respelled id = %d, %v; want 0", minted, err)
	}
	// A lost adoption (UPDATE hits 0 rows) is reachable only by a race; it returns the same ErrVariantRespelled.

	// --- an id already filed keeps its row and alias ---
	etched := base + "_e"
	banEtched, err := c.ResolveMagicBanID(ctx, etched, MagicVariant{MtgjsonUUID: base, IsEtched: true})
	if err != nil {
		t.Fatalf("ResolveMagicBanID etched: %v", err)
	}
	// c2's cache is cold, so the second ask reaches the table.
	if got, err := c2.ResolveMagicBanID(ctx, etched, MagicVariant{MtgjsonUUID: base, IsEtched: true, Language: "French"}); err != nil || got != banEtched {
		t.Fatalf("resolve of a filed id under another alias = %d, %v; want its row %d", got, err, banEtched)
	}
	var etchedFlag bool
	var etchedLang string
	if err := c.db.QueryRowContext(ctx, `SELECT is_etched, language FROM variants WHERE ban_id=$1`, banEtched).Scan(&etchedFlag, &etchedLang); err != nil || !etchedFlag || etchedLang != "" {
		t.Fatalf("filed row's alias = etched %v language %q, %v; want etched, English", etchedFlag, etchedLang, err)
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

	// The ingest gate counts only the providers the ingest alone writes, not
	// a stash's provider 3 or another provider's day.
	if _, err := c.UpsertLongPrices(ctx, []LongPrice{
		{BanID: tcgBan, Date: "2024-03-01", Provider: ProviderTCGDirectLow, Price: 1},
		{BanID: tcgBan, Date: "2024-03-02", Provider: ProviderTCGLow, Price: 1},
		{BanID: tcgBan, Date: "2024-03-09", Provider: liveSentinelProvider, Price: 1},
	}, 0); err != nil {
		t.Fatalf("UpsertLongPrices (gate): %v", err)
	}
	if d, ok, err := c.LatestIngestDate(ctx, liveSentinelCatLong); err != nil || !ok || d.Format("2006-01-02") != "2024-03-01" {
		t.Errorf("LatestIngestDate = %v ok=%v err=%v, want 2024-03-01", d, ok, err)
	}
	// A later ingest day without Direct Low advances it, and a stash's
	// provider 3 and 4 rows after it do not.
	if _, err := c.UpsertLongPrices(ctx, []LongPrice{
		{BanID: tcgBan, Date: "2024-03-05", Provider: ProviderTCGMid, Price: 1},
		{BanID: tcgBan, Date: "2024-03-08", Provider: ProviderTCGLow, Price: 1},
		{BanID: tcgBan, Date: "2024-03-08", Provider: ProviderTCGMarket, Price: 1},
	}, 0); err != nil {
		t.Fatalf("UpsertLongPrices (stash): %v", err)
	}
	if d, ok, err := c.LatestIngestDate(ctx, liveSentinelCatLong); err != nil || !ok || d.Format("2006-01-02") != "2024-03-05" {
		t.Errorf("LatestIngestDate after a stash = %v ok=%v err=%v, want the provider 5 day 2024-03-05", d, ok, err)
	}
	if _, ok, err := c.LatestIngestDate(ctx, 999003); err != nil || ok {
		t.Errorf("LatestIngestDate(empty) ok=%v err=%v, want false", ok, err)
	}
	// A second sub-type on the same product: the finishes a non-Magic card is
	// charted by, which the read path has to tell apart.
	foilBan, err := c.ResolveTCGBanID(ctx, TCGVariant{CategoryID: liveSentinelCatLong, ProductID: liveSentinelProdLong, SubType: "Cold Foil"})
	if err != nil {
		t.Fatalf("ResolveTCGBanID (foil): %v", err)
	}
	if foilBan == tcgBan {
		t.Fatalf("sub-types share a ban_id: %d", foilBan)
	}
	subTypes, err := c.LookupTCGSubTypeBanIDs(ctx, liveSentinelProdLong)
	if err != nil {
		t.Fatalf("LookupTCGSubTypeBanIDs: %v", err)
	}
	if subTypes["Normal"] != tcgBan || subTypes["Cold Foil"] != foilBan {
		t.Errorf("LookupTCGSubTypeBanIDs = %+v, want Normal=%d Cold Foil=%d", subTypes, tcgBan, foilBan)
	}

	// --- scoped warm: one category, on a cold client ---
	// The Magic half is deliberately not warmed here: a Magic-scoped warm pulls
	// every uuid-keyed row, which is the ~190k-row load this scoping exists to
	// keep off the non-Magic sites. What matters is that the category predicate
	// runs and excludes everything else, so the sentinel product arrives and the
	// sentinel uuid does not.
	c3, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient 3: %v", err)
	}
	defer c3.Close()
	counts, err := c3.WarmVariantCache(ctx, VariantScope{TCGCategoryIDs: []int{liveSentinelCatLong}})
	if err != nil {
		t.Fatalf("WarmVariantCache scoped: %v", err)
	}
	if counts.Magic != 0 {
		t.Errorf("category-scoped warm loaded %d magic variants, want 0", counts.Magic)
	}
	if counts.TCG != 2 {
		t.Errorf("category-scoped warm loaded %d non-magic variants, want the 2 sentinels", counts.TCG)
	}
	if got, ok := c3.CachedTCGBanID(liveSentinelProdLong); !ok || got != tcgBan {
		t.Errorf("CachedTCGBanID = %d (ok=%v), want %d after a scoped warm", got, ok, tcgBan)
	}
	// The warm pass also indexes what each ban_id is, which is what keeps a
	// chart page from asking the archive that question per card.
	if idx := c3.variants.warm.Load(); idx == nil {
		t.Error("warm pass published no ban_id index")
	} else if vi, ok := idx.byBanID[tcgBan]; !ok || vi.TCGProductID != liveSentinelProdLong {
		t.Errorf("ban_id index has %+v for %d, want the sentinel product", vi, tcgBan)
	}

	if warmed, ok := c3.CachedTCGSubTypeBanIDs(liveSentinelProdLong); !ok ||
		warmed["Normal"] != tcgBan || warmed["Cold Foil"] != foilBan {
		t.Errorf("CachedTCGSubTypeBanIDs = %+v (ok=%v), want Normal=%d Cold Foil=%d", warmed, ok, tcgBan, foilBan)
	}
	if got, ok := c3.CachedMagicBanID(base); ok {
		t.Errorf("category-scoped warm cached magic variant %d; it should not have been read", got)
	}
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

	if err := c.EnsurePriceDatesSchema(ctx); err != nil {
		t.Fatalf("EnsurePriceDatesSchema: %v", err)
	}

	cleanup := func() {
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1`, scopeSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE provider=$1`, scopeSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE mtgjson_uuid=$1 OR tcgp_category_id=$2`,
			scopeSentinelUUID, scopeSentinelCat)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, scopeSentinelProvider)
	}
	cleanup()
	t.Cleanup(cleanup)

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

	magicBan, err := c.ResolveMagicBanID(ctx, scopeSentinelUUID, MagicVariant{MtgjsonUUID: scopeSentinelUUID})
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

	// The anchors come from the days the upsert filed, each under its own game.
	rs, err := c.db.QueryContext(ctx, `
		SELECT category || ' ' || to_char(date, 'YYYY-MM-DD') FROM price_dates
		 WHERE provider=$1 ORDER BY 1`, scopeSentinelProvider)
	if err != nil {
		t.Fatalf("read price_dates: %v", err)
	}
	defer rs.Close()
	var filed []string
	for rs.Next() {
		var day string
		if err := rs.Scan(&day); err != nil {
			t.Fatalf("scan price_dates: %v", err)
		}
		filed = append(filed, day)
	}
	want := []string{
		"1 " + magicPrior, "1 " + magicCur,
		fmt.Sprintf("%d %s", scopeSentinelCat, tcgPrior), fmt.Sprintf("%d %s", scopeSentinelCat, tcgCur),
	}
	if !slices.Equal(filed, want) {
		t.Errorf("price_dates = %v, want %v", filed, want)
	}

	// A game with no rows under the provider, and a window reaching back past
	// a game's first day, come back empty instead of searching the provider's
	// whole history for a day that is not there.
	if movers, err := c.GetMoversLong(ctx, scopeSentinelProvider, 7, 0, 0, scopeSentinelCat+1); err != nil || movers != nil {
		t.Errorf("game without rows: movers = %+v, err = %v, want none", movers, err)
	}
	if movers, err := c.GetMoversLong(ctx, scopeSentinelProvider, 30, 0, 0, scopeSentinelCat); err != nil || movers != nil {
		t.Errorf("window past the first day: movers = %+v, err = %v, want none", movers, err)
	}
}

// TestExpirePriceDatesLive keeps the screener's year and a month of slack, and
// drops what is older.
func TestExpirePriceDatesLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.EnsurePriceDatesSchema(ctx); err != nil {
		t.Fatalf("EnsurePriceDatesSchema: %v", err)
	}
	cleanup := func() {
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE provider=$1`, scopeSentinelProvider)
	}
	cleanup()
	t.Cleanup(cleanup)

	now := time.Now()
	kept, expired := now.AddDate(0, -12, -20), now.AddDate(0, -13, -2)
	for _, day := range []time.Time{kept, expired} {
		if _, err := c.db.ExecContext(ctx, `INSERT INTO price_dates (provider, category, date) VALUES ($1, $2, $3)`,
			scopeSentinelProvider, scopeSentinelCat, day.Format(time.DateOnly)); err != nil {
			t.Fatalf("insert %s: %v", day.Format(time.DateOnly), err)
		}
	}
	if err := c.ExpirePriceDates(ctx); err != nil {
		t.Fatalf("ExpirePriceDates: %v", err)
	}

	rs, err := c.db.QueryContext(ctx, `SELECT to_char(date, 'YYYY-MM-DD') FROM price_dates WHERE provider=$1`, scopeSentinelProvider)
	if err != nil {
		t.Fatalf("read price_dates: %v", err)
	}
	defer rs.Close()
	var left []string
	for rs.Next() {
		var day string
		if err := rs.Scan(&day); err != nil {
			t.Fatalf("scan: %v", err)
		}
		left = append(left, day)
	}
	if want := []string{kept.Format(time.DateOnly)}; !slices.Equal(left, want) {
		t.Errorf("price_dates after expiry = %v, want %v", left, want)
	}
}

// Sentinels for the derived-id test. 8191 is the largest category TCGBanID
// accepts and no TCGplayer category comes near it; 999004 is past it, so it
// exercises the sequence fallback.
const (
	derivedSentinelCat      = tcgBanIDMaxCategory
	derivedSentinelCatOver  = 999004
	derivedSentinelProd     = 888113
	derivedSentinelProvider = int16(997)
)

// TestEnsureTCGVariantsLive files variants against the real table: a new one
// under its derived id, one filed under the sequence beforehand keeping that
// id, and one the layout cannot hold falling back to the sequence. Each id has
// to come back the same from a second call and from a cold client, and carry
// a price through the FK.
func TestEnsureTCGVariantsLive(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.EnsurePriceDatesSchema(ctx); err != nil {
		t.Fatalf("EnsurePriceDatesSchema: %v", err)
	}

	scratch := os.Getenv("TCGLIVE_SCRATCH") == "1"
	layout, err := c.priceLayout(ctx)
	if err != nil {
		t.Fatalf("priceLayout: %v", err)
	}
	catTable := fmt.Sprintf("prices_cat_%d", derivedSentinelCat)

	cleanup := func() {
		_, _ = c.db.ExecContext(ctx, `DELETE FROM prices WHERE provider=$1`, derivedSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM price_dates WHERE provider=$1`, derivedSentinelProvider)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM variants WHERE tcgp_category_id IN ($1,$2)`,
			derivedSentinelCat, derivedSentinelCatOver)
		_, _ = c.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, derivedSentinelProvider)
		// The derived-id write creates its category's partition on the ban_id layout.
		if scratch && layout == "ban_id" {
			_, _ = c.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+catTable)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := c.db.ExecContext(ctx, `
		INSERT INTO providers (id, shorthand, public_name, kind, currency)
		VALUES ($1,'SENTINEL3','Sentinel Derived','retail','USD')
		ON CONFLICT (id) DO NOTHING`, derivedSentinelProvider); err != nil {
		t.Fatalf("insert sentinel provider: %v", err)
	}

	fresh := TCGVariant{CategoryID: derivedSentinelCat, ProductID: derivedSentinelProd, SubType: "Normal"}
	legacy := TCGVariant{CategoryID: derivedSentinelCat, ProductID: derivedSentinelProd, SubType: "Cold Foil"}
	over := TCGVariant{CategoryID: derivedSentinelCatOver, ProductID: derivedSentinelProd, SubType: "Normal"}

	// A row filed under the sequence before ids were derived, as every
	// existing non-Magic variant was.
	var legacyID int64
	if err := c.db.QueryRowContext(ctx, `
		INSERT INTO variants (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
		VALUES ($1,$2,$3) RETURNING ban_id`,
		legacy.CategoryID, legacy.ProductID, legacy.SubType).Scan(&legacyID); err != nil {
		t.Fatalf("insert legacy variant: %v", err)
	}

	ids, err := c.EnsureTCGVariants(ctx, []TCGVariant{fresh, legacy, over})
	if err != nil {
		t.Fatalf("EnsureTCGVariants: %v", err)
	}
	want, _ := TCGBanID(fresh)
	if ids[fresh] != want {
		t.Errorf("fresh variant filed as %d, want its derived id %d", ids[fresh], want)
	}
	if ids[legacy] != legacyID {
		t.Errorf("legacy variant came back as %d, want its sequence id %d", ids[legacy], legacyID)
	}
	if ids[over] == 0 || ids[over] >= 1<<tcgBanIDCategoryShift {
		t.Errorf("out-of-range variant filed as %d, want a sequence id", ids[over])
	}

	// Again, from the cache and then from a client that never saw them.
	again, err := c.EnsureTCGVariants(ctx, []TCGVariant{fresh, legacy, over})
	if err != nil {
		t.Fatalf("EnsureTCGVariants again: %v", err)
	}
	c2, err := NewClient(liveConfig(t))
	if err != nil {
		t.Fatalf("NewClient (cold): %v", err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	cold, err := c2.EnsureTCGVariants(ctx, []TCGVariant{fresh, legacy, over})
	if err != nil {
		t.Fatalf("EnsureTCGVariants cold: %v", err)
	}
	for _, v := range []TCGVariant{fresh, legacy, over} {
		if again[v] != ids[v] || cold[v] != ids[v] {
			t.Errorf("%+v: first %d, again %d, cold %d", v, ids[v], again[v], cold[v])
		}
	}
	if got, err := c2.ResolveTCGBanID(ctx, fresh); err != nil || got != want {
		t.Errorf("ResolveTCGBanID(fresh) = %d, %v; want %d", got, err, want)
	}

	// The prices FK takes a row on the derived id.
	day := time.Now().UTC()
	if err := c.EnsurePricePartition(ctx, day); err != nil {
		t.Fatalf("EnsurePricePartition: %v", err)
	}
	if n, err := c.UpsertLongPrices(ctx, []LongPrice{
		{BanID: want, Date: day.Format("2006-01-02"), Provider: derivedSentinelProvider, Price: 1.23},
	}, 0); err != nil || n != 1 {
		t.Fatalf("UpsertLongPrices on the derived id = %d, %v", n, err)
	}
}
