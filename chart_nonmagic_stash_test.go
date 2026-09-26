package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// withGameAndFlags points the config at one game and one pair of long-form
// flags for the duration of a test.
func withGameAndFlags(t *testing.T, game mtgmatcher.Game, writes, reads bool) {
	t.Helper()
	prevGame := Config().Game
	prevTS := Config().TimeseriesConfig
	t.Cleanup(func() {
		Config().Game = prevGame
		Config().TimeseriesConfig = prevTS
	})
	Config().Game = game
	Config().TimeseriesConfig.LongFormWrites = writes
	Config().TimeseriesConfig.LongFormReads = reads
}

// The two flags are Magic's cutover, deployment by deployment. A non-Magic game
// is not part of it: the wide table's mtgjson_uuid is a Postgres uuid column, so
// a game that numbers its cards has no legacy path to be cut over from, and
// leaving its writes behind a flag is what left its charts with only the
// datasets the tcgcsv ingest writes on its own (issue #280).
func TestLongFormGatesForNonMagic(t *testing.T) {
	for _, tc := range []struct {
		game                  mtgmatcher.Game
		writes, reads         bool
		wantActive, wantWrite bool
	}{
		{DefaultGame, false, false, false, false},
		{DefaultGame, true, false, true, true},
		{DefaultGame, false, true, true, false},
		{DefaultGame, true, true, true, true},
		{mtgmatcher.GameLorcana, false, false, true, true},
		{mtgmatcher.GameLorcana, true, true, true, true},
		{"pokemon", false, true, true, true},
	} {
		withGameAndFlags(t, tc.game, tc.writes, tc.reads)
		if got := longFormActive(); got != tc.wantActive {
			t.Errorf("longFormActive(game=%s writes=%v reads=%v) = %v, want %v",
				tc.game, tc.writes, tc.reads, got, tc.wantActive)
		}
		if got := longFormWrites(); got != tc.wantWrite {
			t.Errorf("longFormWrites(game=%s writes=%v reads=%v) = %v, want %v",
				tc.game, tc.writes, tc.reads, got, tc.wantWrite)
		}
	}
}

// A dataset with a provider id and a card with a variant produce one row per
// visit, carrying the config's provider rather than its legacy column index.
func TestNonMagicSnapshotAddStoresOneRowPerProvider(t *testing.T) {
	var s nonMagicSnapshot
	mkm := DatasetConfig{PublicName: "Cardmarket Low", Index: 4, Provider: timeseries.ProviderMKMLow}
	csi := DatasetConfig{PublicName: "Cool Stuff Inc Buylist", Index: 9, Provider: timeseries.ProviderCSIBuylist}

	s.add(4242, mkm, "2026-09-24", 1.5)
	s.add(4242, csi, "2026-09-24", 0.75)

	want := []timeseries.LongPrice{
		{BanID: 4242, Date: "2026-09-24", Provider: timeseries.ProviderMKMLow, Price: 1.5},
		{BanID: 4242, Date: "2026-09-24", Provider: timeseries.ProviderCSIBuylist, Price: 0.75},
	}
	if !slices.Equal(s.Rows, want) {
		t.Errorf("rows = %+v, want %+v", s.Rows, want)
	}
	if s.NoProvider != 0 || s.NoVariant != 0 {
		t.Errorf("nothing should have been skipped: %+v", s)
	}
}

// A dataset the config never gave a provider id cannot be stored, and neither
// can a card whose product the tcgcsv ingest has not minted a variant for. The
// two are counted apart because they need different fixes.
func TestNonMagicSnapshotAddCountsSkipsSeparately(t *testing.T) {
	var s nonMagicSnapshot
	noProvider := DatasetConfig{PublicName: "Star City Games Buylist", Index: 6}
	scg := DatasetConfig{PublicName: "Star City Games Buylist", Index: 6, Provider: timeseries.ProviderSCGBuylist}

	s.add(4242, noProvider, "2026-09-24", 3)
	s.add(0, scg, "2026-09-24", 3)
	s.add(4242, scg, "2026-09-24", 3)

	if len(s.Rows) != 1 {
		t.Errorf("only the fully-resolved price should store: %+v", s.Rows)
	}
	if s.NoProvider != 1 {
		t.Errorf("NoProvider = %d, want 1", s.NoProvider)
	}
	if s.NoVariant != 1 {
		t.Errorf("NoVariant = %d, want 1", s.NoVariant)
	}

	report := s.skipped()
	if !strings.Contains(report, "1 skipped with no variant") ||
		!strings.Contains(report, "1 skipped with no provider id") {
		t.Errorf("skipped() = %q, want both counts named", report)
	}
}

// A clean snapshot says nothing about skips, so the completion notice reads as
// one sentence rather than trailing empty clauses.
func TestNonMagicSnapshotSkippedSilentWhenClean(t *testing.T) {
	var s nonMagicSnapshot
	s.add(1, DatasetConfig{Provider: timeseries.ProviderTCGLow}, "2026-09-24", 1)
	if got := s.skipped(); got != "" {
		t.Errorf("skipped() = %q, want empty", got)
	}
}

// Two scrapers can feed one dataset. The wide path resolved that by overwriting
// a column on the accumulated row; here both rows are emitted and the upsert's
// dedupe keeps the last, so the last writer has to be last in the slice.
func TestNonMagicSnapshotKeepsLastWriteLast(t *testing.T) {
	var s nonMagicSnapshot
	low := DatasetConfig{PublicName: "TCGplayer Low", Index: 2, Provider: timeseries.ProviderTCGLow}
	s.add(7, low, "2026-09-24", 1)
	s.add(7, low, "2026-09-24", 2)

	if len(s.Rows) != 2 || s.Rows[len(s.Rows)-1].Price != 2 {
		t.Errorf("rows = %+v, want the later price last", s.Rows)
	}
}

// withTCGCSVGames points the config's ingestion registry at the given category
// ids and loads a catalog for one of them, which is how the site learns which
// slice of the shared archive is its own.
func withTCGCSVGames(t *testing.T, ownCategory int, ingested []int) {
	t.Helper()
	prevConfig := Config().TCGCSVConfig
	prevCatalog := tcgCatalogPtr.Load()
	t.Cleanup(func() {
		Config().TCGCSVConfig = prevConfig
		tcgCatalogPtr.Store(prevCatalog)
	})

	if ingested == nil {
		Config().TCGCSVConfig = nil
	} else {
		cfg := &tcgcsv.Config{}
		for _, id := range ingested {
			cfg.Games = append(cfg.Games, tcgcsv.GameConfig{CategoryID: id})
		}
		Config().TCGCSVConfig = cfg
	}
	if ownCategory == 0 {
		tcgCatalogPtr.Store(nil)
	} else {
		tcgCatalogPtr.Store(&tcgCatalogSnapshot{CategoryID: ownCategory})
	}
}

// The ingest owns the TCGplayer series where the config lists this game. With no
// tcgcsv_config at all the snapshot keeps writing them, because otherwise nobody
// would; with a config but no catalog yet - the boot window, scrapers published
// and the category not named - it defers to the ingest rather than overwrite a
// whole-category pass with the subset this process loaded.
func TestTCGCSVOwnsTCGSeries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ownCategory int
		ingested    []int
		want        bool
	}{
		{"own game is ingested", 71, []int{1, 71, 85}, true},
		{"another game is ingested", 71, []int{1, 85}, false},
		{"no tcgcsv_config at all", 71, nil, false},
		{"config but no catalog yet", 0, []int{71}, true},
		{"no tcgcsv_config and no catalog", 0, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTCGCSVGames(t, tc.ownCategory, tc.ingested)
			if got := tcgcsvOwnsTCGSeries(); got != tc.want {
				t.Errorf("tcgcsvOwnsTCGSeries() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Both writers key on (ban_id, date, provider) against a DO UPDATE upsert, so
// before this the TCGplayer series a chart drew was whichever job ran second.
// The ingest covers the whole category, so it keeps them and the snapshot counts
// what it handed over rather than reporting it as a fault.
func TestNonMagicSnapshotLeavesTCGSeriesToTheIngest(t *testing.T) {
	s := nonMagicSnapshot{tcgcsvOwns: tcgcsvOwnedProviders}
	low := DatasetConfig{PublicName: "TCGplayer Low", Provider: timeseries.ProviderTCGLow}
	mid := DatasetConfig{PublicName: "TCGplayer Mid", Provider: timeseries.ProviderTCGMid}
	mkm := DatasetConfig{PublicName: "Cardmarket Low", Provider: timeseries.ProviderMKMLow}

	s.add(4242, low, "2026-09-26", 10)
	s.add(4242, mid, "2026-09-26", 11)
	s.add(4242, mkm, "2026-09-26", 9)

	want := []timeseries.LongPrice{
		{BanID: 4242, Date: "2026-09-26", Provider: timeseries.ProviderMKMLow, Price: 9},
	}
	if !slices.Equal(s.Rows, want) {
		t.Errorf("rows = %+v, want only the Cardmarket price %+v", s.Rows, want)
	}
	if s.TCGCSVOwned != 2 {
		t.Errorf("TCGCSVOwned = %d, want 2", s.TCGCSVOwned)
	}
	if s.NoVariant != 0 || s.NoProvider != 0 {
		t.Errorf("a declined provider is not a fault: %+v", s)
	}
	if got := s.skipped(); !strings.Contains(got, "2 left to the tcgcsv ingest") {
		t.Errorf("skipped() = %q, want the handover named", got)
	}
}

// A card with no variant row is a missing variant even on a provider the ingest
// owns, and counting it as one would send an operator after a catalog gap for a
// series the snapshot was never going to write. The ownership check comes first.
func TestNonMagicSnapshotDeclinesBeforeResolvingAVariant(t *testing.T) {
	s := nonMagicSnapshot{tcgcsvOwns: tcgcsvOwnedProviders}
	s.add(0, DatasetConfig{PublicName: "TCGplayer Low", Provider: timeseries.ProviderTCGLow}, "2026-09-26", 10)

	if s.NoVariant != 0 {
		t.Errorf("NoVariant = %d, want 0: the price was declined, not unresolvable", s.NoVariant)
	}
	if s.TCGCSVOwned != 1 {
		t.Errorf("TCGCSVOwned = %d, want 1", s.TCGCSVOwned)
	}
}

// serveSellerN publishes one seller holding several cards, each at one NM price.
func serveSellerN(shorthand string, prices map[string]float64, ts time.Time) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for cardID, price := range prices {
		inv[cardID] = []mtgban.InventoryEntry{{Price: price, Conditions: "NM"}}
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, InventoryTimestamp: &ts,
	})
}

// The whole snapshot short of the upsert: served scrapers in, long price rows
// out. The ban_id resolver stands in for the warmed variant cache, which is the
// one piece that needs a database, so the accumulator's three outcomes are
// exercised against a real walk rather than against hand-built calls.
func TestCollectNonMagicSnapshotFromServedScrapers(t *testing.T) {
	ids := nRealUUIDs(t, 2)
	known, unknown := ids[0], ids[1]

	keepScrapers(t)
	withTCGCSVGames(t, 71, []int{71})
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZMKM"}, PublicName: "Cardmarket Low", Provider: timeseries.ProviderMKMLow},
		{Buylist: []string{"ZZSCG"}, PublicName: "Star City Games Buylist", Provider: timeseries.ProviderSCGBuylist},
		{Retail: []string{"ZZTCG"}, PublicName: "TCGplayer Low", Provider: timeseries.ProviderTCGLow},
		{Retail: []string{"ZZCK"}, PublicName: "Card Kingdom Retail"},
	})

	now := time.Now()
	serve(
		[]mtgban.Seller{
			serveSellerN("ZZMKM", map[string]float64{known: 2, unknown: 5}, now),
			serveSellerN("ZZTCG", map[string]float64{known: 9}, now),
			serveSellerN("ZZCK", map[string]float64{known: 7}, now),
		},
		[]mtgban.Vendor{serveVendor("ZZSCG", known, mtgban.BuylistEntry{BuyPrice: 1, Conditions: "NM"}, now)},
	)

	// The cache holds a variant for one of the two cards, as it does for a
	// product the tcgcsv catalog has reached and not for one it has not.
	snapshot := collectNonMagicSnapshot(backend(), now, func(card *mtgmatcher.CardObject) int64 {
		if card.UUID == known {
			return 555
		}
		return 0
	})

	date := now.Format("2006-01-02")
	want := []timeseries.LongPrice{
		{BanID: 555, Date: date, Provider: timeseries.ProviderMKMLow, Price: 2},
		{BanID: 555, Date: date, Provider: timeseries.ProviderSCGBuylist, Price: 1},
	}
	// Retail is walked before buylist, so the two rows land in this order.
	if !slices.Equal(snapshot.Rows, want) {
		t.Errorf("rows = %+v, want %+v", snapshot.Rows, want)
	}
	if snapshot.NoVariant != 1 {
		t.Errorf("NoVariant = %d, want 1 for the Cardmarket price on the unminted card", snapshot.NoVariant)
	}
	if snapshot.TCGCSVOwned != 1 {
		t.Errorf("TCGCSVOwned = %d, want 1 for the TCGplayer price the ingest writes", snapshot.TCGCSVOwned)
	}
	if snapshot.NoProvider != 1 {
		t.Errorf("NoProvider = %d, want 1 for the dataset with no provider id", snapshot.NoProvider)
	}
}
