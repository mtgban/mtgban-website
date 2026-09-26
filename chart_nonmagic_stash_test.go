package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

// withGameAndFlags points the config at one game and one pair of long-form
// flags for the duration of a test.
func withGameAndFlags(t *testing.T, game string, writes, reads bool) {
	t.Helper()
	prevGame := Config.Game
	prevTS := Config.TimeseriesConfig
	t.Cleanup(func() {
		Config.Game = prevGame
		Config.TimeseriesConfig = prevTS
	})
	Config.Game = game
	Config.TimeseriesConfig.LongFormWrites = writes
	Config.TimeseriesConfig.LongFormReads = reads
}

// The two flags are Magic's cutover, deployment by deployment. A non-Magic game
// is not part of it: the wide table's mtgjson_uuid is a Postgres uuid column, so
// a game that numbers its cards has no legacy path to be cut over from, and
// leaving its writes behind a flag is what left its charts with only the
// datasets the tcgcsv ingest writes on its own (issue #280).
func TestLongFormGatesForNonMagic(t *testing.T) {
	for _, tc := range []struct {
		game                  string
		writes, reads         bool
		wantActive, wantWrite bool
	}{
		{DefaultGame, false, false, false, false},
		{DefaultGame, true, false, true, true},
		{DefaultGame, false, true, true, false},
		{DefaultGame, true, true, true, true},
		{"lorcana", false, false, true, true},
		{"lorcana", true, true, true, true},
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
