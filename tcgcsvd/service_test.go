package tcgcsvd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// stubStore satisfies Store without a database; the tests here only exercise
// construction and game selection, neither of which touches storage.
type stubStore struct{ readOnly bool }

func (s stubStore) ReadOnly() bool { return s.readOnly }
func (s stubStore) EnsureTCGSchema(context.Context) error {
	return nil
}
func (s stubStore) EnsureTCGProductsSchema(context.Context) error { return nil }
func (s stubStore) EnsureTCGCategoryPartition(context.Context, int) error {
	return nil
}
func (s stubStore) GetTCGLatestDate(context.Context, int) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (s stubStore) UpsertTCGPrices(context.Context, []timeseries.TCGPriceRow, int) (int, error) {
	return 0, nil
}
func (s stubStore) UpsertTCGProducts(context.Context, []timeseries.TCGProduct, int) (int, error) {
	return 0, nil
}
func (s stubStore) ResolveTCGBanID(context.Context, timeseries.TCGVariant) (int64, error) {
	return 0, nil
}
func (s stubStore) UpsertLongPrices(context.Context, []timeseries.LongPrice, int) (int, error) {
	return 0, nil
}
func (s stubStore) TryAdvisoryLock(context.Context, int64) (bool, func(), error) {
	return false, func() {}, nil
}

// *timeseries.Client is the real implementation; keep the interface honest.
var _ Store = (*timeseries.Client)(nil)

func testService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(tcgcsv.Config{Games: []tcgcsv.GameConfig{
		{Name: "Pokemon", CategoryID: 3},
		{Name: "Disney Lorcana", CategoryID: 71},
		{Name: "Riftbound", CategoryID: 89},
	}}, stubStore{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewRequiresGamesAndStore(t *testing.T) {
	if _, err := New(tcgcsv.Config{}, stubStore{}); err == nil {
		t.Error("want an error when no games are configured")
	}
	cfg := tcgcsv.Config{Games: []tcgcsv.GameConfig{{Name: "Disney Lorcana", CategoryID: 71}}}
	if _, err := New(cfg, nil); err == nil {
		t.Error("want an error when no store is passed")
	}
}

func TestSelectGames(t *testing.T) {
	svc := testService(t)

	t.Run("empty spec takes every configured game", func(t *testing.T) {
		games, err := svc.SelectGames("")
		if err != nil {
			t.Fatal(err)
		}
		if len(games) != 3 {
			t.Fatalf("got %d games, want all 3", len(games))
		}
	})

	t.Run("filters and dedupes", func(t *testing.T) {
		games, err := svc.SelectGames(" 71, 3 ,71")
		if err != nil {
			t.Fatal(err)
		}
		if len(games) != 2 || games[0].CategoryID != 71 || games[1].CategoryID != 3 {
			t.Fatalf("got %+v, want categories 71 then 3", games)
		}
		if games[0].Name != "Disney Lorcana" {
			t.Errorf("category 71 resolved to %q, want the configured name", games[0].Name)
		}
	})

	t.Run("unconfigured category is an error", func(t *testing.T) {
		_, err := svc.SelectGames("71,999")
		if err == nil {
			t.Fatal("want an error for a category that isn't configured")
		}
		// The message lists what is configured, so a typo is fixable from it.
		if !strings.Contains(err.Error(), "71 (Disney Lorcana)") {
			t.Errorf("error should list the configured games, got %q", err)
		}
	})

	t.Run("non-numeric category is an error", func(t *testing.T) {
		if _, err := svc.SelectGames("lorcana"); err == nil {
			t.Fatal("want an error for a non-numeric category id")
		}
	})

	t.Run("comma-only spec selects nothing", func(t *testing.T) {
		if _, err := svc.SelectGames(","); err == nil {
			t.Fatal("want an error when the spec selects no games")
		}
	})
}

// A caller mutating what Games returns must not be able to reshape the set of
// games the service ingests.
func TestGamesIsACopy(t *testing.T) {
	svc := testService(t)
	games := svc.Games()
	games[0].CategoryID = 1
	if svc.Games()[0].CategoryID != 3 {
		t.Error("mutating the returned slice changed the service's games")
	}
}

// A read-only database can't ingest, so the jobs must refuse rather than report
// a clean run that wrote nothing.
func TestJobsRefuseAReadOnlyStore(t *testing.T) {
	svc, err := New(tcgcsv.Config{Games: []tcgcsv.GameConfig{{Name: "Disney Lorcana", CategoryID: 71}}},
		stubStore{readOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.IngestLatest(context.Background()); err == nil {
		t.Error("IngestLatest should refuse a read-only store")
	}
	if err := svc.SyncProducts(context.Background()); err == nil {
		t.Error("SyncProducts should refuse a read-only store")
	}
	if err := svc.Backfill(context.Background(), BackfillOptions{}); err == nil {
		t.Error("Backfill should refuse a read-only store")
	}
}

func TestBackfillRejectsBadDates(t *testing.T) {
	svc := testService(t)
	for _, opts := range []BackfillOptions{
		{From: "2026-13-01"},
		{To: "yesterday"},
	} {
		if err := svc.Backfill(context.Background(), opts); err == nil {
			t.Errorf("want an error for %+v", opts)
		}
	}
}
