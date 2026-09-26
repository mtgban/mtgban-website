package tcgcsvd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// recordingStore keeps what was upserted and answers the freshness gate with a
// date the test chooses.
type recordingStore struct {
	stubStore
	latest time.Time

	mu   sync.Mutex
	rows []timeseries.TCGPriceRow
}

func (s *recordingStore) GetTCGLatestDate(context.Context, int) (time.Time, bool, error) {
	if s.latest.IsZero() {
		return time.Time{}, false, nil
	}
	return s.latest, true, nil
}

func (s *recordingStore) UpsertTCGPrices(_ context.Context, rows []timeseries.TCGPriceRow, _ int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, rows...)
	return len(rows), nil
}

func (s *recordingStore) stored() []timeseries.TCGPriceRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]timeseries.TCGPriceRow(nil), s.rows...)
}

// fakeTCGCSV stands in for tcgcsv.com: one game, one group, one price, and an
// /archive/ tree that answers with archiveStatus.
type fakeTCGCSV struct {
	lastUpdated   time.Time
	archiveStatus int

	mu           sync.Mutex
	archiveCalls int
}

func (f *fakeTCGCSV) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/last-updated.txt":
			fmt.Fprint(w, f.lastUpdated.UTC().Format("2006-01-02T15:04:05-0700"))
		case strings.HasPrefix(r.URL.Path, "/archive/"):
			f.mu.Lock()
			f.archiveCalls++
			f.mu.Unlock()
			w.WriteHeader(f.archiveStatus)
			fmt.Fprint(w, "the price archive has been temporarily removed")
		case r.URL.Path == "/tcgplayer/71/groups":
			fmt.Fprint(w, `{"success":true,"errors":[],"results":[{"groupId":17690,"name":"D23 Promos","categoryId":71}]}`)
		case r.URL.Path == "/tcgplayer/71/17690/prices":
			fmt.Fprint(w, `{"success":true,"errors":[],"results":[
				{"productId":454229,"lowPrice":12.5,"midPrice":13.0,"highPrice":20.0,"marketPrice":14.25,"directLowPrice":null,"subTypeName":"Holofoil"}]}`)
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeTCGCSV) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.archiveCalls
}

// fakeService wires a Service to fake and store, with the client's throttle off
// so the test isn't paced by tcgcsv etiquette.
func fakeService(t *testing.T, fake *fakeTCGCSV, store Store) (*Service, *[]string) {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	var notified []string
	cfg := tcgcsv.Config{Games: []tcgcsv.GameConfig{{Name: "Disney Lorcana", CategoryID: 71}}}
	svc, err := New(cfg, store, WithNotifier(func(_, message string) { notified = append(notified, message) }))
	if err != nil {
		t.Fatal(err)
	}
	svc.client = tcgcsv.NewClient(cfg, tcgcsv.WithBaseURL(srv.URL))
	return svc, &notified
}

// The archive is withdrawn, so a plain backfill can only store the one day
// tcgcsv still publishes: the current snapshot, read from the per-group price
// files. It must actually store it, say so, and not spend a request per day
// learning the same 403 over and over.
func TestBackfillFallsBackToTheSnapshot(t *testing.T) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	fake := &fakeTCGCSV{lastUpdated: today.Add(20 * time.Hour), archiveStatus: http.StatusForbidden}
	store := &recordingStore{}
	svc, notified := fakeService(t, fake, store)

	if err := svc.Backfill(context.Background(), BackfillOptions{}); err != nil {
		t.Fatalf("Backfill: %v", err)
	}

	rows := store.stored()
	if len(rows) != 1 {
		t.Fatalf("stored %d rows, want 1", len(rows))
	}
	if want := today.Format("2006-01-02"); rows[0].Date != want {
		t.Errorf("row date = %q, want the snapshot date %q", rows[0].Date, want)
	}
	if rows[0].CategoryID != 71 || rows[0].ProductID != 454229 || rows[0].SubTypeName != "Holofoil" {
		t.Errorf("unexpected row: %+v", rows[0])
	}
	// One refusal is enough to know the whole archive is gone.
	if n := fake.calls(); n != 1 {
		t.Errorf("asked the archive for %d day(s), want 1", n)
	}
	// A backfill that leaves most of its range permanently missing is not a
	// quiet success.
	if len(*notified) != 1 || !strings.Contains((*notified)[0], "cannot be recovered") {
		t.Errorf("notifications = %v, want one saying the range cannot be recovered", *notified)
	}
}

// Re-fetching a date already stored is the whole point of -force, and with the
// archive gone the snapshot's own date is the only one it can mean. The
// freshness gate must not turn that into a no-op.
func TestBackfillSnapshotIgnoresTheFreshnessGate(t *testing.T) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	fake := &fakeTCGCSV{lastUpdated: today.Add(20 * time.Hour), archiveStatus: http.StatusForbidden}
	store := &recordingStore{latest: today}
	svc, _ := fakeService(t, fake, store)

	if err := svc.Backfill(context.Background(), BackfillOptions{Force: true}); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if rows := store.stored(); len(rows) != 1 {
		t.Fatalf("stored %d rows, want 1 despite the category already holding %s",
			len(rows), today.Format("2006-01-02"))
	}

	// The daily job still gates: an unchanged snapshot writes nothing.
	store.rows = nil
	if err := svc.IngestLatest(context.Background()); err != nil {
		t.Fatalf("IngestLatest: %v", err)
	}
	if rows := store.stored(); len(rows) != 0 {
		t.Errorf("daily ingest stored %d rows for a date already current, want 0", len(rows))
	}
}

// A range in the past is genuinely unrecoverable now. Storing today's prices
// because someone asked for last July would be a surprise, so the run fails and
// names the range instead.
func TestBackfillPastRangeIsUnrecoverable(t *testing.T) {
	fake := &fakeTCGCSV{
		lastUpdated:   time.Now().UTC().Truncate(24 * time.Hour).Add(20 * time.Hour),
		archiveStatus: http.StatusForbidden,
	}
	store := &recordingStore{}
	svc, _ := fakeService(t, fake, store)

	err := svc.Backfill(context.Background(), BackfillOptions{From: "2026-07-08", To: "2026-07-14"})
	if err == nil {
		t.Fatal("want an error for a past range that cannot be recovered")
	}
	if !strings.Contains(err.Error(), "2026-07-08..2026-07-14") {
		t.Errorf("error should name the range asked for, got %q", err)
	}
	if rows := store.stored(); len(rows) != 0 {
		t.Errorf("stored %d rows for a range outside the snapshot, want 0", len(rows))
	}
}

// If the archive ever disappears as a 404 rather than a 403, a whole range of
// "no archive that day" means the same thing, and the day loop must report it as
// the archive being gone instead of a clean run over zero days.
func TestBackfillArchiveEntirelyMissingRange(t *testing.T) {
	fake := &fakeTCGCSV{
		lastUpdated:   time.Now().UTC().Truncate(24 * time.Hour).Add(20 * time.Hour),
		archiveStatus: http.StatusNotFound,
	}
	svc, _ := fakeService(t, fake, &recordingStore{})

	from := time.Date(2024, 2, 8, 0, 0, 0, 0, time.UTC)
	err := svc.backfillFromArchive(context.Background(), svc.Games(), from, from.AddDate(0, 0, 3), false)
	if !errors.Is(err, tcgcsv.ErrArchiveUnavailable) {
		t.Fatalf("err = %v, want ErrArchiveUnavailable", err)
	}
	if n := fake.calls(); n != 4 {
		t.Errorf("asked the archive for %d day(s), want 4", n)
	}

	// And a single unpublished day is ordinary: today's archive lands after
	// tcgcsv's evening refresh, so one 404 at the tail of a range is not a
	// withdrawn archive.
	if err := svc.backfillFromArchive(context.Background(), svc.Games(), from, from, false); err != nil {
		t.Errorf("a one-day range with no archive yet: %v", err)
	}
}
