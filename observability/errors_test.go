package observability

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestNormalizeBuild(t *testing.T) {
	sha := strings.Repeat("a1", 20)
	for in, want := range map[string]string{
		sha:                          sha,
		sha + "-1731300000000000000": sha, // dev: the commit plus the start time
	} {
		if got, ok := NormalizeBuild(in); !ok || got != want {
			t.Errorf("NormalizeBuild(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "-1731300000000000000", sha[:39], strings.ToUpper(sha), sha + "x", "https://x/" + sha, sha + "-12a", sha + "-"} {
		if _, ok := NormalizeBuild(bad); ok {
			t.Errorf("NormalizeBuild(%q) accepted", bad)
		}
	}
}

func TestScriptsAndClassesAreClones(t *testing.T) {
	s, c := Scripts(), ErrorClasses()
	s[0], c[0] = "x", "x"
	if Scripts()[0] == "x" || ErrorClasses()[0] == "x" {
		t.Error("a caller's edit reached the closed lists")
	}
}

type fakeErrorStore struct {
	mu      sync.Mutex
	calls   []errorCall
	refused int
	err     error
	panics  bool          // when set, UpsertErrors panics after recording the call
	entered chan struct{} // when set, signalled on entry
	release chan struct{} // when set, UpsertErrors waits on it
}

type errorCall struct {
	instance string
	rows     []ErrorRow
}

func (s *fakeErrorStore) UpsertErrors(ctx context.Context, instance string, rows []ErrorRow) (int, error) {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, errorCall{instance, slices.Clone(rows)})
	if s.panics {
		panic("store down")
	}
	return s.refused, s.err
}

func (s *fakeErrorStore) last(t *testing.T) errorCall {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("the store was not called")
	}
	return s.calls[len(s.calls)-1]
}

var testBuild = strings.Repeat("0f", 20)

// newTestBuffer returns a buffer over a fake store, its clock and its reject count.
func newTestBuffer(at time.Time) (*ErrorBuffer, *fakeErrorStore, *time.Time, *int) {
	store := &fakeErrorStore{}
	now := at
	rejects := 0
	b := NewErrorBuffer(store, "inst", func() time.Time { return now }, func() { rejects++ })
	return b, store, &now, &rejects
}

func TestErrorBufferAggregatesByKey(t *testing.T) {
	at := time.Date(2026, 11, 11, 15, 4, 5, 0, time.FixedZone("x", -5*3600))
	b, store, _, _ := newTestBuffer(at)
	for range 3 {
		b.Add("desktop", testBuild, "navbar.js", "TypeError", 10, 1)
	}
	b.Add("desktop", testBuild, "navbar.js", "TypeError", 11, 1)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	call := store.last(t)
	day := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	want := []ErrorRow{
		{Day: day, Device: "desktop", Build: testBuild, Script: "navbar.js", Class: "TypeError", Line: 10, N: 3},
		{Day: day, Device: "desktop", Build: testBuild, Script: "navbar.js", Class: "TypeError", Line: 11, N: 1},
	}
	if call.instance != "inst" || !slices.Equal(call.rows, want) {
		t.Errorf("got %q %+v, want inst %+v", call.instance, call.rows, want)
	}
	if len(store.calls) != 1 {
		t.Errorf("%d store calls, want 1", len(store.calls))
	}
}

func TestErrorBufferRowsAreSorted(t *testing.T) {
	b, store, _, _ := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	r := rand.New(rand.NewPCG(1, 2))
	devices, scripts, classes := []string{"desktop", "mobile"}, []string{"navbar.js", "utils.js", "inline"}, []string{"Error", "TypeError"}
	for _, i := range r.Perm(50) {
		b.Add(devices[i%2], testBuild, scripts[i%3], classes[i/25], i, 1)
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := store.last(t).rows
	if len(rows) != 50 {
		t.Fatalf("%d rows, want 50", len(rows))
	}
	if !slices.IsSortedFunc(rows, compareErrorRows) {
		t.Errorf("rows are not sorted: %+v", rows)
	}
}

func TestErrorBufferSplitsAtMidnightUTC(t *testing.T) {
	b, store, now, _ := newTestBuffer(time.Date(2026, 11, 11, 23, 59, 59, 0, time.UTC))
	b.Add("desktop", testBuild, "navbar.js", "TypeError", 10, 1)
	*now = time.Date(2026, 11, 12, 0, 0, 1, 0, time.UTC)
	b.Add("desktop", testBuild, "navbar.js", "TypeError", 10, 1)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := store.last(t).rows
	if len(rows) != 2 || rows[0].Day.Equal(rows[1].Day) {
		t.Errorf("rows %+v, want two days", rows)
	}
}

func TestErrorBufferRefusesPastItsCap(t *testing.T) {
	b, _, _, _ := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	b.maxPending = 3
	for i := range 3 {
		if !b.Add("desktop", testBuild, "navbar.js", "Error", i, 1) {
			t.Fatalf("key %d refused under the cap", i)
		}
	}
	if b.Add("desktop", testBuild, "navbar.js", "Error", 3, 1) {
		t.Error("a 4th new key was taken")
	}
	if !b.Add("desktop", testBuild, "navbar.js", "Error", 0, 1) {
		t.Error("a repeat of a held key was refused")
	}
}

func TestRefusedRowsAreReportedAsRejected(t *testing.T) {
	b, store, _, rejects := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	store.refused = 4
	for i := range 6 {
		b.Add("desktop", testBuild, "navbar.js", "Error", i, 1)
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *rejects != 4 {
		t.Errorf("%d rejects, want 4", *rejects)
	}
}

func TestFailedErrorFlushIsRetried(t *testing.T) {
	b, store, _, rejects := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	store.err = errors.New("down")
	b.Add("desktop", testBuild, "navbar.js", "Error", 1, 2)
	b.Add("mobile", testBuild, "utils.js", "TypeError", 7, 1)
	if err := b.Flush(context.Background()); !errors.Is(err, store.err) {
		t.Fatalf("Flush = %v, want the store's error", err)
	}
	first := store.last(t).rows
	if len(first) != 2 {
		t.Fatalf("the store saw %d rows, want 2", len(first))
	}
	store.err = nil
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again := store.last(t).rows; !slices.Equal(again, first) {
		t.Errorf("retried %+v, want %+v", again, first)
	}
	if *rejects != 0 {
		t.Errorf("%d rejects, want 0", *rejects)
	}
}

func TestErrorBufferCloseFlushesWithinItsDeadline(t *testing.T) {
	b, store, _, _ := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1)
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := store.last(t).rows; len(rows) != 1 {
		t.Errorf("Close wrote %+v", rows)
	}
	if b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1) {
		t.Error("Add after Close was taken")
	}

	blocked, slow, _, _ := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	slow.entered, slow.release = make(chan struct{}, 1), make(chan struct{})
	t.Cleanup(func() { close(slow.release) })
	blocked.Add("desktop", testBuild, "navbar.js", "Error", 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- blocked.Close(ctx) }()
	select {
	case <-slow.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Close never reached the store")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Close = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return when its context ended")
	}
}

func TestErrorBufferRejectsRowsWhenTheStorePanics(t *testing.T) {
	b, store, _, rejects := newTestBuffer(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	store.panics = true
	b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1)
	b.Add("mobile", testBuild, "utils.js", "TypeError", 7, 1)
	if err := b.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("Flush = %v, want a panic error", err)
	}
	if *rejects != 2 {
		t.Errorf("%d rejects, want 2", *rejects)
	}
	store.panics = false
	if err := b.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.calls) != 1 {
		t.Errorf("%d store calls, want 1: the rows were retried", len(store.calls))
	}
}

// A panic past the store, in reject, ends Close with an error, not the process.
func TestErrorBufferCloseRecoversAPanic(t *testing.T) {
	store := &fakeErrorStore{refused: 1}
	b := NewErrorBuffer(store, "inst", time.Now, func() { panic("reject down") })
	b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1)
	if err := b.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "close panic") {
		t.Errorf("Close = %v, want a panic error", err)
	}
}

func TestNilErrorBufferIsSafe(t *testing.T) {
	var b *ErrorBuffer
	if b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1) {
		t.Error("a nil buffer took a row")
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Error(err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Error(err)
	}
	b.Run(context.Background(), time.Minute)
}

func TestErrorBufferRunFlushesOnTheTicker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &fakeErrorStore{}
		b := NewErrorBuffer(store, "test", time.Now, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			b.Run(ctx, time.Minute)
			close(done)
		}()
		b.Add("desktop", testBuild, "navbar.js", "Error", 1, 1)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if rows := store.last(t).rows; len(rows) != 1 || rows[0].N != 1 {
			t.Fatalf("rows = %+v", rows)
		}
		cancel()
		<-done
	})
}

func TestErrorNamesAreRegistered(t *testing.T) {
	v := Validators{Page: func(s string) bool { return s == "search" }}
	cases := []struct {
		name, scope, value string
		wantS              string
		ok                 bool
	}{
		{"ui.js.error", "navbar.js", "TypeError", "navbar.js", true},
		{"ui.js.error", "inline", "other", "inline", true},
		{"ui.js.rejection", "other", "ScriptError", "other", true},
		{"ui.js.rejection", "fflate.min.js", "AbortError", "fflate.min.js", true},
		{"ui.js.error", "evil.js", "TypeError", "", false},             // not a file under js/
		{"ui.js.error", "navbar.js", "x is not a function", "", false}, // a message is not a class
		{"ui.js.error", "", "TypeError", "", false},
		{"ui.perf.ttfb", "search", "<200ms", "search", true},
		{"ui.perf.lcp", "search", "<2.5s", "search", true},
		{"ui.perf.dom_ready", "search", "8s+", "search", true},
		{"ui.perf.lcp", "search", "1234", "", false},                // a raw number is not a bucket
		{"ui.perf.ttfb", "/search?q=bolt", "<200ms", "other", true}, // unknown page folds
		{"ui.perf.ttfb", "", "<200ms", "", false},                   // a scoped name with no scope
	}
	for i, c := range cases {
		n, found := Lookup(c.name)
		if !found {
			t.Fatalf("%s is not registered", c.name)
		}
		s, _, ok := n.Check(c.scope, c.value, v)
		if ok != c.ok || s != c.wantS {
			t.Errorf("case %d: got (%q, %v), want (%q, %v)", i, s, ok, c.wantS, c.ok)
		}
	}
}
