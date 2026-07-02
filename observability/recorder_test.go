package observability

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeStore struct {
	mu           sync.Mutex
	inserted     int
	refresh      int
	refreshBlock chan struct{}
}

func (f *fakeStore) InsertBatch(ctx context.Context, evs []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inserted += len(evs)
	return nil
}
func (f *fakeStore) RefreshRollup(ctx context.Context) error {
	// Block outside the lock so count() is never deadlocked by a held refresh.
	if f.refreshBlock != nil {
		<-f.refreshBlock
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refresh++
	return nil
}
func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inserted
}

func waitFor(t *testing.T, want int, get func() int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if get() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d, got %d", want, get())
}

func TestRecordNonBlockingWhenFull(t *testing.T) {
	// Build without starting the goroutine so nothing drains the channel.
	r := newRecorder(&fakeStore{}, recorderCfg{bufferSize: 2, batchSize: 10, flushInterval: time.Hour, refreshInterval: time.Hour})
	r.ch <- Event{}
	r.ch <- Event{} // channel now full
	done := make(chan struct{})
	go func() { r.Record(Event{}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Record blocked on a full buffer")
	}
	if r.Dropped() != 1 {
		t.Fatalf("expected 1 dropped, got %d", r.Dropped())
	}
}

func TestFlushOnBatchSize(t *testing.T) {
	fs := &fakeStore{}
	r := newRecorder(fs, recorderCfg{bufferSize: 16, batchSize: 3, flushInterval: time.Hour, refreshInterval: time.Hour})
	r.start()
	defer r.Close()
	for i := 0; i < 3; i++ {
		r.Record(Event{Path: "p"})
	}
	waitFor(t, 3, fs.count)
}

func TestCloseDrainsAndFlushes(t *testing.T) {
	fs := &fakeStore{}
	r := newRecorder(fs, recorderCfg{bufferSize: 16, batchSize: 100, flushInterval: time.Hour, refreshInterval: time.Hour})
	r.start()
	r.Record(Event{Path: "a"})
	r.Record(Event{Path: "b"})
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fs.count() != 2 {
		t.Fatalf("expected 2 flushed on close, got %d", fs.count())
	}
}

func TestNilRecorderSafe(t *testing.T) {
	var r *Recorder
	r.Record(Event{}) // must not panic
	if err := r.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	if r.Dropped() != 0 {
		t.Fatal("nil Dropped must be 0")
	}
}

func TestDoubleCloseNoPanic(t *testing.T) {
	r := NewRecorder(&fakeStore{})
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRefreshDoesNotStallFlush(t *testing.T) {
	block := make(chan struct{})
	fs := &fakeStore{refreshBlock: block}
	r := newRecorder(fs, recorderCfg{bufferSize: 16, batchSize: 1, flushInterval: time.Hour, refreshInterval: 10 * time.Millisecond})
	r.start()
	defer func() {
		close(block) // unblock the held refresh so Close can drain
		r.Close()
	}()
	// Give the refresh ticker time to fire and block inside RefreshRollup.
	time.Sleep(50 * time.Millisecond)
	// Even with refresh blocked, a recorded event must still flush.
	r.Record(Event{Path: "p"})
	waitFor(t, 1, fs.count)
}
