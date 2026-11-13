package main

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// memCounterStore keeps every row the counter writes, in order.
type memCounterStore struct {
	mu      sync.Mutex
	written []observability.Row
}

func (m *memCounterStore) UpsertMinutes(_ context.Context, _ time.Time, rows []observability.Row) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written = append(m.written, rows...)
	return nil
}

// snapshot is a copy of the rows written so far.
func (m *memCounterStore) snapshot() []observability.Row {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]observability.Row(nil), m.written...)
}

// dimsHolderSet reports whether r's holder has its dimensions worked out.
func dimsHolderSet(r *http.Request) bool {
	h := holderOf(r)
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.set
}

// fakeCounter is the feature counter a test installed and what it wrote.
type fakeCounter struct {
	t       *testing.T
	counter *observability.Counter
	store   *memCounterStore // records every UpsertMinutes call's rows
	once    sync.Once
}

// withFeatureCounter installs a counter over an in-memory store and a fixed
// clock as FeatureCounter, with observabilityInstance "test", for one test.
func withFeatureCounter(t *testing.T) *fakeCounter {
	t.Helper()
	prevCounter, prevInstance := FeatureCounter, observabilityInstance
	t.Cleanup(func() {
		FeatureCounter, observabilityInstance = prevCounter, prevInstance
	})
	now := time.Date(2026, 11, 11, 12, 0, 30, 0, time.UTC)
	f := &fakeCounter{t: t, store: &memCounterStore{}}
	f.counter = observability.NewCounter(f.store, "test", func() time.Time { return now })
	FeatureCounter, observabilityInstance = f.counter, "test"
	return f
}

// rows closes the counter on its first call and returns every row written,
// the counter's own metrics.* rows included. Later calls return the same rows.
func (f *fakeCounter) rows() []observability.Row {
	f.once.Do(func() {
		if err := f.counter.Close(context.Background()); err != nil {
			f.t.Errorf("closing the feature counter: %v", err)
		}
	})
	return f.store.snapshot()
}

// find returns the rows with that name, in the order they were written.
func find(rows []observability.Row, name string) []observability.Row {
	var out []observability.Row
	for _, row := range rows {
		if row.Name == name {
			out = append(out, row)
		}
	}
	return out
}

// wantRow fails unless exactly one row has that scope, name and value, with N n.
func wantRow(t *testing.T, rows []observability.Row, scope, name, value string, n int64) {
	t.Helper()
	var match []observability.Row
	for _, row := range rows {
		if row.Scope == scope && row.Name == name && row.Value == value {
			match = append(match, row)
		}
	}
	if len(match) != 1 || match[0].N != n {
		t.Errorf("rows %q/%q/%q = %+v, want one with N %d", scope, name, value, match, n)
	}
}

// wantNoRow fails when any row has that name.
func wantNoRow(t *testing.T, rows []observability.Row, name string) {
	t.Helper()
	if got := find(rows, name); len(got) != 0 {
		t.Errorf("rows named %q = %+v, want none", name, got)
	}
}

// wantFacts fails unless got is want, in order.
func wantFacts(t *testing.T, got, want []fact) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("facts =\n%v\nwant\n%v", got, want)
	}
}
