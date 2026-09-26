package main

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// useDatastore publishes ds for the duration of the calling test or
// benchmark, restoring whatever was live when it returns. Safe to call more
// than once per test: each call restores to what it overwrote, so nested or
// repeated swaps unwind back to the true original.
func useDatastore(tb testing.TB, ds *datastore) {
	tb.Helper()
	previous := liveDatastore.Swap(ds)
	tb.Cleanup(func() { liveDatastore.Store(previous) })
}

func TestCurrentDatastorePublishesAndRestoresAtomically(t *testing.T) {
	useDatastore(t, nil)
	got := currentDatastore()
	if got == nil {
		t.Fatal("currentDatastore() returned nil before any datastore was published")
	} else if len(got.backend.GetUUIDs()) != 0 {
		t.Fatalf("empty datastore contained %d cards", len(got.backend.GetUUIDs()))
	}

	want := newDatastore(&mtgmatcher.Backend{}, time.Now())
	useDatastore(t, want)
	got = currentDatastore()
	if got != want {
		t.Fatal("currentDatastore() did not return the atomically published datastore")
	}
}
