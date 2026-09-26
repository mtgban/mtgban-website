package main

import (
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/palette"
)

// datastore is one loaded card datastore and the snapshots the site derives
// from it, built together and published together. Immutable once published.
//
// Only backend and editions are non-nil in emptyDatastore, the value served
// before the first load completes: numbers (exact-number searches scan
// instead), names (SuggestAPI answers 204) and palette (lists served
// no-store) all wait for an actual load.
type datastore struct {
	backend  *mtgmatcher.Backend
	numbers  *numbersSnapshot
	names    *namesSnapshot
	editions *editionsSnapshot
	palette  *palette.Snapshot
	loadedAt time.Time
}

// newDatastore builds every derived snapshot from b; an empty backend gives
// empty snapshots.
func newDatastore(b *mtgmatcher.Backend, loadedAt time.Time) *datastore {
	return &datastore{
		backend:  b,
		numbers:  newNumbersSnapshot(b),
		names:    newNamesSnapshot(b.Names(mtgmatcher.NameFormCanonical, false), b.Names(mtgmatcher.NameFormCanonical, true)),
		editions: newEditionsSnapshot(b),
		palette:  paletteService.NewSnapshot(b),
		loadedAt: loadedAt,
	}
}

// liveDatastore holds the one datastore the site currently serves. Only
// loadDatastore stores into it; everything else reads it through
// currentDatastore.
var liveDatastore atomic.Pointer[datastore]

// emptyDatastore is served before the first load: nil numbers, names and
// palette make those answers scan, 204 and no-store. newDatastore would
// fill them, but cycles back here through paletteService's Backend hook.
var emptyDatastore = &datastore{
	backend:  &mtgmatcher.Backend{},
	editions: &editionsSnapshot{},
}

// currentDatastore returns the live datastore, or the empty one before the
// first load has published. Never nil.
func currentDatastore() *datastore {
	ds := liveDatastore.Load()
	if ds != nil {
		return ds
	}
	return emptyDatastore
}

// backend is the website's live card datastore. The backend itself is
// immutable after Open; only the pointer changes when a datastore reloads.
func backend() *mtgmatcher.Backend {
	return currentDatastore().backend
}
