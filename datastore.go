package main

import (
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

// datastore is one loaded card datastore and the snapshots the site derives
// from it, built together and published together. Immutable once published.
//
// Only backend and editions are non-nil in the empty datastore newSite
// pre-stores (site.go), the value served before the first load completes:
// numbers (exact-number searches scan instead), names (SuggestAPI answers
// 204) and palette (lists served no-store) all wait for an actual load.
type datastore struct {
	backend  *mtgmatcher.Backend
	numbers  *numbersSnapshot
	names    *suggest.Names
	editions *editionsSnapshot
	palette  *palette.Snapshot
	loadedAt time.Time
}
