package main

import (
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/banprice"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

// datastore is one loaded card datastore and the snapshots the site derives
// from it, built together and published together. Immutable once published.
//
// Only backend and editions are non-nil in the empty datastore newSite
// pre-stores (site.go), the value served before the first load completes:
// numbers (exact-number searches scan instead, and a number searched alone
// is no collector number), sources (contents: searches scan instead), names
// (SuggestAPI answers 204), palette (lists served no-store) and odds (no
// labels) all wait for an actual load.
type datastore struct {
	backend  *matcher.Backend
	numbers  *numbersSnapshot
	sources  *sourcesSnapshot
	names    *suggest.Names
	editions *editionsSnapshot
	palette  *palette.Snapshot
	finishes []banprice.Finish
	odds     *productOdds
	loadedAt time.Time
}
