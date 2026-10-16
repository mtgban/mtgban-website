package main

import (
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/banprice"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

// datastore is one loaded card datastore and the snapshots the site derives
// from it, built together and published together. Immutable once published,
// but for the odds memo below.
//
// Only backend and editions are non-nil in the empty datastore newSite
// pre-stores (site.go), the value served before the first load completes:
// numbers (exact-number searches scan instead), names (SuggestAPI answers
// 204), palette (lists served no-store) and odds (no labels) all wait for
// an actual load.
//
// odds is the one field filled after publish: a memo of each product's
// counts, computed on first use and shared by every request on this load.
type datastore struct {
	backend  *mtgmatcher.Backend
	numbers  *numbersSnapshot
	names    *suggest.Names
	editions *editionsSnapshot
	palette  *palette.Snapshot
	finishes []banprice.Finish
	odds     *productOdds
	loadedAt time.Time
}
