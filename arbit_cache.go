package main

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

// arbitHeldRows is how many comparison rows a snapshot keeps, about 95 MB
// of 486-byte rows: every source's default arbit and reverse view hold
// 175,000 between them, one view of a source a few hundred to 120,000.
const arbitHeldRows = 200_000

// arbitView is what a comparison's rows depend on beside its two stores and
// the backend: the page and the filters ArbitOpts was built from, and the
// shorthands of the applied toggles' price sources, sorted and joined by
// commas.
type arbitView struct {
	mode         arbitMode
	filters      string
	priceSources string
}

// newArbitView is the view of a request at st in mode m.
func newArbitView(st arbitState, m arbitMode) arbitView {
	var priceSources []string
	for key := range st.applied(m) {
		shorthand := FilterOptConfig[key].PriceSource
		if shorthand != "" {
			priceSources = append(priceSources, shorthand)
		}
	}
	slices.Sort(priceSources)
	return arbitView{mode: m, filters: st.engineKey(m), priceSources: strings.Join(priceSources, ",")}
}

// arbitKey is one comparison: a view of the published source and compared
// store, and the TCGplayer Direct listings either side's stock comes from.
type arbitKey struct {
	view            arbitView
	source, scraper mtgban.Scraper
	direct          *tcgListingsSnapshot
}

// arbitRows is one comparison's rows, computed by the first request to ask.
type arbitRows struct {
	once sync.Once
	rows []mtgban.ArbitEntry

	// Under the cache's mutex: whether rows is set, the rows counted
	// against its budget, and its clock at the last request for these
	done bool
	held int
	used uint64
}

// arbitCache holds one prices snapshot's comparisons against the backend
// they resolved through, keeping the most recently asked for within budget
// rows. A published store is never changed in place, so newPrices carries
// the comparisons the next snapshot still publishes both stores of, and a
// replaced snapshot's stores go with it.
type arbitCache struct {
	mu      sync.Mutex
	budget  int
	backend weak.Pointer[matcher.Backend]
	entries map[arbitKey]*arbitRows
	held    int
	clock   uint64
}

// arbitHeldFor is next's cache: the comparisons of prev's that next still
// publishes both stores of, and the same price sources of their view as
// prev.
// prev is nil before the first publish.
func arbitHeldFor(prev, next *prices) *arbitCache {
	c := &arbitCache{budget: arbitHeldRows, entries: map[arbitKey]*arbitRows{}}
	if prev == nil {
		return c
	}
	prev.arbit.mu.Lock()
	defer prev.arbit.mu.Unlock()
	c.budget, c.backend, c.clock = prev.arbit.budget, prev.arbit.backend, prev.arbit.clock
	for key, entry := range prev.arbit.entries {
		if !entry.done || !next.publishes(key.source) || !next.publishes(key.scraper) || !next.sameStores(prev, key.view.priceSources) {
			continue
		}
		// Each cache counts its own entries under its own mutex
		carried := &arbitRows{rows: entry.rows, done: true, held: entry.held, used: entry.used}
		carried.once.Do(func() {})
		c.entries[key] = carried
		c.held += carried.held
	}
	return c
}

// arbitRows are the rows comparing source with scraper in view, shared and
// read-only, run with opts the first time they are asked for. A store p
// does not publish, such as a reader's custom buylist, is compared afresh.
func (p *prices) arbitRows(b *matcher.Backend, view arbitView, opts *mtgban.ArbitOpts, source, scraper mtgban.Scraper) []mtgban.ArbitEntry {
	key := arbitKey{view: view, source: unwrapDirectStock(source), scraper: unwrapDirectStock(scraper)}
	if !p.publishes(key.source) || !p.publishes(key.scraper) {
		return compareStores(b, opts, view.mode, source, scraper)
	}
	key.direct = cmp.Or(directListings(source), directListings(scraper))

	c := p.arbit
	c.mu.Lock()
	if c.backend != weak.Make(b) {
		c.backend = weak.Make(b)
		c.entries, c.held = map[arbitKey]*arbitRows{}, 0
	}
	entry, found := c.entries[key]
	if !found {
		entry = &arbitRows{}
		c.entries[key] = entry
	}
	c.clock++
	entry.used = c.clock
	c.mu.Unlock()

	entry.once.Do(func() {
		rows := compareStores(b, opts, view.mode, source, scraper)
		entry.rows = rows
		c.mu.Lock()
		entry.done = true
		if c.entries[key] == entry {
			entry.held = len(rows)
			c.held += entry.held
			c.evict()
		}
		c.mu.Unlock()
	})
	return entry.rows
}

// evict drops the least recently asked for comparisons until the rows
// held fit the budget.
func (c *arbitCache) evict() {
	for c.held > c.budget {
		var oldest arbitKey
		var oldestEntry *arbitRows
		for key, entry := range c.entries {
			if oldestEntry == nil || entry.used < oldestEntry.used {
				oldest, oldestEntry = key, entry
			}
		}
		delete(c.entries, oldest)
		c.held -= oldestEntry.held
	}
}

// compareStores runs the comparison scraperCompare shows for one store
// against the source, for the page m is.
func compareStores(b *matcher.Backend, opts *mtgban.ArbitOpts, m arbitMode, source, scraper mtgban.Scraper) []mtgban.ArbitEntry {
	switch {
	case m.Global && m.Sealed:
		return mtgban.Mismatch(b, opts, source.(mtgban.Seller), scraper.(mtgban.Seller))
	case m.Global:
		return mtgban.Mismatch(b, opts, scraper.(mtgban.Seller), source.(mtgban.Seller))
	case m.Reverse:
		return mtgban.Arbit(b, opts, source.(mtgban.Vendor), scraper.(mtgban.Seller))
	}
	return mtgban.Arbit(b, opts, scraper.(mtgban.Vendor), source.(mtgban.Seller))
}

// unwrapDirectStock is the published store under Direct's stock, or s.
func unwrapDirectStock(s mtgban.Scraper) mtgban.Scraper {
	stocked, wrapped := s.(*directStockSeller)
	if wrapped {
		return stocked.Seller
	}
	return s
}

// directListings is the Direct listings s's stock was built from, nil for
// a store that carries none.
func directListings(s mtgban.Scraper) *tcgListingsSnapshot {
	stocked, wrapped := s.(*directStockSeller)
	if !wrapped {
		return nil
	}
	stocked.Inventory()
	return stocked.snap
}

// publishes says whether s is the store p publishes under its shorthand.
func (p *prices) publishes(s mtgban.Scraper) bool {
	shorthand := s.Info().Shorthand
	seller, isSeller := s.(mtgban.Seller)
	if isSeller && p.index.seller[shorthand] == seller {
		return true
	}
	vendor, isVendor := s.(mtgban.Vendor)
	return isVendor && p.index.vendor[shorthand] == vendor
}

// sameStores says whether p and q publish the same stores, or none, under
// each of the comma-separated shorthands, in any case, as the toggles
// look them up.
func (p *prices) sameStores(q *prices, shorthands string) bool {
	if shorthands == "" {
		return true
	}
	for shorthand := range strings.SplitSeq(strings.ToLower(shorthands), ",") {
		if p.index.sellerFold[shorthand] != q.index.sellerFold[shorthand] || p.index.vendorFold[shorthand] != q.index.vendorFold[shorthand] {
			return false
		}
	}
	return true
}
