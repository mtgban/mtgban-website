package main

import (
	"context"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/notify"
	"github.com/mtgban/mtgban-website/internal/sessionstore"
	"github.com/mtgban/mtgban-website/timeseries"
)

// StaleAfter is how long a store's retail or buylist data may go without a
// fresh load before the admin dashboard and the Discord alarm call it stale.
const StaleAfter = 48 * time.Hour

// DropAfter is how long a store's retail or buylist data may go without a
// fresh load before the site stops serving it. Every store scrapes at least
// daily, so this is a week of missed runs.
const DropAfter = 7 * 24 * time.Hour

// isStale reports whether ts - a store's InventoryTimestamp or
// BuylistTimestamp - is older than StaleAfter, as of now. A nil or zero ts
// (never loaded) reads as maximally stale rather than a special case.
func isStale(ts *time.Time, now time.Time) bool {
	return ts == nil || now.Sub(*ts) > StaleAfter
}

// staleBadge is the admin dashboard's "stale Nd" label for ts as of now, or
// "" when ts is fresh. A nil ts has no age to count from, so it reads as
// simply "stale".
func staleBadge(ts *time.Time, now time.Time) string {
	if ts == nil {
		return "stale"
	}
	if !isStale(ts, now) {
		return ""
	}
	return fmt.Sprintf("stale %dd", int(now.Sub(*ts).Hours()/24))
}

// staleTransition classifies how a row's staleness changed between two
// checks, for the Discord alarm to notify on the change alone rather than on
// every check.
type staleTransition int

const (
	noStaleTransition staleTransition = iota
	becameStale
	staleRecovered
)

// classifyStaleTransition is the alarm's decision, pure so it can be tested
// without a clock, a store or Discord: was and is are the previous and
// current staleness of the same row.
func classifyStaleTransition(was, is bool) staleTransition {
	switch {
	case is && !was:
		return becameStale
	case !is && was:
		return staleRecovered
	default:
		return noStaleTransition
	}
}

// staleAlarmState remembers which rows were last announced stale, so
// checkStaleness notifies only on a transition. In-memory only: a restart
// may announce every already-stale row once more.
var staleAlarmState = struct {
	mu          sync.Mutex
	stale       map[string]bool
	strayPrices bool
}{stale: map[string]bool{}}

// strayNotify announces a stray-rows change; overridable in tests.
var strayNotify = func(kind, message string) { ServerNotify(kind, message) }

// strayRowLimit is where the stray-row count stops; overridable in tests.
var strayRowLimit = int64(timeseries.StrayRowLimit)

// strayPriceRows counts the archive rows in prices_default; overridable in tests.
var strayPriceRows = func(ctx context.Context) (int64, error) {
	if PricesArchiveDB == nil {
		return 0, nil
	}
	return PricesArchiveDB.StrayPriceRows(ctx)
}

// checkStrayPrices announces rows in prices_default when they appear and when
// they clear. Callers must hold staleAlarmState.mu.
func checkStrayPrices() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := strayPriceRows(ctx)
	if err != nil {
		log.Println("stray price rows:", err)
		return
	}
	switch stray := n > 0; {
	case stray && !staleAlarmState.strayPrices:
		count := fmt.Sprint(n)
		if n >= strayRowLimit {
			count = "at least " + count
		}
		strayNotify("timeseries", fmt.Sprintf("%s price rows sit in prices_default: a month's partition was missing when they were written", count))
	case !stray && staleAlarmState.strayPrices:
		strayNotify("timeseries", "prices_default is empty again")
	}
	staleAlarmState.strayPrices = n > 0
}

// staleMessageBudget is how much of the alarm one message carries: under
// the 2000 characters Discord takes, with room for notify's dev marker.
const staleMessageBudget = 1900

// notifyStale posts one alarm message and says whether it went through. It
// is overridable in tests, so a check's Discord traffic can be asserted on
// directly.
var notifyStale = func(kind, message string) error {
	log.Println(message)
	if Config().Discord.ServerWebhookURL == "" {
		return nil
	}
	return notify.Send(Config().Discord.ServerWebhookURL, kind, message, DevMode)
}

// droppedStore is a store taken out of the snapshots for data past
// DropAfter, kept for the dashboard and the alarm to name.
type droppedStore struct {
	info    mtgban.ScraperInfo
	kind    string
	updated time.Time
	entries int
}

// droppedStoresPtr holds every store dropStaleStores took out, keyed like the
// alarm's rows. One served again keeps its record: readers skip it.
var droppedStoresPtr atomic.Pointer[map[string]droppedStore]

// pastDrop reports whether ts is older than DropAfter as of now. A store
// with no update time is kept: it has no age to be dropped for.
func pastDrop(ts *time.Time, now time.Time) bool {
	return ts != nil && now.Sub(*ts) > DropAfter
}

// dropStaleStores stops serving every seller and vendor whose data is past
// DropAfter, until a fresh load brings it back. Session stores keep their
// own lifetime.
func dropStaleStores(now time.Time) {
	for _, store := range takeStaleStores(now) {
		switch strings.ToUpper(store.info.Shorthand) {
		case "CK", "CKBLLAST":
			rebuildCKSignals()
			return
		}
	}
}

// takeStaleStores publishes the snapshots without the stores past DropAfter,
// records them, and returns them.
func takeStaleStores(now time.Time) []droppedStore {
	sessions := lockAskedSnapshots()
	defer scrapersWriteMu.Unlock()
	p := currentPrices()

	// A real store counts as left on its side only with a date within
	// DropAfter: an undated one has no age to be fresh by.
	var oldSellers []mtgban.Seller
	realSeller := false
	for _, seller := range p.sellers {
		info := seller.Info()
		session := sessions[info.Shorthand+"/"+sessionstore.Retail]
		if pastDrop(info.InventoryTimestamp, now) && !session {
			oldSellers = append(oldSellers, seller)
			continue
		}
		realSeller = realSeller || (!session && info.InventoryTimestamp != nil)
	}
	// A side with no dated real store left (session stores go on their own,
	// an undated one has no age to vouch for it) keeps its freshest old one
	// served, and checkStaleness calls it out.
	if !realSeller && len(oldSellers) > 0 {
		i := freshestStore(oldSellers, sessionstore.Retail)
		log.Printf("kept %s %s past DropAfter: the last one served", sessionstore.Retail, oldSellers[i].Info().Shorthand)
		oldSellers = slices.Delete(oldSellers, i, i+1)
	}
	var oldVendors []mtgban.Vendor
	realVendor := false
	for _, vendor := range p.vendors {
		info := vendor.Info()
		session := sessions[info.Shorthand+"/"+sessionstore.Buylist]
		if pastDrop(info.BuylistTimestamp, now) && !session {
			oldVendors = append(oldVendors, vendor)
			continue
		}
		realVendor = realVendor || (!session && info.BuylistTimestamp != nil)
	}
	if !realVendor && len(oldVendors) > 0 {
		i := freshestStore(oldVendors, sessionstore.Buylist)
		log.Printf("kept %s %s past DropAfter: the last one served", sessionstore.Buylist, oldVendors[i].Info().Shorthand)
		oldVendors = slices.Delete(oldVendors, i, i+1)
	}

	var dropped []droppedStore
	for _, seller := range oldSellers {
		info := seller.Info()
		dropped = append(dropped, droppedStore{info, sessionstore.Retail, *info.InventoryTimestamp, len(seller.Inventory())})
	}
	for _, vendor := range oldVendors {
		info := vendor.Info()
		dropped = append(dropped, droppedStore{info, sessionstore.Buylist, *info.BuylistTimestamp, len(vendor.Buylist())})
	}
	if len(dropped) == 0 {
		return nil
	}
	sellers := withoutStores(p.sellers, oldSellers)
	vendors := withoutStores(p.vendors, oldVendors)
	pricesPtr.Store(newPrices(sellers, vendors, p.scrapers))

	record := map[string]droppedStore{}
	prev := droppedStoresPtr.Load()
	if prev != nil {
		maps.Copy(record, *prev)
	}
	for _, store := range dropped {
		record[store.info.Shorthand+"/"+store.kind] = store
		log.Printf("dropped %s %s: no update since %s", store.kind, store.info.Shorthand, store.updated.UTC().Format(time.RFC3339))
	}
	droppedStoresPtr.Store(&record)
	return dropped
}

// lockAskedSnapshots takes scrapersWriteMu over a snapshot whose every store
// Sessions was asked about, and returns whether each one, keyed like the
// alarm's rows, was published from an upload. Sessions takes its lock before
// scrapersWriteMu (see dropSessionScraper), so it is asked first, and asked
// again when a publish swaps the snapshot meanwhile.
func lockAskedSnapshots() map[string]bool {
	for {
		p := currentPrices()
		sessions := map[string]bool{}
		for _, seller := range p.sellers {
			info := seller.Info()
			sessions[info.Shorthand+"/"+sessionstore.Retail] = Sessions.Is(sessionstore.Retail, info.Shorthand)
		}
		for _, vendor := range p.vendors {
			info := vendor.Info()
			sessions[info.Shorthand+"/"+sessionstore.Buylist] = Sessions.Is(sessionstore.Buylist, info.Shorthand)
		}

		scrapersWriteMu.Lock()
		if currentPrices() == p {
			return sessions
		}
		scrapersWriteMu.Unlock()
	}
}

// withoutStores is stores, in its order, less the ones in gone, matched by
// shorthand as a side serves one store per shorthand.
func withoutStores[S interface{ Info() mtgban.ScraperInfo }](stores, gone []S) []S {
	shorthands := map[string]bool{}
	for _, store := range gone {
		shorthands[store.Info().Shorthand] = true
	}
	var kept []S
	for _, store := range stores {
		if !shorthands[store.Info().Shorthand] {
			kept = append(kept, store)
		}
	}
	return kept
}

// freshestStore is the index of the store in stores with the latest kind
// timestamp; every one of them has one, being past DropAfter.
func freshestStore[S interface{ Info() mtgban.ScraperInfo }](stores []S, kind string) int {
	timestamp := func(info mtgban.ScraperInfo) time.Time {
		if kind == sessionstore.Retail {
			return *info.InventoryTimestamp
		}
		return *info.BuylistTimestamp
	}
	best := 0
	for i, store := range stores {
		if timestamp(store.Info()).After(timestamp(stores[best].Info())) {
			best = i
		}
	}
	return best
}

// servedStore reports whether the snapshots serve shorthand on kind's side.
func servedStore(kind, shorthand string) bool {
	if kind == sessionstore.Retail {
		return slices.ContainsFunc(GetSellers(), func(s mtgban.Seller) bool { return s.Info().Shorthand == shorthand })
	}
	return slices.ContainsFunc(GetVendors(), func(v mtgban.Vendor) bool { return v.Info().Shorthand == shorthand })
}

// droppedEntries is how many entries kind's store under shorthand had when
// it was dropped, 0 for one never dropped.
func droppedEntries(kind, shorthand string) int {
	record := droppedStoresPtr.Load()
	if record == nil {
		return 0
	}
	return (*record)[shorthand+"/"+kind].entries
}

// droppedDump reports whether a dump timestamped ts, for kind's store under
// shorthand, is not worth serving again after a drop: undated, past
// DropAfter, or no newer than the data the store was dropped with.
func droppedDump(kind, shorthand string, ts *time.Time, now time.Time) bool {
	record := droppedStoresPtr.Load()
	if record == nil {
		return false
	}
	store, found := (*record)[shorthand+"/"+kind]
	if !found {
		return false
	}
	// An undated dump could never be dropped again
	return ts == nil || pastDrop(ts, now) || !ts.After(store.updated)
}

// droppedStoresOf is kind's side of the dropped stores not served again, by
// shorthand.
func droppedStoresOf(kind string) []droppedStore {
	record := droppedStoresPtr.Load()
	if record == nil {
		return nil
	}
	var out []droppedStore
	for _, key := range slices.Sorted(maps.Keys(*record)) {
		store := (*record)[key]
		if store.kind == kind && !servedStore(kind, store.info.Shorthand) {
			out = append(out, store)
		}
	}
	return out
}

// checkStaleness drops the stores past DropAfter, compares every served
// seller's and vendor's staleness against staleAlarmState and announces the
// rows that changed, the drops included. Session stores
// (internal/sessionstore) are skipped, like the dashboard's own banner.
func checkStaleness() {
	now := time.Now()
	dropStaleStores(now)

	staleAlarmState.mu.Lock()
	defer staleAlarmState.mu.Unlock()

	var changes []staleChange
	for _, seller := range GetSellers() {
		info := seller.Info()
		if Sessions.Is(sessionstore.Retail, info.Shorthand) {
			continue
		}
		changes = appendStaleChange(changes, info.Shorthand+"/"+sessionstore.Retail, sessionstore.Retail, info.Shorthand, info.InventoryTimestamp, now)
		changes = appendKeptChange(changes, info.Shorthand+"/"+sessionstore.Retail, sessionstore.Retail, info.Shorthand, info.InventoryTimestamp, now)
	}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if Sessions.Is(sessionstore.Buylist, info.Shorthand) {
			continue
		}
		changes = appendStaleChange(changes, info.Shorthand+"/"+sessionstore.Buylist, sessionstore.Buylist, info.Shorthand, info.BuylistTimestamp, now)
		changes = appendKeptChange(changes, info.Shorthand+"/"+sessionstore.Buylist, sessionstore.Buylist, info.Shorthand, info.BuylistTimestamp, now)
	}
	for _, kind := range []string{sessionstore.Retail, sessionstore.Buylist} {
		changes = appendDropChanges(changes, kind, now)
	}
	announceStaleChanges(changes)
	checkStrayPrices()
}

// appendDropChanges announces each of kind's dropped stores once when it
// stops being served, and once when a fresh load serves it again. Callers
// must hold staleAlarmState.mu.
func appendDropChanges(changes []staleChange, kind string, now time.Time) []staleChange {
	record := droppedStoresPtr.Load()
	if record == nil {
		return changes
	}
	for _, key := range slices.Sorted(maps.Keys(*record)) {
		store := (*record)[key]
		if store.kind != kind {
			continue
		}
		alarmKey := "dropped/" + key
		label := staleLabel(kind, store.info.Shorthand)
		switch classifyStaleTransition(staleAlarmState.stale[alarmKey], !servedStore(kind, store.info.Shorthand)) {
		case becameStale:
			line := label + " is no longer served, not updated in " + staleAge(store.updated, now)
			// Its return is announced as served again, not also as fresh again
			changes = append(changes, staleChange{key: alarmKey, stale: true, line: line, clears: key})
		case staleRecovered:
			changes = append(changes, staleChange{key: alarmKey, stale: false, line: label + " is served again"})
		}
	}
	return changes
}

// appendKeptChange announces, with @here, a served store past DropAfter:
// after dropStaleStores, only the last store on its side is one. Callers
// must hold staleAlarmState.mu.
func appendKeptChange(changes []staleChange, key, kind, shorthand string, ts *time.Time, now time.Time) []staleChange {
	alarmKey := "kept/" + key
	switch classifyStaleTransition(staleAlarmState.stale[alarmKey], pastDrop(ts, now)) {
	case becameStale:
		line := "@here " + staleLabel(kind, shorthand) + " is still served, not updated in " + staleAge(*ts, now) + ": it is the last " + kind + " store left"
		return append(changes, staleChange{key: alarmKey, stale: true, line: line})
	case staleRecovered:
		// Its fresh load is announced on its own row
		delete(staleAlarmState.stale, alarmKey)
	}
	return changes
}

// staleChange is one row's staleness flipping, and the line announcing it.
type staleChange struct {
	key   string
	stale bool
	line  string
	// clears is a row this change settles too, once recorded
	clears string
}

// appendStaleChange appends the row to changes if its staleness differs
// from the last one announced. Callers must hold staleAlarmState.mu.
func appendStaleChange(changes []staleChange, key, kind, shorthand string, ts *time.Time, now time.Time) []staleChange {
	switch classifyStaleTransition(staleAlarmState.stale[key], isStale(ts, now)) {
	case becameStale:
		line := staleLabel(kind, shorthand) + " has no update time"
		if ts != nil {
			line = staleLabel(kind, shorthand) + " has not updated in " + staleAge(*ts, now)
		}
		return append(changes, staleChange{key: key, stale: true, line: line})
	case staleRecovered:
		return append(changes, staleChange{key: key, stale: false, line: staleLabel(kind, shorthand) + " is fresh again"})
	}
	return changes
}

// announceStaleChanges posts changes in as few messages as fit, and records
// each change once its message went through. It stops at the first refusal:
// what was not recorded is announced at the next check. Callers must hold
// staleAlarmState.mu.
func announceStaleChanges(changes []staleChange) {
	for len(changes) > 0 {
		lines := []string{changes[0].line}
		size := len(changes[0].line)
		for len(lines) < len(changes) && size+1+len(changes[len(lines)].line) <= staleMessageBudget {
			size += 1 + len(changes[len(lines)].line)
			lines = append(lines, changes[len(lines)].line)
		}
		if notifyStale("stale", strings.Join(lines, "\n")) != nil {
			return
		}
		for _, change := range changes[:len(lines)] {
			staleAlarmState.stale[change.key] = change.stale
			if change.clears != "" {
				staleAlarmState.stale[change.clears] = false
			}
		}
		changes = changes[len(lines):]
	}
}

// staleLabel names a row for the alarm message: game, store (or "unknown
// store"), kind and shorthand.
func staleLabel(kind, shorthand string) string {
	store, ok := scraperStoreOf(shorthand)
	if !ok {
		store = "unknown store"
	}
	return fmt.Sprintf("%s/%s %s (%s)", Config().Game, store, kind, shorthand)
}

// staleAge is how long ts has been stale, in whole days (always at least 2,
// since StaleAfter is 48h).
func staleAge(ts, now time.Time) string {
	return fmt.Sprintf("%dd", int(now.Sub(ts).Hours()/24))
}
