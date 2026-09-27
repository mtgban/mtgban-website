package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

// StaleAfter is how long a store's retail or buylist data may go without a
// fresh load before the admin dashboard and the Discord alarm call it stale.
const StaleAfter = 48 * time.Hour

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

// staleAlarmState remembers which rows were stale last check, so
// checkStaleness notifies only on a transition. In-memory only: a restart
// may announce every already-stale row once more.
var staleAlarmState = struct {
	mu    sync.Mutex
	stale map[string]bool
}{stale: map[string]bool{}}

// notifyStale is the alarm's notification hook, overridable in tests so a
// check's actual Discord traffic can be asserted on directly.
var notifyStale = func(kind, message string) { ServerNotify(kind, message) }

// checkStaleness compares every served seller's and vendor's staleness
// against staleAlarmState and notifies only on a change. Session stores
// (internal/sessionstore) are skipped, like the dashboard's own banner.
func checkStaleness() {
	now := time.Now()

	staleAlarmState.mu.Lock()
	defer staleAlarmState.mu.Unlock()

	for _, seller := range GetSellers() {
		info := seller.Info()
		if Sessions.Is(sessionstore.Retail, info.Shorthand) {
			continue
		}
		noteStaleTransition(info.Shorthand+"/"+sessionstore.Retail, sessionstore.Retail, info.Shorthand, info.InventoryTimestamp, now)
	}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if Sessions.Is(sessionstore.Buylist, info.Shorthand) {
			continue
		}
		noteStaleTransition(info.Shorthand+"/"+sessionstore.Buylist, sessionstore.Buylist, info.Shorthand, info.BuylistTimestamp, now)
	}
}

// noteStaleTransition updates staleAlarmState for one row and notifies if
// its staleness changed. Callers must hold staleAlarmState.mu.
func noteStaleTransition(key, kind, shorthand string, ts *time.Time, now time.Time) {
	switch classifyStaleTransition(staleAlarmState.stale[key], isStale(ts, now)) {
	case becameStale:
		staleAlarmState.stale[key] = true
		label := staleLabel(kind, shorthand)
		if ts == nil {
			notifyStale("stale", label+" has no update time")
		} else {
			notifyStale("stale", label+" has not updated in "+staleAge(*ts, now))
		}
	case staleRecovered:
		staleAlarmState.stale[key] = false
		notifyStale("stale", staleLabel(kind, shorthand)+" is fresh again")
	}
}

// staleLabel names a row for the alarm message: game, store (or "unknown
// store"), kind and shorthand.
func staleLabel(kind, shorthand string) string {
	store, ok := scraperStoreOf(shorthand)
	if !ok {
		store = "unknown store"
	}
	return fmt.Sprintf("%s/%s %s (%s)", Config.Game, store, kind, shorthand)
}

// staleAge is how long ts has been stale, in whole days (always at least 2,
// since StaleAfter is 48h).
func staleAge(ts, now time.Time) string {
	return fmt.Sprintf("%dd", int(now.Sub(ts).Hours()/24))
}
