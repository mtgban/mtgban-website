package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/notify"
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

// staleAlarmState remembers which rows were last announced stale, so
// checkStaleness notifies only on a transition. In-memory only: a restart
// may announce every already-stale row once more.
var staleAlarmState = struct {
	mu    sync.Mutex
	stale map[string]bool
}{stale: map[string]bool{}}

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

// checkStaleness compares every served seller's and vendor's staleness
// against staleAlarmState and announces the rows that changed. Session
// stores (internal/sessionstore) are skipped, like the dashboard's own
// banner.
func checkStaleness() {
	now := time.Now()

	staleAlarmState.mu.Lock()
	defer staleAlarmState.mu.Unlock()

	var changes []staleChange
	for _, seller := range GetSellers() {
		info := seller.Info()
		if Sessions.Is(sessionstore.Retail, info.Shorthand) {
			continue
		}
		changes = appendStaleChange(changes, info.Shorthand+"/"+sessionstore.Retail, sessionstore.Retail, info.Shorthand, info.InventoryTimestamp, now)
	}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if Sessions.Is(sessionstore.Buylist, info.Shorthand) {
			continue
		}
		changes = appendStaleChange(changes, info.Shorthand+"/"+sessionstore.Buylist, sessionstore.Buylist, info.Shorthand, info.BuylistTimestamp, now)
	}
	announceStaleChanges(changes)
}

// staleChange is one row's staleness flipping, and the line announcing it.
type staleChange struct {
	key   string
	stale bool
	line  string
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
