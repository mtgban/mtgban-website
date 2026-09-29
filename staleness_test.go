package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

func TestIsStale(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Hour)
	old := now.Add(-49 * time.Hour)
	atTheThreshold := now.Add(-StaleAfter)

	tests := []struct {
		name string
		ts   *time.Time
		want bool
	}{
		{"an hour old", &fresh, false},
		{"49 hours old", &old, true},
		{"exactly 48h old is not yet stale", &atTheThreshold, false},
		{"never loaded", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStale(tt.ts, now)
			if got != tt.want {
				t.Errorf("isStale(%v) = %v, want %v", tt.ts, got, tt.want)
			}
		})
	}
}

func TestStaleBadge(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Hour)
	threeDays := now.Add(-72 * time.Hour)

	tests := []struct {
		name string
		ts   *time.Time
		want string
	}{
		{"fresh", &fresh, ""},
		{"3 days stale", &threeDays, "stale 3d"},
		{"never loaded", nil, "stale"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := staleBadge(tt.ts, now)
			if got != tt.want {
				t.Errorf("staleBadge(%v) = %q, want %q", tt.ts, got, tt.want)
			}
		})
	}
}

func TestClassifyStaleTransition(t *testing.T) {
	tests := []struct {
		name    string
		was, is bool
		want    staleTransition
	}{
		{"fresh, stays fresh", false, false, noStaleTransition},
		{"stale, stays stale", true, true, noStaleTransition},
		{"fresh goes stale", false, true, becameStale},
		{"stale recovers", true, false, staleRecovered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyStaleTransition(tt.was, tt.is)
			if got != tt.want {
				t.Errorf("classifyStaleTransition(%v, %v) = %v, want %v", tt.was, tt.is, got, tt.want)
			}
		})
	}
}

// Pins that a stale/recovered transition notifies exactly once, and a
// repeat check while a row stays stale does not notify again.
func TestCheckStalenessTracksTransitionsOverRepeatedChecks(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevState := staleAlarmState.stale
	prevNotify := notifyStale
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		staleAlarmState.stale = prevState
		notifyStale = prevNotify
	})
	staleAlarmState.stale = map[string]bool{}

	var notices []string
	notifyStale = func(kind, message string) error {
		notices = append(notices, message)
		return nil
	}

	old := time.Now().Add(-72 * time.Hour)
	fresh := time.Now()
	sellers := []mtgban.Seller{inventoryOf("ZZSTALE", 1, old), inventoryOf("ZZFRESH", 1, fresh)}
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&noVendors)

	checkStaleness()
	if !staleAlarmState.stale["ZZSTALE/retail"] {
		t.Fatal("first check did not record ZZSTALE/retail as stale")
	}
	if staleAlarmState.stale["ZZFRESH/retail"] {
		t.Fatal("first check wrongly recorded ZZFRESH/retail as stale")
	}
	if len(notices) != 1 {
		t.Fatalf("after going stale: %d notices, want 1: %v", len(notices), notices)
	}

	// A second check with nothing changed must not un-record the stale row,
	// nor notify again while it stays stale.
	checkStaleness()
	if !staleAlarmState.stale["ZZSTALE/retail"] {
		t.Fatal("second check lost ZZSTALE/retail's stale state")
	}
	if len(notices) != 1 {
		t.Fatalf("after a repeat check while still stale: %d notices, want still 1: %v", len(notices), notices)
	}

	// ZZSTALE loads fresh data: the next check must flip it back and notify
	// exactly once more, for the recovery.
	sellers = []mtgban.Seller{inventoryOf("ZZSTALE", 1, time.Now()), inventoryOf("ZZFRESH", 1, fresh)}
	sellersPtr.Store(&sellers)
	checkStaleness()
	if staleAlarmState.stale["ZZSTALE/retail"] {
		t.Fatal("check after a fresh load still reads ZZSTALE/retail as stale")
	}
	if len(notices) != 2 {
		t.Fatalf("after recovering: %d notices, want 2: %v", len(notices), notices)
	}
}

// Pins that checkStaleness never alarms on a session store, matching the
// dashboard's own stale banner.
func TestCheckStalenessSkipsSessionStores(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevState := staleAlarmState.stale
	prevNotify := notifyStale
	prevSessions := Sessions
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		staleAlarmState.stale = prevState
		notifyStale = prevNotify
		Sessions = prevSessions
	})
	staleAlarmState.stale = map[string]bool{}
	Sessions = sessionstore.New(sessionHooks())

	var notices []string
	notifyStale = func(kind, message string) error {
		notices = append(notices, message)
		return nil
	}

	var noSellers []mtgban.Seller
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&noSellers)
	vendorsPtr.Store(&noVendors)

	// Publish stamps the served copy "now"; back-date it directly so the
	// row reads stale while Sessions still claims the shorthand.
	rows := []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}}
	_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZUPLOAD"), rows)
	if err != nil {
		t.Fatalf("publishing the session store: %s", err)
	}
	old := time.Now().Add(-72 * time.Hour)
	sellers := []mtgban.Seller{inventoryOf("ZZUPLOAD", 1, old)}
	sellersPtr.Store(&sellers)

	checkStaleness()
	if len(notices) != 0 {
		t.Errorf("a session store triggered the alarm: %v", notices)
	}
	if staleAlarmState.stale["ZZUPLOAD/retail"] {
		t.Error("a session store was recorded as stale")
	}
}

// withStaleAlarm serves sellers and starts the alarm from nothing, with post
// standing in for Discord.
func withStaleAlarm(t *testing.T, sellers []mtgban.Seller, post func(message string) error) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevState := staleAlarmState.stale
	prevNotify := notifyStale
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		staleAlarmState.stale = prevState
		notifyStale = prevNotify
	})
	staleAlarmState.stale = map[string]bool{}
	notifyStale = func(_, message string) error { return post(message) }
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&noVendors)
}

// The rows that go stale in one check are announced in one message, so a
// burst of them does not run into Discord's rate limit.
func TestCheckStalenessAnnouncesOneCheckTogether(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	var notices []string
	withStaleAlarm(t, []mtgban.Seller{inventoryOf("ZZA", 1, old), inventoryOf("ZZB", 1, old), inventoryOf("ZZC", 1, old)},
		func(message string) error {
			notices = append(notices, message)
			return nil
		})

	checkStaleness()
	if len(notices) != 1 || strings.Count(notices[0], "has not updated in") != 3 {
		t.Errorf("notices = %q, want one message naming all three", notices)
	}
}

// A message Discord refuses is not recorded as announced, so the next check
// posts it again; once it goes through, the row stays quiet.
func TestCheckStalenessRetriesARefusedAlarm(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	refuse := true
	var notices []string
	withStaleAlarm(t, []mtgban.Seller{inventoryOf("ZZSTALE", 1, old)}, func(message string) error {
		notices = append(notices, message)
		if refuse {
			return errors.New("429 Too Many Requests")
		}
		return nil
	})

	checkStaleness()
	if staleAlarmState.stale["ZZSTALE/retail"] {
		t.Error("a refused alarm was recorded as announced")
	}
	refuse = false
	checkStaleness()
	checkStaleness()
	if len(notices) != 2 || notices[0] != notices[1] {
		t.Errorf("notices = %q, want the refused alarm posted once more, then quiet", notices)
	}
	if !staleAlarmState.stale["ZZSTALE/retail"] {
		t.Error("the delivered alarm was not recorded")
	}
}

// Changes that do not fit one message go out in several; those in a
// message that went through are recorded even when a later one is refused.
func TestCheckStalenessSplitsWhatDoesNotFit(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	var sellers []mtgban.Seller
	for i := range 60 {
		sellers = append(sellers, inventoryOf(fmt.Sprintf("ZZSTORE%02d", i), 1, old))
	}
	var notices []string
	withStaleAlarm(t, sellers, func(message string) error {
		notices = append(notices, message)
		if len(notices) > 1 {
			return errors.New("429 Too Many Requests")
		}
		return nil
	})

	checkStaleness()
	if len(notices) != 2 || len(notices[0]) > staleMessageBudget {
		t.Fatalf("posted %d messages, the first of %d bytes: want two, within %d", len(notices), len(notices[0]), staleMessageBudget)
	}
	announced := strings.Count(notices[0], "\n") + 1
	var recorded int
	for _, stale := range staleAlarmState.stale {
		if stale {
			recorded++
		}
	}
	if recorded != announced || announced >= len(sellers) {
		t.Errorf("recorded %d rows, want the %d the first message announced of %d", recorded, announced, len(sellers))
	}
}
