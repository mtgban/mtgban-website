package main

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
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

// withDropState starts each drop test from served sellers and vendors, no
// drops on record and a fresh alarm, and puts all of it back afterwards.
func withDropState(t *testing.T, sellers []mtgban.Seller, vendors []mtgban.Vendor) *[]string {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevDropped := droppedStoresPtr.Load()
	prevState := staleAlarmState.stale
	prevNotify := notifyStale
	prevSessions := Sessions
	prevSignals := ckSignalsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		droppedStoresPtr.Store(prevDropped)
		staleAlarmState.stale = prevState
		notifyStale = prevNotify
		Sessions = prevSessions
		ckSignalsPtr.Store(prevSignals)
	})
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	droppedStoresPtr.Store(nil)
	staleAlarmState.stale = map[string]bool{}
	Sessions = sessionstore.New(sessionHooks())

	var notices []string
	notifyStale = func(kind, message string) error {
		notices = append(notices, message)
		return nil
	}
	return &notices
}

func servedShorthands() (sellers, vendors []string) {
	for _, seller := range GetSellers() {
		sellers = append(sellers, seller.Info().Shorthand)
	}
	for _, vendor := range GetVendors() {
		vendors = append(vendors, vendor.Info().Shorthand)
	}
	return sellers, vendors
}

// A store whose data is past DropAfter stops being served on either side,
// while a merely stale one, a session store and one with no update time stay;
// a fresh load serves it again.
func TestDropStaleStoresStopsServingOnlyOldData(t *testing.T) {
	now := time.Now()
	old, stale := now.Add(-8*24*time.Hour), now.Add(-3*24*time.Hour)
	undated := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"uuid-0": {{Price: 1}}}, mtgban.ScraperInfo{Name: "ZZUNDATED", Shorthand: "ZZUNDATED"})
	withDropState(t, nil, []mtgban.Vendor{buylistOf("ZZOLDV", 1, old), buylistOf("ZZFRESHV", 1, now)})
	_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZUPLOAD"), []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing the session store: %s", err)
	}
	// Publish served the session store anew; serve the back-dated copy.
	sellers := []mtgban.Seller{inventoryOf("ZZOLD", 1, old), inventoryOf("ZZSTALE", 1, stale), inventoryOf("ZZUPLOAD", 1, old), undated}
	sellersPtr.Store(&sellers)

	dropStaleStores(now)

	gotSellers, gotVendors := servedShorthands()
	if !slices.Equal(gotSellers, []string{"ZZSTALE", "ZZUPLOAD", "ZZUNDATED"}) || !slices.Equal(gotVendors, []string{"ZZFRESHV"}) {
		t.Errorf("served sellers %v, vendors %v; want ZZOLD and ZZOLDV dropped", gotSellers, gotVendors)
	}
	if got := droppedStoresOf(sessionstore.Retail); len(got) != 1 || got[0].info.Shorthand != "ZZOLD" {
		t.Errorf("dropped retail = %v, want ZZOLD", got)
	}

	err = updateSellers(inventoryOf("ZZOLD", 1, now))
	if err != nil {
		t.Fatalf("a fresh load was refused: %s", err)
	}
	if got := droppedStoresOf(sessionstore.Retail); len(got) != 0 {
		t.Errorf("ZZOLD is served again but still listed as dropped: %v", got)
	}
}

// The alarm says once that a store is no longer served, and once that it is
// again; the dashboard lists it as dropped in between.
func TestCheckStalenessAnnouncesADropAndItsReturn(t *testing.T) {
	notices := withDropState(t, []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-8*24*time.Hour))}, nil)

	checkStaleness()
	checkStaleness()
	if len(*notices) != 1 || !strings.Contains((*notices)[0], "(ZZOLD) is no longer served, not updated in 8d") {
		t.Fatalf("after two checks: %q, want one drop notice", *notices)
	}

	var pv PageVars
	adminScraperTable(sessionstore.Retail, time.Now(), &pv)
	if len(pv.Tables) != 1 || len(pv.Tables[0]) != 1 || pv.Tables[0][0][1] != "ZZOLD" || pv.Tables[0][0][8] != "dropped 8d" {
		t.Errorf("dashboard = %q, want ZZOLD marked dropped 8d", pv.Tables)
	}

	sellers := []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now())}
	sellersPtr.Store(&sellers)
	checkStaleness()
	if len(*notices) != 2 || !strings.Contains((*notices)[1], "(ZZOLD) is served again") {
		t.Errorf("after a fresh load: %q, want a served-again notice", *notices)
	}
}

// Dropping CK takes its signals with it rather than leaving the last ones up.
func TestDroppingCKClearsItsSignals(t *testing.T) {
	withDropState(t, nil, []mtgban.Vendor{buylistOf("CK", 1, time.Now().Add(-8*24*time.Hour))})
	signals := map[string]ckView{"uuid-0": {PauseLabel: "paused"}}
	ckSignalsPtr.Store(&signals)

	dropStaleStores(time.Now())
	if ckSignalsPtr.Load() != nil {
		t.Error("CK was dropped but its signals are still served")
	}
}

// The sweep asks Sessions before taking scrapersWriteMu: a session publish
// takes them the other way round, Sessions' lock and then, to install,
// scrapersWriteMu, so holding both in the opposite order can deadlock.
func TestDropStaleStoresAsksSessionsBeforeLocking(t *testing.T) {
	withDropState(t, []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-8*24*time.Hour))}, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	hooks := sessionHooks()
	hooks.Install = func(string, mtgban.Scraper) error {
		close(entered)
		<-release
		return nil
	}
	Sessions = sessionstore.New(hooks)

	published := make(chan error)
	go func() {
		_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZUPLOAD"), []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}})
		published <- err
	}()
	<-entered // the publish now holds Sessions' lock

	swept := make(chan struct{})
	go func() {
		dropStaleStores(time.Now())
		close(swept)
	}()
	// Wait for the sweep to block on Sessions, then see what it holds
	waitForStack(t, "takeStaleStores", "sessionstore.(*Registry).Is(")
	free := scrapersWriteMu.TryLock()
	if free {
		scrapersWriteMu.Unlock()
	}
	close(release)
	err := <-published
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}
	<-swept
	if !free {
		t.Error("the sweep held scrapersWriteMu while waiting on Sessions")
	}
}

// A store back from a drop is held to the size it had then, as a served
// store is: the first dump after an outage is the likeliest to be partial.
func TestAStoreBackFromADropIsHeldToItsSize(t *testing.T) {
	old := time.Now().Add(-8 * 24 * time.Hour)
	withDropState(t, []mtgban.Seller{inventoryOf("ZZOLD", 200, old)}, []mtgban.Vendor{buylistOf("ZZOLDV", 200, old)})
	dropStaleStores(time.Now())

	if updateSellers(inventoryOf("ZZOLD", 10, time.Now())) == nil {
		t.Error("a store dropped with 200 entries came back with 10")
	}
	if updateVendors(buylistOf("ZZOLDV", 10, time.Now())) == nil {
		t.Error("a buylist dropped with 200 entries came back with 10")
	}
	err := updateSellers(inventoryOf("ZZOLD", 150, time.Now()))
	if err != nil {
		t.Errorf("a store dropped with 200 entries was refused back with 150: %s", err)
	}
}

// A store announced stale, then dropped, is announced once more on its
// return, as served again, not also as fresh again.
func TestAReturnAfterADropIsAnnouncedOnce(t *testing.T) {
	notices := withDropState(t, []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-3*24*time.Hour))}, nil)
	checkStaleness()

	sellers := []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-8*24*time.Hour))}
	sellersPtr.Store(&sellers)
	checkStaleness()

	sellers = []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now())}
	sellersPtr.Store(&sellers)
	checkStaleness()

	// One check's lines go out as one message
	if len(*notices) != 3 || !strings.Contains((*notices)[2], "(ZZOLD) is served again") || strings.Contains((*notices)[2], "fresh again") {
		t.Errorf("notices = %q, want stale, dropped, then served again alone", *notices)
	}
}

// waitForStack waits until some goroutine's stack runs through every one of
// frames, so a test can act once another goroutine is known to be blocked.
func waitForStack(t *testing.T, frames ...string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if !slices.ContainsFunc(frames, func(frame string) bool { return !strings.Contains(stack, frame) }) {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no goroutine reached %q", frames)
}

// A drop announced to no one yet keeps the store's stale row as it was: if
// the store is back by the next check, that row still says it is fresh.
func TestARefusedDropLineKeepsTheStaleRow(t *testing.T) {
	notices := withDropState(t, []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-3*24*time.Hour))}, nil)
	checkStaleness()

	sellers := []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now().Add(-8*24*time.Hour))}
	sellersPtr.Store(&sellers)
	notifyStale = func(string, string) error { return errors.New("refused") }
	checkStaleness()

	notifyStale = func(kind, message string) error {
		*notices = append(*notices, message)
		return nil
	}
	sellers = []mtgban.Seller{inventoryOf("ZZOLD", 1, time.Now())}
	sellersPtr.Store(&sellers)
	checkStaleness()

	if len(*notices) != 2 || !strings.Contains((*notices)[1], "(ZZOLD) is fresh again") {
		t.Errorf("notices = %q, want stale and then fresh again", *notices)
	}
}
