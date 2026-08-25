package main

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// withNewspaperUUIDs installs a cache of n uuids for the duration of a test.
func withNewspaperUUIDs(t *testing.T, n int) {
	t.Helper()
	prev := newspaperUUIDsPtr.Load()
	t.Cleanup(func() { newspaperUUIDsPtr.Store(prev) })

	set := map[string]struct{}{}
	for i := 0; i < n; i++ {
		set[strconv.Itoa(i)] = struct{}{}
	}
	newspaperUUIDsPtr.Store(&set)
}

// Every newspaper page is built from the cached uuids, so with none the
// section is a stack of empty tables - a game with no newspaper data, or one
// whose database was never configured, should not be offered it at all.
func TestNewspaperHiddenWhenNothingCached(t *testing.T) {
	nav := ExtraNavs["Newspaper"]
	if nav.ShouldHide == nil {
		t.Fatal("the Newspaper section has no ShouldHide, so an empty cache cannot hide it")
	}

	withNewspaperUUIDs(t, 0)
	if !nav.ShouldHide() {
		t.Error("nothing cached, want the section hidden")
	}

	withNewspaperUUIDs(t, 3)
	if nav.ShouldHide() {
		t.Error("uuids cached, want the section shown")
	}
}

// The nav loop used to consult ShouldHide only for subpages, so a hidden
// section still rendered its own button.
func TestNavHonoursShouldHideOnASection(t *testing.T) {
	prevSig, prevDev := SigCheck, DevMode
	t.Cleanup(func() { SigCheck, DevMode = prevSig, prevDev })
	SigCheck, DevMode = false, true

	names := func() []string {
		var out []string
		for _, n := range genPageNav("Search", "").Nav {
			out = append(out, n.Name)
		}
		return out
	}

	withNewspaperUUIDs(t, 5)
	shown := names()
	if !contains(shown, "Newspaper") {
		t.Fatalf("precondition: Newspaper missing from %v", shown)
	}

	withNewspaperUUIDs(t, 0)
	hidden := names()
	if contains(hidden, "Newspaper") {
		t.Errorf("Newspaper still in the nav with nothing cached: %v", hidden)
	}
	// Its subpages go with it rather than dangling.
	for _, sub := range ExtraNavs["Newspaper"].SubPages {
		if contains(hidden, sub.Name) {
			t.Errorf("subpage %q outlived its hidden section", sub.Name)
		}
	}
	// And nothing else was dropped along the way: what disappeared is exactly
	// the section plus whichever of its subpages had been showing (some hide
	// themselves for their own reasons).
	gone := map[string]bool{}
	for _, name := range shown {
		if !contains(hidden, name) {
			gone[name] = true
		}
	}
	expected := map[string]bool{"Newspaper": true}
	for _, sub := range ExtraNavs["Newspaper"].SubPages {
		if contains(shown, sub.Name) {
			expected[sub.Name] = true
		}
	}
	for name := range gone {
		if !expected[name] {
			t.Errorf("%q disappeared and should not have", name)
		}
	}
	for name := range expected {
		if !gone[name] {
			t.Errorf("%q should have disappeared with its section", name)
		}
	}
}

func contains(all []string, want string) bool {
	for _, s := range all {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

var _ = time.Now
