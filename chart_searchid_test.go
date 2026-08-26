package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The row under a chart and the chart itself have to mean the same printing,
// which is why the id comes off the resolved target rather than from a second
// resolution of its own.
func TestChartSearchID(t *testing.T) {
	t.Run("the target names the row", func(t *testing.T) {
		target := &chartTarget{BanID: 13456, SearchID: "abcd_f"}
		got, ok := chartSearchID("ban:13456", target)
		if !ok || got != "abcd_f" {
			t.Errorf("chartSearchID = %q/%v, want abcd_f/true", got, ok)
		}
	})

	// No archive to resolve against - a deployment without one, or an id that
	// resolved to nothing - still maps a plain matcher id.
	t.Run("a matcher id resolves without a target", func(t *testing.T) {
		uuids := mtgmatcher.GetUUIDs()
		if len(uuids) == 0 {
			t.Skip("datastore not loaded")
		}
		got, ok := chartSearchID(uuids[0], nil)
		if !ok || got != uuids[0] {
			t.Errorf("chartSearchID = %q/%v, want %q/true", got, ok, uuids[0])
		}
	})

	// An id nothing can place comes back as it went in, and says so: the caller
	// counts it toward the "left out of the chart" notice rather than dropping
	// it silently.
	t.Run("an unplaceable id says so", func(t *testing.T) {
		got, ok := chartSearchID("ban:999999999", nil)
		if ok || got != "ban:999999999" {
			t.Errorf("chartSearchID = %q/%v, want the id back with ok=false", got, ok)
		}
	})
}
