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

// A ban_id and a TCGplayer product id can be the same number - the overlap
// resolveChartTarget's precedence exists to navigate - so neither the target's
// verdict nor the ban: marker may be second-guessed by asking the matcher's
// external map about the raw digits.
func TestChartSearchIDDoesNotGuessBanIDs(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("datastore not loaded")
	}

	// A product id the matcher really does resolve, so the test turns on the
	// guard rather than on the number failing to match anything.
	var tcgID, card string
	for _, u := range uuids {
		co, err := mtgmatcher.GetUUID(u)
		if err != nil {
			continue
		}
		id := co.Identifiers["tcgplayerProductId"]
		if id == "" {
			continue
		}
		if _, merr := mtgmatcher.MatchId(id); merr == nil {
			tcgID, card = id, co.Name
			break
		}
	}
	if tcgID == "" {
		t.Skip("no resolvable tcgplayer product id in the datastore")
	}

	t.Run("a ban: id is never read as a product id", func(t *testing.T) {
		got, ok := chartSearchID("ban:"+tcgID, nil)
		if ok {
			t.Errorf("chartSearchID(ban:%s) = %q/true, want it refused: "+
				"that number is our ban_id here, not %s", tcgID, got, card)
		}
	})

	// A target that resolved but could not name a row has already looked
	// everywhere; the raw string is the one thing that must not be retried.
	t.Run("a resolved target that names no row is final", func(t *testing.T) {
		target := &chartTarget{BanID: 42}
		got, ok := chartSearchID(tcgID, target)
		if ok || got != tcgID {
			t.Errorf("chartSearchID = %q/%v, want the id back with ok=false", got, ok)
		}
	})

	// Without a target there is no archive to have spoken, so a bare product
	// id still resolves the way a chartless deployment needs it to.
	t.Run("a bare product id still resolves with no target", func(t *testing.T) {
		got, ok := chartSearchID(tcgID, nil)
		if !ok || got == tcgID {
			t.Errorf("chartSearchID(%s) = %q/%v, want the matched card", tcgID, got, ok)
		}
	})
}
