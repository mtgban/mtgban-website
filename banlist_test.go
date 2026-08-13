package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func loadBanlistFixture(t *testing.T) map[string][]ChartCheckpoint {
	t.Helper()

	blob, err := os.ReadFile("testdata/banlist_history.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc banlistFile
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}

	return indexBanlist(doc)
}

// TestIndexBanlist covers what the published document asks of the reader: the
// formats worth charting, the entries that can be dated, the names that need
// work, and the actions no marker fits.
func TestIndexBanlist(t *testing.T) {
	index := loadBanlistFixture(t)

	// Keyed the way the index is, through the matcher's own normalization —
	// which drops every "s" among other things, so the keys are not the names.
	for _, tc := range []struct {
		name, card string
		want       int
		why        string
	}{
		{"banned and restricted in two formats", "Sowing Mycospawn", 2, ""},
		{"legal again", "Karn, the Great Creator", 1, ""},
		{"outside the ten year cutoff", "Black Lotus", 0, "the announcement is from 1999"},
		{"an uncharted format", "Scavenger Hunt", 1, "unsets is dropped, pauper is not, and the variants collapse"},
		{"a name the list spells its own way", `"Name Sticker" Goblin`, 1, ""},
		{"an action with no marker", "Some Card", 0, "specialized is an Alchemy mechanic"},
		{"a dateless entry with a dated url", "Launch Card", 1, ""},
		{"a dateless entry with no date anywhere", "Standing Card", 0, "a standing ban list is not an event"},
	} {
		got := len(index[mtgmatcher.Normalize(banlistCardName(tc.card))])
		if got != tc.want {
			t.Errorf("%s: %q has %d markers, want %d %s", tc.name, tc.card, got, tc.want, tc.why)
		}
	}

	// The two announcements for one card should say what each format did.
	var details []string
	for _, cp := range index[mtgmatcher.Normalize("Sowing Mycospawn")] {
		details = append(details, cp.Detail)
	}
	want := map[string]bool{"Banned in Legacy": true, "Restricted in Vintage": true}
	for _, d := range details {
		if !want[d] {
			t.Errorf("unexpected detail %q", d)
		}
	}
	if len(details) != len(want) {
		t.Errorf("got details %q, want %d distinct", details, len(want))
	}
}

// TestBanlistCheckpointsFaces checks the two things a lookup has to do beyond
// reading the map: honour the chart's window, and find a card whose ban names
// only one of its faces.
func TestBanlistCheckpointsFaces(t *testing.T) {
	index := loadBanlistFixture(t)
	banlistIndex.Store(&index)
	defer banlistIndex.Store(nil)

	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := banlistCheckpoints("Sowing Mycospawn", old); len(got) != 2 {
		t.Errorf("whole card: got %d markers, want 2", len(got))
	}
	// The document banned "Reflection of Kiki-Jiki"; the chart asks with the
	// whole card.
	if got := banlistCheckpoints("Kiki-Jiki, Mirror Breaker // Reflection of Kiki-Jiki", old); len(got) != 1 {
		t.Errorf("back face: got %d markers, want 1", len(got))
	}

	recent := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if got := banlistCheckpoints("Sowing Mycospawn", recent); len(got) != 0 {
		t.Errorf("outside the window: got %d markers, want 0", len(got))
	}
}
