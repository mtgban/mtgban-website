package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A card reprinted on one day in sets of different categories gets a marker
// per set, and callers sort markers by date alone. The sets were read from a
// map of categories, so those markers came in a different order per request:
// a hundred requests all but ensure a wrong one if nothing else orders them.
func TestSameDayCheckpointsKeepOneOrder(t *testing.T) {
	const name = "Fixture Reprint"
	b := &mtgmatcher.Backend{
		UUIDs: map[string]*mtgmatcher.CardObject{
			"REPRINT-1": {Card: mtgmatcher.Card{
				UUID:      "REPRINT-1",
				Name:      name,
				Printings: []string{"AAA", "BBB", "CCC", "DDD"},
			}},
		},
		Hashes: map[string][]string{mtgmatcher.Normalize(name): {"REPRINT-1"}},
	}
	day := time.Date(2024, 2, 9, 0, 0, 0, 0, time.UTC)
	edition := func(name, code string) EditionEntry {
		return EditionEntry{Name: name, Code: code, Date: day, Keyrune: strings.ToLower(code)}
	}
	ds := &datastore{
		backend: b,
		editions: &editionsSnapshot{SealedEditionsList: map[string][]EditionEntry{
			"Expansions":  {edition("Set A", "AAA"), edition("Set E", "EEE")},
			"Commander":   {edition("Set B", "BBB")},
			"Masters":     {edition("Set C", "CCC")},
			"Promotional": {edition("Set D", "DDD")},
		}},
	}

	// The reprints by set, then the release of the one set the card is not in.
	want := []string{"reprint Set A", "reprint Set B", "reprint Set C", "reprint Set D", "release Set E"}
	for range 100 {
		var got []string
		for _, cp := range relevantCheckpoints(ds, name, day.AddDate(-1, 0, 0)) {
			got = append(got, cp.Type+" "+cp.Title)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("markers in order %v, want %v", got, want)
		}
	}
}
