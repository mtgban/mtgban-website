package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/bucketstore"
	"github.com/mtgban/simplecloud"
)

// A card reprinted on one day in sets of different categories gets a marker
// per set, and callers sort markers by date alone. The sets were read from a
// map of categories, so those markers came in a different order per request:
// a hundred requests all but ensure a wrong one if nothing else orders them.
func TestSameDayCheckpointsKeepOneOrder(t *testing.T) {
	const name = "Fixture Reprint"
	b := &matcher.Backend{
		UUIDs: map[string]*matcher.CardObject{
			"REPRINT-1": {Card: matcher.Card{
				UUID:      "REPRINT-1",
				Name:      name,
				Printings: []string{"AAA", "BBB", "CCC", "DDD"},
			}},
		},
		Hashes: map[string][]string{matcher.Normalize(name): {"REPRINT-1"}},
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

// A game with no checkpoints_path reads nothing, so the cron has nothing to
// report, and saving is refused rather than sent nowhere.
func TestCheckpointsNoPathReadsNothing(t *testing.T) {
	withConfigCopy(t)
	Config().Game = "lorcana"
	Config().CheckpointsPath = ""
	saved, savedDoc := checkpointsStore.Bucket, checkpointsStore.Get()
	t.Cleanup(func() {
		checkpointsStore.Bucket = saved
		checkpointsStore.Set(savedDoc)
	})
	checkpointsStore.Set(checkpointsFile{Events: []CheckpointEvent{{ID: "dropped"}}})
	checkpointsStore.Bucket = func(context.Context) (simplecloud.ReadWriter, string, error) {
		t.Error("the store asked for a bucket with no path set")
		return nil, "", errors.New("no path")
	}

	err := reloadCheckpoints()
	if err != nil {
		t.Errorf("reload with no path: %v", err)
	}
	if events := checkpointsStore.Get().Events; len(events) != 0 {
		t.Errorf("reload with no path kept %+v", events)
	}
	err = saveCheckpoints(context.Background(), []CheckpointEvent{{ID: "launch"}})
	if err == nil {
		t.Error("save with no path succeeded")
	}
	text, err := currentCheckpointsJSON()
	if err != nil || text != "" {
		t.Errorf("editor text with no path = %q, %v; want none", text, err)
	}
}

// A save is what the next reload reads, from where checkpoints_path says.
func TestCheckpointsSavedThenReloaded(t *testing.T) {
	withConfigCopy(t)
	Config().Game = "lorcana"
	Config().CheckpointsPath = filepath.Join(t.TempDir(), "checkpoints.json")
	savedDoc := checkpointsStore.Get()
	t.Cleanup(func() { checkpointsStore.Set(savedDoc) })
	err := reloadCheckpoints()
	if err != nil {
		t.Fatal(err)
	}

	event := CheckpointEvent{ID: "launch", Type: "format", Date: "2026-10-01", Title: "Launch"}
	err = saveCheckpoints(context.Background(), []CheckpointEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	checkpointsStore.Set(checkpointsFile{})
	err = reloadCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	events := checkpointsStore.Get().Events
	if len(events) != 1 || events[0].ID != "launch" {
		t.Errorf("reloaded %+v from %s, want the saved event", events, Config().CheckpointsPath)
	}
}

// Neither editor saves over a document its store never read from the bucket.
func TestCheckpointAndOverrideSavesRefusedUntilRead(t *testing.T) {
	withConfigCopy(t)
	Config().Game = "lorcana"
	Config().CheckpointsPath = filepath.Join(t.TempDir(), "checkpoints.json")
	koPath := filepath.Join(t.TempDir(), keyOverridesFile)
	savedCP, savedKO := checkpointsStore, keyOverridesStore
	t.Cleanup(func() { checkpointsStore, keyOverridesStore = savedCP, savedKO })
	checkpointsStore = &bucketstore.Store[checkpointsFile]{Bucket: savedCP.Bucket}
	keyOverridesStore = &bucketstore.Store[KeyOverrides]{
		Bucket: func(context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, koPath, nil
		},
	}
	events := []CheckpointEvent{{ID: "launch"}}

	err := saveCheckpoints(context.Background(), events)
	if !errors.Is(err, errCheckpointsUnread) {
		t.Errorf("checkpoints save before a read = %v, want %v", err, errCheckpointsUnread)
	}
	err = saveKeyOverrides(KeyOverrides{})
	if !errors.Is(err, errKeyOverridesUnread) {
		t.Errorf("key overrides save before a read = %v, want %v", err, errKeyOverridesUnread)
	}

	err = errors.Join(reloadCheckpoints(), loadKeyOverrides())
	if err != nil {
		t.Fatal(err)
	}
	err = errors.Join(saveCheckpoints(context.Background(), events), saveKeyOverrides(KeyOverrides{}))
	if err != nil {
		t.Errorf("save after a read: %v", err)
	}
}
