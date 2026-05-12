package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/simplecloud"
)

// CheckpointEvent is one record as authored in checkpoints.json. A single event
// can fan out into multiple ChartCheckpoint annotations (e.g. a ban announcement
// affecting several cards or carrying both banned and unbanned lists).
type CheckpointEvent struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"` // "ban" | "release"
	Date          string   `json:"date"` // YYYY-MM-DD
	Format        string   `json:"format,omitempty"`
	Title         string   `json:"title"`
	URL           string   `json:"url,omitempty"`
	SetCode       string   `json:"set_code,omitempty"`
	CardsBanned   []string `json:"cards_banned,omitempty"`
	CardsUnbanned []string `json:"cards_unbanned,omitempty"`
}

type checkpointsFile struct {
	Events []CheckpointEvent `json:"events"`
}

// ChartCheckpoint is the per-chart annotation shape sent to the frontend.
// One record == one vertical line on the chart.
//
// Bans/unbans carry an IconURL pointing to a local white-stroked SVG.
// Releases/reprints carry a KeyruneCode so the frontend can render the set
// glyph from the Keyrune font (already loaded for the search page) — that
// avoids fetching and recoloring external SVGs at render time.
type ChartCheckpoint struct {
	Type        string `json:"type"`   // "ban" | "unban" | "release" | "reprint"
	Date        string `json:"date"`   // YYYY-MM-DD
	Title       string `json:"title"`  // headline, e.g. set name or ban announcement title
	Detail      string `json:"detail"` // sub-line, e.g. "Banned in Modern"
	URL         string `json:"url,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	KeyruneCode string `json:"keyruneCode,omitempty"`
}

var (
	checkpointsMu     sync.RWMutex
	checkpointsLoaded []CheckpointEvent
)

// newCheckpointsBucket builds a fresh bucket client for the checkpoints
// document. Mirrors loadDatastore's URL-scheme switch and uses
// Config.Datastore credentials, since the document lives on the same bucket
// as the datastore. Called per operation rather than hoisted to a global —
// reload/save are infrequent enough that the extra B2 auth round-trip is
// not worth a long-lived client.
func newCheckpointsBucket(ctx context.Context) (simplecloud.ReadWriter, error) {
	if Config.Datastore.CheckpointsPath == "" {
		return nil, errors.New("checkpoints_path not configured")
	}
	u, err := url.Parse(Config.Datastore.CheckpointsPath)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "":
		return &simplecloud.FileBucket{}, nil
	case "b2":
		return simplecloud.NewB2Client(ctx, Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey, u.Host)
	default:
		return nil, fmt.Errorf("unsupported checkpoints path scheme: %s", u.Scheme)
	}
}

func reloadCheckpoints() error {
	ctx := context.Background()
	bucket, err := newCheckpointsBucket(ctx)
	if err != nil {
		return err
	}
	cpPath := Config.Datastore.CheckpointsPath
	reader, err := simplecloud.InitReader(ctx, bucket, cpPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var parsed checkpointsFile
	if err := json.NewDecoder(reader).Decode(&parsed); err != nil {
		return err
	}
	checkpointsMu.Lock()
	checkpointsLoaded = parsed.Events
	checkpointsMu.Unlock()
	source := "disk"
	if strings.HasPrefix(cpPath, "b2://") {
		source = "B2"
	}
	log.Printf("checkpoints: loaded %d events from %s (%s)", len(parsed.Events), cpPath, source)
	return nil
}

// writeCheckpointsFile serializes events to writer using the same pretty-print
// settings as writeConfigFile (4-space indent, no HTML escaping) so manual
// diffs stay readable.
func writeCheckpointsFile(events []CheckpointEvent, w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	return e.Encode(&checkpointsFile{Events: events})
}

// saveCheckpoints pushes events to B2 and, on success, atomically swaps the
// in-memory cache. We serialize into a buffer first so JSON encoding errors
// don't leave a half-written object on B2.
func saveCheckpoints(ctx context.Context, events []CheckpointEvent) error {
	bucket, err := newCheckpointsBucket(ctx)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := writeCheckpointsFile(events, &buf); err != nil {
		return err
	}

	cpPath := Config.Datastore.CheckpointsPath
	writer, err := simplecloud.InitWriter(ctx, bucket, cpPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(writer, &buf); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	checkpointsMu.Lock()
	checkpointsLoaded = events
	checkpointsMu.Unlock()
	return nil
}

// currentCheckpointsJSON returns the in-memory document serialized as JSON,
// for display in the admin editor. Never returns nil — an empty store still
// produces a valid `{"events": []}` document.
func currentCheckpointsJSON() (string, error) {
	checkpointsMu.RLock()
	events := checkpointsLoaded
	checkpointsMu.RUnlock()

	var buf bytes.Buffer
	if err := writeCheckpointsFile(events, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// relevantCheckpoints returns the checkpoint markers that apply to a chart for
// the given card. Bans are curated; releases and reprints both come from
// SealedEditionsList — the same source that used to feed the keyrune-at-top
// renderer — so the two systems can't drift apart.
func relevantCheckpoints(cardName string, earliest time.Time) []ChartCheckpoint {
	if cardName == "" {
		return nil
	}

	printingSet := map[string]bool{}
	if codes, err := mtgmatcher.Printings4Card(cardName); err == nil {
		for _, c := range codes {
			printingSet[strings.ToUpper(c)] = true
		}
	}

	out := curatedCheckpoints(cardName, earliest)
	out = append(out, setCheckpointsFromEditions(earliest, printingSet)...)

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Date < out[j].Date
	})
	return out
}

func curatedCheckpoints(cardName string, earliest time.Time) []ChartCheckpoint {
	checkpointsMu.RLock()
	events := checkpointsLoaded
	checkpointsMu.RUnlock()

	earliestStr := earliest.Format("2006-01-02")
	var out []ChartCheckpoint

	for _, ev := range events {
		if ev.Date < earliestStr {
			continue
		}
		switch ev.Type {
		case "ban":
			if containsFold(ev.CardsBanned, cardName) {
				out = append(out, ChartCheckpoint{
					Type:    "ban",
					Date:    ev.Date,
					Title:   ev.Title,
					Detail:  banDetail("Banned", ev.Format),
					URL:     ev.URL,
					IconURL: "/img/checkpoints/hammer.svg",
				})
			}
			if containsFold(ev.CardsUnbanned, cardName) {
				out = append(out, ChartCheckpoint{
					Type:    "unban",
					Date:    ev.Date,
					Title:   ev.Title,
					Detail:  banDetail("Unbanned", ev.Format),
					URL:     ev.URL,
					IconURL: "/img/checkpoints/unlock.svg",
				})
			}
		}
	}
	return out
}

// setCheckpointsFromEditions walks SealedEditionsList (the same registry that
// drove the keyrune-at-top renderer) and emits one checkpoint per set whose
// release falls inside the chart window. Sets in the card's own printing
// history become "reprint" markers; all others become "release" markers.
func setCheckpointsFromEditions(earliest time.Time, printingSet map[string]bool) []ChartCheckpoint {
	if SealedEditionsList == nil {
		return nil
	}
	now := time.Now()
	seen := map[string]bool{}
	var out []ChartCheckpoint
	for _, entries := range SealedEditionsList {
		for _, e := range entries {
			if e.Code == "" || seen[e.Code] {
				continue
			}
			if e.Date.IsZero() || e.Date.Before(earliest) || e.Date.After(now) {
				continue
			}
			seen[e.Code] = true

			cp := ChartCheckpoint{
				Date:        e.Date.Format("2006-01-02"),
				Title:       e.Name,
				KeyruneCode: e.Keyrune,
			}
			if printingSet[strings.ToUpper(e.Code)] {
				cp.Type = "reprint"
				cp.Detail = "Reprinted"
			} else {
				cp.Type = "release"
				cp.Detail = "Set released"
			}
			out = append(out, cp)
		}
	}
	return out
}

func banDetail(action, format string) string {
	if format == "" {
		return action
	}
	return action + " in " + format
}

func containsFold(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}
