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
//
// AllCards skips the per-card filter so the event lands on every chart — used
// for game-wide news like a format launch ("Pioneer announced") where the
// banned/unbanned card lists don't apply. Type "format" is implicitly AllCards.
type CheckpointEvent struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"` // "ban" | "format"
	Date          string   `json:"date"` // YYYY-MM-DD
	Format        string   `json:"format,omitempty"`
	Title         string   `json:"title"`
	URL           string   `json:"url,omitempty"`
	SetCode       string   `json:"set_code,omitempty"`
	AllCards      bool     `json:"all_cards,omitempty"`
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
// Format events carry an IconText (the format name, e.g. "Pioneer") which
// the frontend draws directly as the label content.
type ChartCheckpoint struct {
	Type        string `json:"type"`   // "ban" | "unban" | "release" | "reprint" | "format"
	Date        string `json:"date"`   // YYYY-MM-DD
	Title       string `json:"title"`  // headline, e.g. set name or ban announcement title
	Detail      string `json:"detail"` // sub-line, e.g. "Banned in Modern"
	URL         string `json:"url,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	IconText    string `json:"iconText,omitempty"`
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
	out = append(out, setCheckpointsFromEditions(cardName, earliest, printingSet)...)

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Date < out[j].Date
	})
	return out
}

// multiCardCheckpoints builds the shared checkpoint timeline for a multi-card
// chart by merging every card's relevant checkpoints into one axis: the union
// of bans/unbans and reprints across all cards, plus set releases. When cards
// resolve the same set on the same day, a reprint (a card was actually
// reprinted there) takes precedence over a plain release marker.
func multiCardCheckpoints(cardNames []string, earliest time.Time) []ChartCheckpoint {
	rank := func(t string) int {
		if t == "reprint" {
			return 1
		}
		return 0
	}
	setIdx := map[string]int{} // "date|title" -> index in out, collapses release/reprint dupes
	seen := map[string]bool{}  // full-identity dedup for bans/unbans/format
	var out []ChartCheckpoint

	for _, name := range cardNames {
		for _, cp := range relevantCheckpoints(name, earliest) {
			if cp.Type == "release" || cp.Type == "reprint" {
				key := cp.Date + "|" + cp.Title
				if i, ok := setIdx[key]; ok {
					if rank(cp.Type) > rank(out[i].Type) {
						out[i] = cp
					}
					continue
				}
				setIdx[key] = len(out)
				out = append(out, cp)
				continue
			}
			key := cp.Type + "|" + cp.Date + "|" + cp.Title + "|" + cp.Detail
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, cp)
		}
	}

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
			if ev.AllCards || containsFold(ev.CardsBanned, cardName) {
				out = append(out, ChartCheckpoint{
					Type:    "ban",
					Date:    ev.Date,
					Title:   ev.Title,
					Detail:  banDetail("Banned", ev.Format),
					URL:     ev.URL,
					IconURL: "/img/checkpoints/hammer.svg",
				})
			}
			if ev.AllCards || containsFold(ev.CardsUnbanned, cardName) {
				out = append(out, ChartCheckpoint{
					Type:    "unban",
					Date:    ev.Date,
					Title:   ev.Title,
					Detail:  banDetail("Unbanned", ev.Format),
					URL:     ev.URL,
					IconURL: "/img/checkpoints/unlock.svg",
				})
			}
		case "format":
			// Format-launch events are inherently all-cards: every chart
			// should see "Pioneer announced" regardless of which card the
			// user is viewing.
			out = append(out, ChartCheckpoint{
				Type:     "format",
				Date:     ev.Date,
				Title:    ev.Title,
				Detail:   formatDetail(ev.Format),
				URL:      ev.URL,
				IconText: ev.Format,
			})
		}
	}
	return out
}

// setCheckpointsFromEditions walks SealedEditionsList (the same registry that
// drove the keyrune-at-top renderer) and emits one checkpoint per set whose
// release falls inside the chart window. Sets in the card's own printing
// history become "reprint" markers; all others become "release" markers.
//
// SLD (Secret Lair Drop) and PLST (The List) are perpetually-updated sets
// where individual cards ship on their own dates, not the set's overall
// release date. For reprints in those sets we emit one checkpoint per
// distinct card release date so the marker lands where the card actually
// appeared, rather than collapsing every drop onto SLD's original 2019 date.
func setCheckpointsFromEditions(cardName string, earliest time.Time, printingSet map[string]bool) []ChartCheckpoint {
	sealedList := GetEditions().SealedEditionsList
	if sealedList == nil {
		return nil
	}
	now := time.Now()
	seen := map[string]bool{}
	var out []ChartCheckpoint

	// Collapse release markers to one per date, preferring the "main" set
	// when multiple sets land on the same day. Ranking is by MTGJSON set type
	// (expansion/core beats commander/promo/etc.) with set code as a stable
	// tiebreaker, so the choice is deterministic across requests. Reprints
	// stay independent so per-set reprint history isn't lost.
	type releasePick struct {
		cp       ChartCheckpoint
		priority int
		code     string
	}
	bestRelease := map[string]releasePick{}

	for _, entries := range sealedList {
		for _, e := range entries {
			if e.Code == "" || seen[e.Code] {
				continue
			}
			seen[e.Code] = true

			isReprint := printingSet[strings.ToUpper(e.Code)]

			if isReprint && (e.Code == "SLD" || e.Code == "PLST") {
				out = append(out, perCardSetCheckpoints(cardName, e, earliest, now)...)
				continue
			}

			if e.Date.IsZero() || e.Date.Before(earliest) || e.Date.After(now) {
				continue
			}

			cp := ChartCheckpoint{
				Date:        e.Date.Format("2006-01-02"),
				Title:       e.Name,
				KeyruneCode: e.Keyrune,
			}
			if isReprint {
				cp.Type = "reprint"
				cp.Detail = "Reprinted"
				out = append(out, cp)
				continue
			}

			cp.Type = "release"
			cp.Detail = "Set released"
			pri := releasePriority(e.Code)
			existing, ok := bestRelease[cp.Date]
			if !ok || pri > existing.priority || (pri == existing.priority && e.Code < existing.code) {
				bestRelease[cp.Date] = releasePick{cp: cp, priority: pri, code: e.Code}
			}
		}
	}
	for _, pick := range bestRelease {
		out = append(out, pick.cp)
	}
	return out
}

// releasePriority ranks a set's release marker so same-day candidates resolve
// to the "main" product. Higher wins. MTGJSON Set.Type buckets are the most
// reliable signal: expansion/core are full new-card sets, draft_innovation is
// a half-step down (Conspiracy/Battlebond/MH-style), and the rest (commander,
// promo, masters, starter, etc.) are typically companion products.
func releasePriority(code string) int {
	set, err := mtgmatcher.GetSet(code)
	if err != nil {
		return 0
	}
	switch set.Type {
	case "expansion":
		return 4
	case "core":
		return 3
	case "draft_innovation":
		return 2
	case "masters":
		return 1
	default:
		return 0
	}
}

// perCardSetCheckpoints emits a reprint checkpoint at each distinct date the
// card was printed in the given set. Falls back to the set's release date for
// printings that don't carry a per-card date in MTGJSON.
func perCardSetCheckpoints(cardName string, e EditionEntry, earliest, now time.Time) []ChartCheckpoint {
	cards := mtgmatcher.MatchInSet(cardName, e.Code)
	if len(cards) == 0 {
		return nil
	}

	setDateStr := ""
	if !e.Date.IsZero() {
		setDateStr = e.Date.Format("2006-01-02")
	}

	emitted := map[string]bool{}
	var out []ChartCheckpoint
	for _, card := range cards {
		dateStr := card.OriginalReleaseDate
		if dateStr == "" {
			dateStr = setDateStr
		}
		if dateStr == "" || emitted[dateStr] {
			continue
		}
		cardDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil || cardDate.Before(earliest) || cardDate.After(now) {
			continue
		}
		emitted[dateStr] = true
		out = append(out, ChartCheckpoint{
			Type:        "reprint",
			Date:        dateStr,
			Title:       e.Name,
			Detail:      "Reprinted",
			KeyruneCode: e.Keyrune,
		})
	}
	return out
}

func banDetail(action, format string) string {
	if format == "" {
		return action
	}
	return action + " in " + format
}

func formatDetail(format string) string {
	if format == "" {
		return "Format announced"
	}
	return format + " format announced"
}

func containsFold(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}
