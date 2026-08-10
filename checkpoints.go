package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/simplecloud"

	"github.com/mtgban/mtgban-website/internal/bucketstore"
)

// banlistFile is the upstream ban list: one chronological list of changes per
// format, keyed by the format's own lowercase name. It carries no titles or
// ids - the frontend composes a title from the format - and no notion of a
// format launch, which lives in the config instead.
type banlistFile map[string][]banlistEntry

// banlistEntry is one announcement for one format. A null date decodes to the
// empty string; those entries are the format's standing ban list rather than
// an event, and are only usable when the announcement url names a date.
type banlistEntry struct {
	Date string `json:"date"`
	URL  string `json:"url"`
	// Changes maps a card name to what the announcement did to it:
	// "banned", "restricted" or "legal" (no longer either).
	Changes map[string]string `json:"changes"`
}

// checkpointFormats are the formats whose announcements move prices enough to
// be worth a marker, mapped to the spelling shown on the chart. The upstream
// list also covers Alchemy and a long tail of retired or niche formats (block
// formats, unsets, two-headed giant); charting a card's Tempest-block ban is
// noise, so anything absent here is dropped at load.
var checkpointFormats = map[string]string{
	"standard":  "Standard",
	"pioneer":   "Pioneer",
	"modern":    "Modern",
	"legacy":    "Legacy",
	"vintage":   "Vintage",
	"pauper":    "Pauper",
	"commander": "Commander",
	"brawl":     "Brawl",
}

// banlistAction describes one card's fate in one announcement, already
// resolved to the marker the chart draws.
type banlistAction struct {
	Type    string // "ban" | "restrict" | "legal"
	Detail  string // "Banned in Legacy"
	IconURL string
}

var banlistActions = map[string]banlistAction{
	"banned":     {Type: "ban", Detail: "Banned", IconURL: "/img/checkpoints/hammer.svg"},
	"restricted": {Type: "restrict", Detail: "Restricted", IconURL: "/img/checkpoints/restricted.svg"},
	// The upstream list says only that a card is legal again, without
	// distinguishing an unban from an unrestriction - and both are true of
	// "legal" in the formats that restrict. Say what it says.
	"legal": {Type: "legal", Detail: "Legal", IconURL: "/img/checkpoints/unlock.svg"},
}

// banlistDateFromURL recovers the date of an entry that carries none from its
// announcement url, which ends in one ("...announcing-pioneer-format-2019-10-21").
// The dateless entries are format launches and standing lists; the launches
// have such a url, the standing lists have none and are skipped.
var banlistURLDate = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})$`)

// banlistVariantSuffix matches the per-variant letter the list appends to the
// Unfinity attractions ("Scavenger Hunt (a)" through "(f)"). Those are six
// printings of one card, named once in our datastore, so the suffix is dropped
// and the six identical markers collapse to one.
var banlistVariantSuffix = regexp.MustCompile(`\s+\([a-z]\)$`)

// banlistYears bounds how far back the timeline is worth building. The list
// reaches 1994; a chart cannot show a marker older than its own data, and the
// index would otherwise carry three decades nobody looks at.
const banlistYears = 10

func banlistDateFromURL(link string) string {
	return banlistURLDate.FindString(strings.TrimRight(link, "/"))
}

// banlistNames are the few cards the list spells differently from our
// datastore. Normalization closes most gaps on its own, but not this one: it
// drops every "s", so "Name Sticker" Goblin folds to nametickergoblin and can
// never meet the card it means.
var banlistNames = map[string]string{
	`"Name Sticker" Goblin`: "_____ Goblin",
}

func banlistCardName(name string) string {
	name = banlistVariantSuffix.ReplaceAllString(name, "")
	if known, found := banlistNames[name]; found {
		return known
	}
	return name
}

// FormatEvent is a curated, game-wide marker configured by hand: a format
// launch or similar, which no ban list reports. Every chart shows it.
type FormatEvent struct {
	Date   string `json:"date"`
	Format string `json:"format"`
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
}

type ChartCheckpoint struct {
	Type string `json:"type"` // "ban" | "restrict" | "legal" | "release" | "reprint" | "format"
	// Format names the format an announcement applies to, so the frontend can
	// compose the title the upstream ban list does not carry.
	Format      string `json:"format,omitempty"`
	Date        string `json:"date"`   // YYYY-MM-DD
	Title       string `json:"title"`  // headline, e.g. set name or ban announcement title
	Detail      string `json:"detail"` // sub-line, e.g. "Banned in Modern"
	URL         string `json:"url,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	IconText    string `json:"iconText,omitempty"`
	KeyruneCode string `json:"keyruneCode,omitempty"`
}

// checkpointsStore holds the checkpoints document. The bucket is built per
// operation, mirroring loadDatastore's URL-scheme switch with the datastore
// credentials, since the document lives on the same bucket as the datastore —
// reload/save are infrequent enough that the extra B2 auth round-trip is not
// worth a long-lived client.
var checkpointsStore = &bucketstore.Store[banlistFile]{
	Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
		cpPath := Config.Datastore.CheckpointsPath
		if cpPath == "" {
			return nil, "", errors.New("checkpoints_path not configured")
		}
		u, err := url.Parse(cpPath)
		if err != nil {
			return nil, "", err
		}
		switch u.Scheme {
		case "":
			return &simplecloud.FileBucket{}, cpPath, nil
		case "b2":
			bucket, err := simplecloud.NewB2Client(ctx, Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey, u.Host)
			return bucket, cpPath, err
		default:
			return nil, "", fmt.Errorf("unsupported checkpoints path scheme: %s", u.Scheme)
		}
	},
}

func reloadCheckpoints() error {
	if err := checkpointsStore.Load(context.Background()); err != nil {
		return err
	}
	events := indexBanlist(checkpointsStore.Get())
	banlistIndex.Store(&events)

	cpPath := Config.Datastore.CheckpointsPath
	source := "disk"
	if strings.HasPrefix(cpPath, "b2://") {
		source = "B2"
	}
	var markers int
	for _, list := range events {
		markers += len(list)
	}
	log.Printf("checkpoints: loaded %d cards, %d markers from %s (%s)", len(events), markers, cpPath, source)
	return nil
}

// banlistIndex is the loaded ban list turned inside out: one entry per card,
// since every chart asks about a single card and walking 350-odd
// announcements (some listing eighty cards) per render is wasted work. Keyed
// by normalized name so lookups need no case folding.
var banlistIndex atomic.Pointer[map[string][]ChartCheckpoint]

// indexBanlist flattens the document into per-card markers, dropping formats
// that are not charted and entries that cannot be placed on a timeline.
func indexBanlist(doc banlistFile) map[string][]ChartCheckpoint {
	cutoff := time.Now().AddDate(-banlistYears, 0, 0).Format("2006-01-02")

	out := map[string][]ChartCheckpoint{}
	// One announcement can name the same card several times once the variant
	// suffixes are stripped, and that is one marker, not six.
	type marker struct{ card, date, format, kind string }
	seen := map[marker]bool{}

	for rawFormat, entries := range doc {
		format, charted := checkpointFormats[strings.ToLower(rawFormat)]
		if !charted {
			continue
		}
		for _, entry := range entries {
			date := entry.Date
			if date == "" {
				date = banlistDateFromURL(entry.URL)
			}
			if date == "" || date < cutoff {
				continue
			}
			for card, rawAction := range entry.Changes {
				action, known := banlistActions[strings.ToLower(rawAction)]
				if !known {
					continue
				}
				key := mtgmatcher.Normalize(banlistCardName(card))
				m := marker{key, date, format, action.Type}
				if seen[m] {
					continue
				}
				seen[m] = true
				out[key] = append(out[key], ChartCheckpoint{
					Type:    action.Type,
					Date:    date,
					Format:  format,
					Detail:  action.Detail + " in " + format,
					URL:     entry.URL,
					IconURL: action.IconURL,
				})
			}
		}
	}
	return out
}

// saveCheckpoints pushes the document to the bucket and, on success, atomically
// swaps the in-memory cache and its index.
func saveCheckpoints(ctx context.Context, doc banlistFile) error {
	if err := checkpointsStore.Save(ctx, doc); err != nil {
		return err
	}
	events := indexBanlist(doc)
	banlistIndex.Store(&events)
	return nil
}

// currentCheckpointsJSON returns the in-memory document serialized as JSON,
// for display in the admin editor.
func currentCheckpointsJSON() (string, error) {
	return checkpointsStore.JSON()
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
	earliestStr := earliest.Format("2006-01-02")
	var out []ChartCheckpoint

	if idx := banlistIndex.Load(); idx != nil {
		// A ban list names the face it means - "Reflection of Kiki-Jiki" -
		// while the chart asks with the whole card, so look up each face too.
		// An announcement naming more than one face of the same card is still
		// one marker, hence the dedupe.
		names := []string{cardName}
		if strings.Contains(cardName, " // ") {
			names = append(names, strings.Split(cardName, " // ")...)
		}
		seen := map[ChartCheckpoint]bool{}
		for _, name := range names {
			for _, cp := range (*idx)[mtgmatcher.Normalize(name)] {
				if cp.Date < earliestStr || seen[cp] {
					continue
				}
				seen[cp] = true
				out = append(out, cp)
			}
		}
	}

	// Format launches are game-wide: every chart should see "Pioneer
	// announced" regardless of which card the user is viewing.
	for _, ev := range Config.FormatEvents {
		if ev.Date < earliestStr {
			continue
		}
		out = append(out, ChartCheckpoint{
			Type:     "format",
			Date:     ev.Date,
			Format:   ev.Format,
			Title:    ev.Title,
			Detail:   formatDetail(ev.Format),
			URL:      ev.URL,
			IconText: ev.Format,
		})
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

func formatDetail(format string) string {
	if format == "" {
		return "Format announced"
	}
	return format + " format announced"
}
