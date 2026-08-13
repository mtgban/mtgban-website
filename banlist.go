package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// banlistURL is where Magic's ban history comes from: a chronological record
// of every change to every format's ban list since 1994, kept alongside the
// magic-search-engine index. It is hardcoded, and Magic's checkpoints are not
// editable, because a hand-written list only ever holds what someone
// remembered to add — the timeline it replaced was missing years of
// announcements and every Vintage restriction. Other games have no such
// source and keep the curated document.
const banlistURL = "https://raw.githubusercontent.com/taw/magic-search-engine/refs/heads/master/index/banlist_history.json"

// banlistFile is the document at banlistURL: format name to the announcements
// that touched it, oldest first.
type banlistFile map[string][]banlistEntry

// banlistEntry is one announcement for one format. A null date decodes to the
// empty string; those entries are the format's standing ban list rather than
// an event, and are only usable when the announcement url names a date.
type banlistEntry struct {
	Date string `json:"date"`
	URL  string `json:"url"`
	// Changes maps a card name to what the announcement did to it: "banned",
	// "restricted", "legal" (no longer either), and a few the chart ignores.
	Changes map[string]string `json:"changes"`
}

// banlistFormats are the formats whose announcements move prices enough to be
// worth a marker, mapped to the spelling shown on the chart. The document also
// covers Alchemy, Historic and a long tail of retired formats (block formats,
// unsets); charting a card's Tempest-block ban is noise, so anything absent
// here is dropped at load.
var banlistFormats = map[string]string{
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
// resolved to the marker the chart draws. The document also reports
// "specialized", "conjurable" and the two commander-specific bans; those are
// Alchemy mechanics or partial bans that no chart marker fits, and are
// dropped.
type banlistAction struct {
	Type    string // "ban" | "restrict" | "legal"
	Detail  string // "Banned", read as "Banned in Legacy"
	IconURL string
}

var banlistActions = map[string]banlistAction{
	"banned":     {Type: "ban", Detail: "Banned", IconURL: "/img/checkpoints/hammer.svg"},
	"restricted": {Type: "restrict", Detail: "Restricted", IconURL: "/img/checkpoints/restricted.svg"},
	// The document says only that a card is legal again, without
	// distinguishing an unban from an unrestriction — and both are true of
	// "legal" in the formats that restrict. Say what it says.
	"legal": {Type: "legal", Detail: "Legal", IconURL: "/img/checkpoints/unlock.svg"},
}

// banlistURLDate recovers the date of an entry that carries none from its
// announcement url, which ends in one ("...announcing-pioneer-2019-10-21").
// The dateless entries are format launches and standing lists; the launches
// have such a url, the standing lists have none and are skipped.
var banlistURLDate = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})$`)

// banlistVariantSuffix matches the per-variant letter the document appends to
// the Unfinity attractions ("Scavenger Hunt (a)" through "(f)"). Those are six
// printings of one card, named once in our datastore, so the suffix is dropped
// and the six identical markers collapse to one.
var banlistVariantSuffix = regexp.MustCompile(`\s+\([a-z]\)$`)

// banlistNames are the few cards the document spells differently from our
// datastore. Normalization closes most gaps on its own, but not this one: it
// drops every "s", so "Name Sticker" Goblin folds to nametickergoblin and can
// never meet the card it means.
var banlistNames = map[string]string{
	`"Name Sticker" Goblin`: "_____ Goblin",
}

// banlistYears bounds how far back the timeline is worth building. The
// document reaches 1994; a chart cannot show a marker older than its own data,
// and the index would otherwise carry three decades nobody looks at.
const banlistYears = 10

const banlistTimeout = 30 * time.Second

func banlistCardName(name string) string {
	name = banlistVariantSuffix.ReplaceAllString(name, "")
	if known, found := banlistNames[name]; found {
		return known
	}
	return name
}

// FormatEvent is a game-wide marker configured by hand: a format launch, the
// one thing no ban list reports. It lives in the config rather than the
// checkpoints document because Magic no longer reads that document, and it
// applies to Magic alone — every other game still says the same thing with a
// "format" event in its own document.
type FormatEvent struct {
	Date   string `json:"date"`
	Format string `json:"format"`
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
}

// banlistIndex is the loaded document turned inside out: one entry per card,
// since every chart asks about a single card and walking 350-odd
// announcements (some listing eighty cards) per render is wasted work. Keyed
// by normalized name so lookups need no case folding.
var banlistIndex atomic.Pointer[map[string][]ChartCheckpoint]

// reloadBanlist fetches the published ban list and swaps in a fresh index.
func reloadBanlist(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, banlistTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, banlistURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("banlist: %s returned %s", banlistURL, resp.Status)
	}

	var doc banlistFile
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	index := indexBanlist(doc)
	banlistIndex.Store(&index)

	var markers int
	for _, list := range index {
		markers += len(list)
	}
	log.Printf("checkpoints: %d cards, %d markers from the published ban list", len(index), markers)

	return nil
}

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
		format, charted := banlistFormats[strings.ToLower(rawFormat)]
		if !charted {
			continue
		}
		for _, entry := range entries {
			date := entry.Date
			if date == "" {
				date = banlistURLDate.FindString(strings.TrimRight(entry.URL, "/"))
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
					Title:   format + " B&R Announcement",
					Detail:  action.Detail + " in " + format,
					URL:     entry.URL,
					IconURL: action.IconURL,
				})
			}
		}
	}

	return out
}

// banlistCheckpoints returns the markers the published ban list holds for one
// card.
func banlistCheckpoints(cardName string, earliest time.Time) []ChartCheckpoint {
	index := banlistIndex.Load()
	if index == nil {
		return nil
	}
	earliestStr := earliest.Format("2006-01-02")

	// A ban list names the face it means — "Reflection of Kiki-Jiki" — while
	// the chart asks with the whole card, so look up each face too. An
	// announcement naming more than one face of the same card is still one
	// marker, hence the dedupe.
	names := []string{cardName}
	if strings.Contains(cardName, " // ") {
		names = append(names, strings.Split(cardName, " // ")...)
	}

	var out []ChartCheckpoint
	seen := map[ChartCheckpoint]bool{}
	for _, name := range names {
		for _, cp := range (*index)[mtgmatcher.Normalize(name)] {
			if cp.Date < earliestStr || seen[cp] {
				continue
			}
			seen[cp] = true
			out = append(out, cp)
		}
	}

	// Format launches are game-wide: every chart shows "Pioneer announced"
	// whatever card it is drawing.
	for _, ev := range Config.FormatEvents {
		if ev.Date < earliestStr {
			continue
		}
		out = append(out, ChartCheckpoint{
			Type:     "format",
			Date:     ev.Date,
			Title:    ev.Title,
			Detail:   formatDetail(ev.Format),
			URL:      ev.URL,
			IconText: ev.Format,
		})
	}

	return out
}
