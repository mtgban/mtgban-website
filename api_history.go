package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

// historyBudget is the card-months one history request may cover, a card
// being one printing in one finish: the read costs about 20 ms per card
// per month of range cold, whatever its shape.
const historyBudget = 120

// historyMonths is a range in 30-day months, rounded to the nearest, at least one.
func historyMonths(days int) int {
	months := (days + 15) / 30
	if months < 1 {
		months = 1
	}
	return months
}

// historyCardsAllowed is how many cards one request over days may cover.
func historyCardsAllowed(days int) int {
	cards := historyBudget / historyMonths(days)
	if cards < 1 {
		cards = 1
	}
	return cards
}

// historyWriteWindow is how long after a write hour a write may still be running.
const historyWriteWindow = 30 * time.Minute

// historyWriteGrace is the max-age served inside that window.
const historyWriteGrace = 60 * time.Second

// historyMaxAge is the seconds until the next archive write at one of hours
// on the host clock, at least a minute, and a minute just after one.
func historyMaxAge(now time.Time, hours []int) int {
	hours = slices.Sorted(slices.Values(hours))
	if len(hours) == 0 {
		hours = []int{0}
	}
	y, m, d := now.Date()
	// cmd/tcgcsvd and a blue-green deploy's other instance write unseen by this process.
	for _, h := range hours {
		if at := time.Date(y, m, d, h, 0, 0, 0, now.Location()); !now.Before(at) && now.Sub(at) < historyWriteWindow {
			return int(historyWriteGrace.Seconds())
		}
	}
	next := time.Date(y, m, d+1, hours[0], 0, 0, 0, now.Location())
	for _, h := range hours {
		if at := time.Date(y, m, d, h, 0, 0, 0, now.Location()); now.Before(at) {
			next = at
			break
		}
	}
	secs := int(next.Sub(now).Seconds())
	if secs < 60 {
		secs = 60
	}
	return secs
}

// historyCacheHours are the archive's write hours: the snapshot, and the tcgcsv ingest off Magic.
func historyCacheHours() []int {
	if Config().Game == DefaultGame {
		return []int{0, 12}
	}
	return []int{0, 12, 21}
}

// historyStashing reports an archive write in progress, a variable so tests can swap it.
var historyStashing = func() bool { return IsStashingInProgress() || IsTCGCSVStashing() }

// historyKey is where a provider's series is filed: the section and store key.
type historyKey struct {
	Section string
	Key     string
}

// historyKeyTable is the current provider-to-key table, published whole by
// buildProviderRegistry.
var historyKeyTable atomic.Pointer[map[int16]historyKey]

// historyKeys is the current provider-to-key table, the defaults before startup.
func historyKeys() map[int16]historyKey {
	table := historyKeyTable.Load()
	if table == nil {
		return historyDefaultKeys
	}
	return *table
}

// historyDefaultKeys is the provider-to-key table docs/api-v2-history.md promises.
var historyDefaultKeys = defaultHistoryKeys()

// defaultHistoryKeys files each seeded provider under its history key, a buylist one under buylist.
func defaultHistoryKeys() map[int16]historyKey {
	keys := map[int16]historyKey{}
	for _, p := range timeseries.Providers() {
		section := "retail"
		if p.Kind == "buylist" {
			section = "buylist"
		}
		keys[p.ID] = historyKey{section, p.HistoryKey}
	}
	return keys
}

// buildHistoryKeys starts from historyDefaultKeys; a dataset with a provider
// id re-keys it to its list's first non-sealed tag. The overrides are read
// first and checked against the table they make together, so dataset order
// cannot refuse a key its holder is moving off; a key two overrides want
// goes to the first, and one a staying provider holds is refused and logged.
func buildHistoryKeys(datasets []DatasetConfig) map[int16]historyKey {
	type override struct {
		provider int16
		key      historyKey
	}
	var wants []override
	moving := map[int16]bool{}
	for _, d := range datasets {
		if d.Provider == 0 || moving[d.Provider] {
			continue
		}
		section, list := "retail", d.Retail
		if len(list) == 0 {
			section, list = "buylist", d.Buylist
		}
		if len(list) == 0 {
			continue
		}
		key := list[0]
		for _, tag := range list {
			if !strings.HasSuffix(tag, "Sealed") {
				key = tag
				break
			}
		}
		moving[d.Provider] = true
		wants = append(wants, override{d.Provider, historyKey{section, key}})
	}
	// a refused provider keeps its default, which may refuse an earlier
	// override in turn, so start over until a pass refuses nothing
	refused := map[int16]bool{}
	for {
		keys := maps.Clone(historyDefaultKeys)
		taken := map[historyKey]int16{}
		for id, k := range keys {
			if !moving[id] || refused[id] {
				taken[k] = id
			}
		}
		clean := true
		for _, w := range wants {
			if refused[w.provider] {
				continue
			}
			if owner, ok := taken[w.key]; ok {
				log.Printf("history: provider %d key %s/%s already taken by provider %d, skipped", w.provider, w.key.Section, w.key.Key, owner)
				refused[w.provider] = true
				clean = false
				break
			}
			taken[w.key] = w.provider
			keys[w.provider] = w.key
		}
		if clean {
			return keys
		}
	}
}

// historyCard is one printing in one finish, with the archive id it reads by.
type historyCard struct {
	ID     string
	Finish string
	BanID  int64
}

// historySeries is one store's series: parallel arrays, oldest first.
type historySeries struct {
	Dates  []string  `json:"dates"`
	Prices []float64 `json:"prices"`
}

// historyCards is a section: card id, then finish, then store key.
type historyCards map[string]map[string]map[string]*historySeries

// historyPivot files the rows read for cards under their id, finish and
// store key, dates ascending, and reports the newest date seen.
func historyPivot(cards []historyCard, rows map[int64]map[string]timeseries.ProviderPrices, keys map[int16]historyKey) (retail, buylist historyCards, latest string) {
	retail, buylist = historyCards{}, historyCards{}
	// leaf-by-leaf day -> price, so two ban ids on one leaf merge
	type leaf struct{ section, id, finish, key string }
	points := map[leaf]map[string]float64{}
	for _, card := range cards {
		for day, pp := range rows[card.BanID] {
			// buildHistoryKeys gives no two providers one key, so this order picks no price.
			for provider, price := range pp {
				k, ok := keys[provider]
				if !ok {
					continue
				}
				l := leaf{k.Section, card.ID, card.Finish, k.Key}
				if points[l] == nil {
					points[l] = map[string]float64{}
				}
				// a later row for the same day wins
				points[l][day] = price
				if day > latest {
					latest = day
				}
			}
		}
	}
	for l, days := range points {
		dates := make([]string, 0, len(days))
		for day := range days {
			dates = append(dates, day)
		}
		sort.Strings(dates)
		series := &historySeries{Dates: dates, Prices: make([]float64, 0, len(dates))}
		for _, day := range dates {
			series.Prices = append(series.Prices, days[day])
		}
		section := retail
		if l.section == "buylist" {
			section = buylist
		}
		if section[l.id] == nil {
			section[l.id] = map[string]map[string]*historySeries{}
		}
		if section[l.id][l.finish] == nil {
			section[l.id][l.finish] = map[string]*historySeries{}
		}
		section[l.id][l.finish][l.key] = series
	}
	return retail, buylist, latest
}

// historySince is the first of the last days calendar days, today included, at midnight on now's clock.
func historySince(now time.Time, days int) time.Time {
	y, m, d := now.Date()
	return time.Date(y, m, d-(days-1), 0, 0, 0, 0, now.Location())
}

// historyRead is the archive read, a variable so tests run without a database.
var historyRead = func(ctx context.Context, banIDs []int64, since time.Time) (map[int64]map[string]timeseries.ProviderPrices, error) {
	if PricesArchiveDB == nil {
		return nil, errors.New("history: no price archive")
	}
	return PricesArchiveDB.HGetAllByBanIDs(ctx, banIDs, since)
}

// historyBanID maps a card to its archive id, a variable for the same reason.
var historyBanID = cachedBanIDForCard

// historyConcurrency caps concurrent history reads per host, like the chart roster.
const historyConcurrency = 4

var historySlots = make(chan struct{}, historyConcurrency)

// historySlotWait bounds the wait for a read slot before a 503, a variable for tests.
var historySlotWait = 5 * time.Second

// historyMeta describes a history response.
type historyMeta struct {
	Date    time.Time `json:"date"`
	Version string    `json:"version"`
	BaseURL string    `json:"base_url"`
	Latest  string    `json:"latest"`
	Range   int       `json:"range"`
	Page    int       `json:"page,omitempty"`
	Pages   int       `json:"pages,omitempty"`
}

// historyOutput is the wire shape: meta, then retail and buylist sections.
type historyOutput struct {
	Meta    historyMeta  `json:"meta"`
	Retail  historyCards `json:"retail,omitempty"`
	Buylist historyCards `json:"buylist,omitempty"`
}

// historyFinishes resolves an id to the card objects of its finishes, as the
// v1 and v2 price APIs do: every finish the printing or its finish twins are sold in.
func historyFinishes(b *mtgmatcher.Backend, id string) []*mtgmatcher.CardObject {
	var out []*mtgmatcher.CardObject
	for _, uuid := range finishUUIDs(b, id) {
		if co, err := b.GetUUID(uuid); err == nil {
			out = append(out, co)
		}
	}
	return out
}

// historyCardsOf turns card objects into the cards the pivot files, keyed by
// the id mode (scryfall for singles and mtgjson for sealed by default), and
// leaves out what the mode has no id for, as v2 prices do, or the variant
// cache does not know.
func historyCardsOf(b *mtgmatcher.Backend, idMode string, cos []*mtgmatcher.CardObject) ([]historyCard, []int64) {
	var cards []historyCard
	var banIDs []int64
	for _, co := range cos {
		banID := historyBanID(co)
		if banID == 0 {
			continue
		}
		mode := idMode
		if mode == "" {
			mode = "scryfall"
			if co.Sealed {
				mode = "mtgjson"
			}
		}
		id := getIDFromMode(b, mode, co)
		if id == "" {
			continue
		}
		cards = append(cards, historyCard{ID: id, Finish: v2Finish(co), BanID: banID})
		if !slices.Contains(banIDs, banID) {
			banIDs = append(banIDs, banID)
		}
	}
	return cards, banIDs
}

// historyLookback is the key's APIlookback in days, 30 without one, the package's in dev.
func historyLookback(sig string) int {
	if DevMode && !SigCheck {
		if p, ok := apiProducts.Package("history"); ok && p.LookbackDays > 0 {
			return p.LookbackDays
		}
		return 365
	}
	days, err := strconv.Atoi(GetParamFromSig(sig, "APIlookback"))
	if err != nil || days <= 0 {
		return 30
	}
	return days
}

// historyCSVHeader is the CSV form's header row.
var historyCSVHeader = []string{"id", "finish", "store", "section", "date", "price"}

// historyCSV flattens the pivot to rows by id, finish, store and date, retail before buylist.
func historyCSV(retail, buylist historyCards) ([]byte, error) {
	type series struct {
		id, finish, store, section string
		points                     *historySeries
	}
	var all []series
	for _, section := range []struct {
		name  string
		cards historyCards
	}{{"retail", retail}, {"buylist", buylist}} {
		for id, finishes := range section.cards {
			for finish, stores := range finishes {
				for store, points := range stores {
					all = append(all, series{id, finish, store, section.name, points})
				}
			}
		}
	}
	slices.SortFunc(all, func(a, b series) int {
		// the sections reversed, so retail comes before buylist
		return cmp.Or(cmp.Compare(a.id, b.id), cmp.Compare(a.finish, b.finish), cmp.Compare(a.store, b.store), cmp.Compare(b.section, a.section))
	})
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.Write(historyCSVHeader)
	for _, s := range all {
		for i, date := range s.points.Dates {
			cw.Write([]string{s.id, s.finish, s.store, s.section, date, strconv.FormatFloat(s.points.Prices[i], 'f', -1, 64)})
		}
	}
	cw.Flush()
	return buf.Bytes(), cw.Error()
}

// etagMatches reports whether an If-None-Match header names etag, compared weakly (RFC 7232).
func etagMatches(header, etag string) bool {
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || tag != "" && strings.TrimPrefix(tag, "W/") == etag {
			return true
		}
	}
	return false
}

// historyZeroDate is meta.date as marshalled before the real date is spliced in.
var historyZeroDate = []byte(`"date":"0001-01-01T00:00:00Z"`)

// historyError answers an error with its status and no caching.
func historyError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	errorResponse(w, status, msg)
}

// HistoryAPI serves /api/v2/history/: one card's, a batch's or a set page's
// daily prices from the archive, by finish and store key, within the plan's
// lookback, in JSON or CSV. The forms, the budget and the shape are in
// docs/api-v2-history.md.
func (s *site) HistoryAPI(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	sig := r.FormValue("sig")
	if !canAccessMode(strings.Split(GetParamFromSig(sig, "APImode"), ","), "history") {
		historyError(w, http.StatusForbidden, "plan does not include history")
		return
	}
	urlPath := strings.TrimPrefix(r.URL.Path, "/api/v2/history/")
	rest, asCSV := strings.CutSuffix(urlPath, ".csv")
	if !asCSV {
		var isJSON bool
		if rest, isJSON = strings.CutSuffix(urlPath, ".json"); !isJSON {
			historyError(w, http.StatusNotFound, "Not found")
			return
		}
	}
	idMode := r.FormValue("id")
	if idMode != "" && !slices.Contains(v2IDModes, idMode) {
		historyError(w, http.StatusBadRequest, fmt.Sprintf("unknown id %q, use one of %s", idMode, strings.Join(v2IDModes, ", ")))
		return
	}
	days := historyLookback(sig)
	if rs := r.FormValue("range"); rs != "" {
		n, err := strconv.Atoi(rs)
		if err != nil || n <= 0 {
			historyError(w, http.StatusBadRequest, "range must be a positive number of days")
			return
		}
		if n < days {
			days = n
		}
	}
	allowed := historyCardsAllowed(days)

	sealed := strings.HasPrefix(rest, "sealed/")
	base := strings.TrimPrefix(rest, "sealed/")
	if base == "" || strings.Contains(base, "/") {
		historyError(w, http.StatusNotFound, "Not found")
		return
	}
	// A single segment is tried as a set first; a list with a comma never is.
	var set *mtgmatcher.Set
	if !strings.Contains(base, ",") {
		if found, err := b.GetSet(base); err == nil {
			set = found
		}
	}
	if set == nil && sealed {
		historyError(w, http.StatusNotFound, "Not found")
		return
	}

	var cos []*mtgmatcher.CardObject
	page, pages := 0, 0
	if set == nil {
		var ids []string
		for _, id := range strings.Split(base, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
		ids = dedupeKeys(ids)
		// Bound the resolution work: a printing has usually one to three finishes.
		if len(ids) > 3*allowed {
			historyError(w, http.StatusBadRequest, fmt.Sprintf("at most %d ids over %d days", 3*allowed, days))
			return
		}
		// The budget's unit is a printing in one finish, so count those,
		// deduplicated across ids, rather than the ids themselves.
		seenUUID := map[string]bool{}
		for _, id := range ids {
			for _, co := range historyFinishes(b, id) {
				if !seenUUID[co.UUID] {
					seenUUID[co.UUID] = true
					cos = append(cos, co)
				}
			}
		}
		if len(cos) == 0 {
			historyError(w, http.StatusNotFound, "Not found")
			return
		}
		// One id is exempt from the budget, whatever its finishes.
		if len(ids) > 1 && len(cos) > allowed {
			historyError(w, http.StatusBadRequest, fmt.Sprintf("these ids cover %d printings by finish; at most %d over %d days, ask for fewer cards or a shorter range", len(cos), allowed, days))
			return
		}
	} else {
		uuids := b.GetUUIDsInSet(set.Code)
		if sealed {
			uuids = b.GetSealedUUIDsInSet(set.Code)
		}
		page = 1
		if ps := r.FormValue("page"); ps != "" {
			n, err := strconv.Atoi(ps)
			if err != nil || n < 1 {
				historyError(w, http.StatusBadRequest, "page must be a positive number")
				return
			}
			page = n
		}
		pages = (len(uuids) + allowed - 1) / allowed
		if pages < 1 {
			pages = 1
		}
		if page > pages {
			historyError(w, http.StatusNotFound, fmt.Sprintf("page %d past the end; the set has %d pages of %d cards over %d days", page, pages, allowed, days))
			return
		}
		start := (page - 1) * allowed
		for _, uuid := range uuids[start:min(start+allowed, len(uuids))] {
			if co, err := b.GetUUID(uuid); err == nil {
				cos = append(cos, co)
			}
		}
	}

	cards, banIDs := historyCardsOf(b, idMode, cos)
	if !acquireSlot(r.Context(), historySlots, historySlotWait) {
		w.Header().Set("Retry-After", "5")
		historyError(w, http.StatusServiceUnavailable, "price history is busy")
		return
	}
	defer func() { <-historySlots }()
	stashingBefore := historyStashing()
	rows, err := historyRead(r.Context(), banIDs, historySince(time.Now(), days))
	stashingAfter := historyStashing()
	stashing := stashingBefore || stashingAfter
	if err != nil {
		if r.Context().Err() == nil {
			log.Printf("history: %d ids over %d days: %v", len(banIDs), days, err)
		}
		w.Header().Set("Retry-After", "30")
		historyError(w, http.StatusServiceUnavailable, "price history unavailable")
		return
	}
	retail, buylist, latest := historyPivot(cards, rows, historyKeys())

	// tagBody is what the ETag covers, body what is sent.
	var tagBody, body []byte
	if asCSV {
		tagBody, err = historyCSV(retail, buylist)
		body = tagBody
		h := w.Header()
		h.Set("Content-Type", "text/csv")
		h.Set("X-MTGBAN-Latest", latest)
		h.Set("X-MTGBAN-Range", strconv.Itoa(days))
		if page > 0 {
			h.Set("X-MTGBAN-Page", strconv.Itoa(page))
			h.Set("X-MTGBAN-Pages", strconv.Itoa(pages))
		}
	} else {
		// meta.date is left zero, so the tag ignores it, then spliced into the body.
		out := historyOutput{
			Meta: historyMeta{
				Version: APIVersionV2, BaseURL: absoluteURL(r, "/go/"),
				Latest: latest, Range: days, Page: page, Pages: pages,
			},
			Retail: retail, Buylist: buylist,
		}
		tagBody, err = json.Marshal(out)
		date, _ := json.Marshal(time.Now())
		body = bytes.Replace(tagBody, historyZeroDate, append([]byte(`"date":`), date...), 1)
		body = append(body, '\n')
		w.Header().Set("Content-Type", "application/json")
	}
	if err != nil {
		historyError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// Nothing found, or the archive mid-write: not worth caching.
	if len(retail) == 0 && len(buylist) == 0 || stashing {
		w.Header().Set("Cache-Control", "no-store")
		w.Write(body)
		return
	}
	sum := sha1.Sum(tagBody)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(historyMaxAge(time.Now(), historyCacheHours())))
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
