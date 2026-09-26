package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/sessionstore"
	"github.com/mtgban/mtgban-website/timeseries"
)

type TimeseriesConfig struct {
	Datasets []DatasetConfig `json:"datasets"`

	// LongFormWrites dual-writes each snapshot into the new long tables
	// (variants + prices) alongside the legacy wide tables. LongFormReads
	// serves charts/analytics from the long tables instead of the wide ones.
	// The cutover is: deploy with writes on + reads off, confirm parity, then
	// flip reads on, then (later) drop the legacy write path. See db_migration/.
	LongFormWrites bool `json:"long_form_writes"`
	LongFormReads  bool `json:"long_form_reads"`
}

type DatasetConfig struct {
	Retail     []string `json:"retail,omitempty"`
	Buylist    []string `json:"buylist,omitempty"`
	PublicName string   `json:"public_name"`
	Index      int      `json:"index"`
	// Provider is the id in the providers lookup table this dataset maps to
	// (long form). Replaces the positional Index once the legacy path is dropped.
	Provider   int16  `json:"provider"`
	Color      string `json:"color"`
	HasSealed  bool   `json:"has_sealed,omitempty"`
	OnlySealed bool   `json:"only_sealed,omitempty"`
}

// longFormActive reports whether this deployment's chart storage is the long,
// ban_id-keyed one. The two flags are the Magic cutover, deployment by
// deployment; a non-Magic game is not part of that cutover because it never had
// the legacy path to cut over from — its card ids are not uuids, so the wide
// table cannot hold a single one of its rows.
//
// An unset game is the default one, the same reading datastoreGame and the rest
// of the site give it, so it is compared through that rather than against the
// raw field: a config that spells out "game": "" is a Magic deployment, not a
// game with no wide table.
func longFormActive() bool {
	return datastoreGame() != DefaultGame ||
		Config.TimeseriesConfig.LongFormWrites ||
		Config.TimeseriesConfig.LongFormReads
}

// longFormWrites reports whether this deployment's snapshot lands in the long
// prices table. Same reasoning as longFormActive, narrowed to the write side:
// a non-Magic game has nowhere else to put a price.
func longFormWrites() bool {
	return datastoreGame() != DefaultGame || Config.TimeseriesConfig.LongFormWrites
}

// providerForDatasetIndex resolves a legacy dataset Index to its provider id via
// the config. Used by the read callers (aggregate stats, movers) that still take
// an index. Returns false if no dataset carries that index or its provider is unset.
func providerForDatasetIndex(index int) (int16, bool) {
	for _, c := range Config.TimeseriesConfig.Datasets {
		if c.Index == index {
			return c.Provider, c.Provider != 0
		}
	}
	return 0, false
}

// earliestChartDate returns the oldest on-record date for a card (bounded by the
// lookback), reading from the long tables or the legacy wide table per the flag.
func earliestChartDate(ctx context.Context, uuid string, isFoil, isEtched bool, lb timeseries.Lookback) (time.Time, error) {
	if Config.TimeseriesConfig.LongFormReads {
		return PricesArchiveDB.GetEarliestDateLong(ctx, uuid, isFoil, isEtched, lb)
	}
	return PricesArchiveDB.GetEarliestDate(ctx, uuid, isFoil, isEtched, lb)
}

type Dataset struct {
	Name   string
	Data   []ChartPoint
	Color  string
	AxisID string
	Sealed bool

	// CardID is the stable per-card identity on a multi-card chart — the same
	// roster id the result rows use for data-card-id. The front-end groups
	// datasets by this instead of the display Name (so two printings sharing a
	// "Name (SET)" label stay separate lines) and matches a legend entry back
	// to its result row so hovering it can drive the sidebar preview.
	CardID string

	// Reference identifies which price source this dataset belongs to
	// (e.g. "TCG Low", "Card Kingdom Buy"). In single-card charts it equals
	// Name; in multi-card charts it's the grouping key the reference picker
	// switches on while Name carries the card name for the legend.
	Reference string
}

// multiCardPalette assigns a distinct color per card when several cards share
// one chart. Picked to be distinguishable in both light and dark themes.
var multiCardPalette = []string{
	"rgb(54, 162, 235)",
	"rgb(255, 99, 132)",
	"rgb(75, 192, 192)",
	"rgb(255, 159, 64)",
	"rgb(153, 102, 255)",
	"rgb(40, 167, 69)",
	"rgb(220, 53, 69)",
	"rgb(23, 162, 184)",
	"rgb(255, 205, 86)",
	"rgb(108, 117, 125)",
}

// getDateAxisValues generates daily date labels from today back to earliest.
func getDateAxisValues(earliest time.Time) []string {
	var dates []string
	today := time.Now()
	for d := today; !d.Before(earliest); d = d.AddDate(0, 0, -1) {
		dates = append(dates, d.Format("2006-01-02"))
	}
	return dates
}

// defaultChartRange is the history a chart draws when it first paints, in days,
// matching the option the date-range select starts on. The page renders this
// much and no more: a viewer entitled to ten years was being sent ten years of
// series in order to look at six months of it, and the rest costs nothing until
// it is asked for.
const defaultChartRange = 180

// chartWindow is the window a request should read: the tier's ceiling from the
// signature, and the range wanted, clamped to it. A non-positive want means the
// ceiling. Reading only what will be drawn prunes partitions - see
// docs/chart-page-loading.md.
func chartWindow(sig string, wantDays int) (window timeseries.Lookback, maxDays int) {
	ceiling := chartLookback(sig)
	maxDays = ceiling.Days()
	if wantDays <= 0 || wantDays > maxDays {
		return ceiling, maxDays
	}
	return timeseries.Lookback(wantDays), maxDays
}

// chartInitialRange is what a chart page renders inline: the range the viewer
// last chose, which the front-end mirrors into a cookie because the server
// cannot read localStorage, else where the select starts. Rendering the wrong
// one draws the chart twice. Zero is "All".
func chartInitialRange(r *http.Request, multi bool) int {
	name, fallback := "SearchChartRange", defaultChartRange
	if multi {
		name, fallback = "SearchChartMultiRange", 0
	}
	days, err := strconv.Atoi(readCookie(r, name))
	if err != nil || days < 0 {
		return fallback
	}
	return days
}

// chartRangeParam reads the requested window off a request, in days. Zero means
// the caller named no range, or named one that isn't a positive number, and
// wants whatever its tier allows.
func chartRangeParam(r *http.Request) int {
	days, err := strconv.Atoi(r.FormValue("range"))
	if err != nil || days <= 0 {
		return 0
	}
	return days
}

// chartLookback returns the chart history window, in days, as encoded in
// the signature under SearchChartLoopback. Absent or invalid values fall
// back to 30 days.
func chartLookback(sig string) timeseries.Lookback {
	if DevMode && !SigCheck {
		return timeseries.Lookback(3650)
	}
	days, err := strconv.Atoi(GetParamFromSig(sig, "SearchChartLoopback"))
	if err != nil || days <= 0 {
		days = 30
	}
	return timeseries.Lookback(days)
}

// getDatasets returns one Dataset per applicable config. All datasets for a
// given card read different columns from the same (uuid, foil, etched,
// language=nil, lookback) result set, so we fetch HGetAll exactly once and
// fan the rows out to every per-dataset render rather than firing N
// identical SQL queries (and discarding 15/16 of each result).
func getDatasets(ctx context.Context, cardID string, sealed bool, keys []string, lb timeseries.Lookback) []Dataset {
	if PricesArchiveDB == nil {
		return nil
	}

	// Pre-filter applicable configs so we don't pay for a DB round-trip
	// or a UUID lookup when nothing will render.
	var configs []DatasetConfig
	for _, c := range Config.TimeseriesConfig.Datasets {
		if sealed && !c.HasSealed {
			continue
		}
		if !sealed && c.OnlySealed {
			continue
		}
		configs = append(configs, c)
	}
	if len(configs) == 0 {
		return nil
	}

	co, err := backend().GetUUID(cardID)
	if err != nil {
		log.Println(err)
		return nil
	}

	datasets := make([]Dataset, 0, len(configs))

	if Config.TimeseriesConfig.LongFormReads {
		results, err := PricesArchiveDB.HGetAllLong(ctx, co.UUID, co.Foil, co.Etched, lb)
		if err != nil {
			log.Println(err)
			return nil
		}
		for _, config := range configs {
			datasets = append(datasets, buildDatasetLong(results, keys, config))
		}
		return datasets
	}

	results, err := PricesArchiveDB.HGetAll(ctx, co.UUID, co.Foil, co.Etched, nil, lb)
	if err != nil {
		log.Println(err)
		return nil
	}
	for _, config := range configs {
		datasets = append(datasets, buildDataset(results, keys, config))
	}
	return datasets
}

// providerDisplay is one provider's chart display: its name and color.
type providerDisplay struct {
	Provider int16
	Name     string
	Color    string
}

// providerRegistry is the ordered, game-agnostic list of chart providers. A chart
// renders one dataset per provider that actually has data for the card, in this
// order, so a new game (which reuses the shared TCGplayer providers) charts with
// no extra code. Built once at startup from the dataset config, which owns every
// provider's id, name, color, and position: a provider a deployment wants on its
// charts needs an entry in timeseries_config.datasets, including the TCGplayer
// metrics a non-Magic deployment charts.
var providerRegistry []providerDisplay

// buildProviderRegistry (re)builds providerRegistry from the loaded config. Call
// it once after the config is parsed. Nothing is substituted for a dataset the
// config leaves incomplete: a missing provider id can't be matched against a
// price row, so it is logged and skipped, and a config that sets none at all
// leaves the registry empty rather than charting a display the config never
// asked for.
func buildProviderRegistry() {
	longForm := longFormActive()
	seen := map[int16]bool{}
	registry := make([]providerDisplay, 0, len(Config.TimeseriesConfig.Datasets))
	for _, d := range Config.TimeseriesConfig.Datasets {
		if d.Provider == 0 {
			if longForm {
				log.Printf("dataset %q (index %d) has no \"provider\" id in the config: it won't chart, dual-write, or screen",
					d.PublicName, d.Index)
			}
			continue
		}
		if seen[d.Provider] {
			log.Printf("dataset %q repeats provider id %d, keeping the first entry's display", d.PublicName, d.Provider)
			continue
		}
		seen[d.Provider] = true
		registry = append(registry, providerDisplay{d.Provider, d.PublicName, d.Color})
	}
	if len(registry) == 0 && longForm {
		log.Println("no chart providers configured: every timeseries_config.datasets entry needs a \"provider\" id")
	}
	providerRegistry = registry
}

// fetchChartPrices reads one resolved target's series: by exact ban_id when the
// target has one, else the Magic canonical (uuid, foil, etched) path.
//
// This is the only read the chart path makes. The axis used to come from a
// second query asking the archive for the card's oldest date, which cost a
// round-trip to learn something the rows themselves say - and against a
// hundred-partition prices table a round-trip is mostly planning, not data.
func fetchChartPrices(ctx context.Context, target *chartTarget, lb timeseries.Lookback) map[string]timeseries.ProviderPrices {
	if PricesArchiveDB == nil {
		return nil
	}
	if target.BanID != 0 {
		results, err := PricesArchiveDB.HGetAllByBanID(ctx, target.BanID, lb)
		if err != nil {
			log.Printf("chart: ban_id %d (%s): %v", target.BanID, target.Name, err)
			return nil
		}
		return results
	}

	// No ban_id and no uuid to fall back on means this printing has no identity
	// the archive can be asked about - a non-Magic finish the product carries no
	// sub-type for, most often. Asking anyway is not an empty chart, it is a
	// type error the caller cannot tell apart from one.
	if !hasCanonicalIdentity(target) {
		log.Printf("chart: %q (%s) resolved to no ban_id and is not an mtgjson uuid, so the archive has no identity to look it up by",
			target.UUID, target.Name)
		return nil
	}

	results, err := PricesArchiveDB.HGetAllLong(ctx, target.UUID, target.Foil, target.Etched, lb)
	if err != nil {
		log.Printf("chart: uuid %s foil=%t etched=%t (%s): %v",
			target.UUID, target.Foil, target.Etched, target.Name, err)
		return nil
	}
	return results
}

// chartRosterConcurrency caps how many of a roster's cards are read at once.
// The archive pool is small (eight connections in the Magic deployment), and a
// roster is one request among many, so it takes a share rather than the lot:
// ten cards over four still lands in three waves instead of ten.
const chartRosterConcurrency = 4

// chartSeries is one roster card's fetched history, kept beside the identity
// the chart and the legend name it by.
type chartSeries struct {
	CardID string
	Name   string
	Prices map[string]timeseries.ProviderPrices

	// target is what the archive is asked about. Set by the caller when it
	// resolves the roster; nil entries are dropped before the fetch.
	target *chartTarget
}

// fetchRosterPrices reads a roster's cards concurrently, in roster order. Read
// one at a time, ten cards cost 848ms against 301ms together. Targets are
// resolved by the caller, whose per-request map has no locking of its own.
func fetchRosterPrices(ctx context.Context, targets []chartSeries, lb timeseries.Lookback) []chartSeries {
	if len(targets) == 0 {
		return nil
	}
	out := make([]chartSeries, len(targets))
	copy(out, targets)

	var wg sync.WaitGroup
	slots := make(chan struct{}, chartRosterConcurrency)
	for i := range out {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			out[i].Prices = fetchChartPrices(ctx, out[i].target, lb)
		})
	}
	wg.Wait()
	return out
}

// earliestChartedDate is the oldest date a fetched series holds, which is where
// the axis starts. Empty series fall back to the lookback boundary, the same
// answer the archive gave when it was asked directly.
//
// The dates are ISO, so the lexicographic minimum is the chronological one.
func earliestChartedDate(results map[string]timeseries.ProviderPrices, lb timeseries.Lookback) time.Time {
	var oldest string
	for date := range results {
		if oldest == "" || date < oldest {
			oldest = date
		}
	}
	if oldest == "" {
		return lb.Since()
	}
	parsed, err := time.Parse("2006-01-02", oldest)
	if err != nil {
		return lb.Since()
	}
	return parsed
}

// chartDatasetsFrom projects a fetched series onto the axis, game-agnostic: one
// dataset per registry provider that has data, in registry order. Adding a game
// needs no code here — its providers just show up. Long-form reads only; the
// legacy path stays in getDatasets.
func chartDatasetsFrom(results map[string]timeseries.ProviderPrices, labels []string) []Dataset {
	// Only providers with data for this card render — that is what makes it
	// game-agnostic and also drops sealed-vs-single applicability out of config
	// (e.g. Sealed EV only has data for sealed products, so it only shows there).
	present := map[int16]bool{}
	for _, pp := range results {
		for provider := range pp {
			present[provider] = true
		}
	}
	datasets := make([]Dataset, 0, len(present))
	for _, pd := range providerRegistry {
		if present[pd.Provider] {
			datasets = append(datasets, buildProviderDataset(results, labels, pd))
		}
	}
	return datasets
}

// ChartPoint is one plotted value, or a gap. Gaps outnumber prices on a long
// chart, so the encoding is over half the payload: null is four bytes and is
// Chart.js's own gap value, where the old "Number.NaN" string cost thirteen.
type ChartPoint struct {
	Price float64
	Known bool
}

// MarshalJSON writes a price as a bare number and a gap as null, which is how
// the value reaches both the template (a JS literal) and the chart API (JSON).
func (p ChartPoint) MarshalJSON() ([]byte, error) {
	if !p.Known {
		return []byte("null"), nil
	}
	return strconv.AppendFloat(nil, p.Price, 'g', -1, 64), nil
}

// UnmarshalJSON reads back what MarshalJSON wrote, so a chart response
// round-trips through Go - which is what lets anything consume the API as a
// typed response rather than as a bag of floats.
//
// The quoted form is also accepted, because that is what the API sent before
// gaps became null and responses carry an hour of cache.
func (p *ChartPoint) UnmarshalJSON(b []byte) error {
	text := string(b)
	if text == "null" {
		*p = ChartPoint{}
		return nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	price, err := strconv.ParseFloat(text, 64)
	if err != nil {
		// "Number.NaN", or anything else that isn't a price, is a gap.
		*p = ChartPoint{}
		return nil
	}
	*p = ChartPoint{Price: price, Known: true}
	return nil
}

// priceAt is the price a pivoted result holds for one provider on one day, and
// whether it holds one at all.
func priceAt(results map[string]timeseries.ProviderPrices, label string, provider int16) ChartPoint {
	pp, ok := results[label]
	if !ok {
		return ChartPoint{}
	}
	price, ok := pp[provider]
	if !ok {
		return ChartPoint{}
	}
	return ChartPoint{Price: price, Known: true}
}

// buildProviderDataset projects one provider's series across the label dates.
// Days the provider did not quote come out as gaps.
func buildProviderDataset(results map[string]timeseries.ProviderPrices, labels []string, pd providerDisplay) Dataset {
	data := make([]ChartPoint, len(labels))
	for i, label := range labels {
		data[i] = priceAt(results, label, pd.Provider)
	}
	return Dataset{Name: pd.Name, Data: data, Color: pd.Color, Reference: pd.Name}
}

// buildDatasetLong is buildDataset for the long-form read: it projects one
// provider out of the pivoted date -> (provider -> price) result. Missing dates
// and missing providers both come out as gaps.
func buildDatasetLong(results map[string]timeseries.ProviderPrices, labels []string, config DatasetConfig) Dataset {
	var data []ChartPoint
	if len(results) > 0 {
		data = make([]ChartPoint, len(labels))
		for i, label := range labels {
			data[i] = priceAt(results, label, config.Provider)
		}
	}
	return Dataset{
		Name:      config.PublicName,
		Data:      data,
		Color:     config.Color,
		Reference: config.PublicName,
	}
}

// buildDataset projects a single column out of the shared HGetAll result
// map. Missing dates and null prices both come out as gaps, so the front-end
// chart leaves a hole rather than drawing a zero.
func buildDataset(results map[string]timeseries.PriceRow, labels []string, config DatasetConfig) Dataset {
	var data []ChartPoint
	if len(results) > 0 {
		data = make([]ChartPoint, len(labels))
		for i, label := range labels {
			if row, ok := results[label]; ok {
				if price := row.PriceForDataset(config.Index); price != nil {
					data[i] = ChartPoint{Price: *price, Known: true}
				}
			}
		}
	}
	return Dataset{
		Name:      config.PublicName,
		Data:      data,
		Color:     config.Color,
		Reference: config.PublicName,
	}
}

// multiCardInput is one card's contribution to a multi-card chart: the
// display name to render in the legend, and the raw datasets returned by
// getDatasets for that card.
type multiCardInput struct {
	CardID   string
	Name     string
	Datasets []Dataset
}

// mergeMultiCardDatasets flattens per-card datasets into the (card × reference)
// list a multi-card chart renders. Each card's datasets get a palette color
// (round-robin, wrap-around past multiCardPalette's length) and the supplied
// card Name, replacing whatever getDatasets put there. Datasets with no data
// are dropped so reference names that a card doesn't support don't pollute the
// reference picker. The returned reference order is the first-seen order
// across all cards — a card later in the list that introduces a new reference
// appends; one that repeats a reference already seen does not.
func mergeMultiCardDatasets(cards []multiCardInput) ([]Dataset, []string) {
	var datasets []Dataset
	refSeen := map[string]bool{}
	var refOrder []string

	for i, card := range cards {
		color := multiCardPalette[i%len(multiCardPalette)]
		for _, ds := range card.Datasets {
			if len(ds.Data) == 0 {
				continue
			}

			ds.Name = card.Name
			ds.CardID = card.CardID
			ds.Color = color
			datasets = append(datasets, ds)

			if !refSeen[ds.Reference] {
				refSeen[ds.Reference] = true
				refOrder = append(refOrder, ds.Reference)
			}
		}
	}

	return datasets, refOrder
}

// getDatasetsForMulti returns one dataset per (card × reference) pair for a
// multi-card chart, plus the list of distinct reference names that have at
// least one non-empty dataset. UUIDs that fail to resolve are skipped so a
// single bad input doesn't take the whole chart down.
func getDatasetsForMulti(ctx context.Context, cardIDs []string, labels []string, lb timeseries.Lookback) ([]Dataset, []string) {
	cards := make([]multiCardInput, 0, len(cardIDs))
	for _, cardID := range cardIDs {
		co, err := backend().GetUUID(cardID)
		if err != nil {
			log.Println(err)
			continue
		}

		cardName := co.Name
		if !co.Sealed {
			cardName = fmt.Sprintf("%s (%s)", co.Name, co.SetCode)
			// Collector number disambiguates two printings that share a
			// set+finish (e.g. a regular and a borderless), so the legend at
			// the top of a multi-card chart tells them apart.
			if co.Number != "" {
				cardName += " #" + co.Number
			}
			if co.Foil {
				cardName += " Foil"
			} else if co.Etched {
				cardName += " Etched"
			}
		}

		cards = append(cards, multiCardInput{
			CardID:   cardID,
			Name:     cardName,
			Datasets: getDatasets(ctx, cardID, co.Sealed, labels, lb),
		})
	}

	return mergeMultiCardDatasets(cards)
}

// A default scale for converting non-NM prices to NM
var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
}

// snapshotDate returns now's date when ts falls on "today" or "tomorrow"
// relative to now, otherwise ts's own calendar date. Scrapers that straddle
// midnight (or run slightly ahead of the server clock) get collapsed onto
// today's row so the COALESCE merge in UpsertRows can fold their columns
// together, while genuinely stale scrapes keep their true observation date.
func snapshotDate(ts time.Time, now time.Time) string {
	today := now.Format("2006-01-02")
	tomorrow := now.AddDate(0, 0, 1).Format("2006-01-02")
	tsDay := ts.In(now.Location()).Format("2006-01-02")
	if tsDay == today || tsDay == tomorrow {
		return today
	}
	return tsDay
}

// getRow returns the accumulator row for a card variant, creating it if
// needed. The dedup key must match the Postgres unique index on
// product_prices: (date, mtgjson_uuid, is_foil, is_etched, language, is_alt).
// Without NormalizeUUID + isAlt, two distinct mtgmatcher UUIDs (e.g. a base
// and its "_alt" sibling) collapse into the same conflict bucket on insert
// and Postgres rejects the whole batch.
func getRow(accumulated map[string]*timeseries.PriceRow, uuid string, isFoil bool, isEtched bool, isAlt bool, language string, date string) *timeseries.PriceRow {
	uuid = timeseries.NormalizeUUID(uuid)
	key := date + "|" + uuid + "|" + strconv.FormatBool(isFoil) + "|" + strconv.FormatBool(isEtched) + "|" + strconv.FormatBool(isAlt) + "|" + language
	row, ok := accumulated[key]
	if !ok {
		row = &timeseries.PriceRow{
			Date:        date,
			MtgjsonUUID: uuid,
			IsFoil:      isFoil,
			IsEtched:    isEtched,
			IsAlt:       isAlt,
			Language:    &language,
		}
		accumulated[key] = row
	}
	return row
}

// stashingInProgress gates concurrent invocations of stashInTimeseries
// (cron + admin button). Use IsStashingInProgress to read.
var stashingInProgress atomic.Bool

// IsStashingInProgress reports whether a timeseries stash is currently
// running. Safe to call from any goroutine.
func IsStashingInProgress() bool {
	return stashingInProgress.Load()
}

// snapshotPriceFunc receives one scraped price bound for the archive: the card
// it belongs to, the dataset whose scraper produced it, the observation date,
// and the price itself (already condition-scaled and known non-zero).
type snapshotPriceFunc func(card *mtgmatcher.CardObject, config DatasetConfig, date string, price float64)

// walkSnapshotPrices visits every price the configured datasets claim from the
// loaded sellers and vendors, in config order. It is the half of a snapshot
// that is the same for every game — which scrapers count, how a condition
// scales a price, which date a scrape lands on — leaving each storage path to
// decide only what to key the result on.
//
// Two scrapers can feed one dataset, so a card and dataset can be visited more
// than once. The later visit is the one that counts, which is what both storage
// paths get for free: one overwrites a column, the other dedupes keeping the
// last row.
func walkSnapshotPrices(start time.Time, visit snapshotPriceFunc) {
	// Collect retail prices from sellers. A store published from an upload
	// lives in memory only, whatever dataset its shorthand happens to name.
	for _, seller := range GetSellers() {
		if Sessions.Is(sessionstore.Retail, seller.Info().Shorthand) {
			continue
		}
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Retail, seller.Info().Shorthand) {
				continue
			}

			date := snapshotDate(*seller.Info().InventoryTimestamp, start)
			log.Println("Stashing", seller.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range seller.Inventory() {
				price := entries[0].Price * defaultGradeMap[entries[0].Conditions]

				// Check if there is a specific price entry
				realRetail, found := entries[0].CustomFields["RetailPrice"]
				if entries[0].Conditions != "NM" && found {
					price, _ = strconv.ParseFloat(realRetail, 64)
				}

				if price == 0 {
					continue
				}

				card, err := backend().GetUUID(id)
				if err != nil {
					log.Println("Error getting card for", id, err)
					continue
				}

				visit(card, config, date, price)
			}
		}
	}

	// Collect buylist prices from vendors
	for _, vendor := range GetVendors() {
		if Sessions.Is(sessionstore.Buylist, vendor.Info().Shorthand) {
			continue
		}
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Buylist, vendor.Info().Shorthand) {
				continue
			}

			date := snapshotDate(*vendor.Info().BuylistTimestamp, start)
			log.Println("Stashing", vendor.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range vendor.Buylist() {
				price := entries[0].BuyPrice * defaultGradeMap[entries[0].Conditions]
				if price == 0 {
					continue
				}

				card, err := backend().GetUUID(id)
				if err != nil {
					log.Println("Error getting card for", id, err)
					continue
				}

				visit(card, config, date, price)
			}
		}
	}
}

// stashNonMagicTimeseries takes a non-Magic deployment's snapshot straight into
// the long prices table, keyed by ban_id.
//
// The legacy wide table is not a fallback here, it is the bug: its
// mtgjson_uuid column is a Postgres uuid, and a game that numbers its cards
// hands us "1459" or "808_f", so every batch came back 22P02 and the whole
// snapshot was lost. That is why a non-Magic deployment charted only the
// TCGplayer metrics the tcgcsv ingest writes on its own, whatever else its
// config listed. Long form keys on a ban_id, which every game has.
//
// A card whose product has no variant row yet is counted and skipped rather
// than minted: the variants table names a non-Magic printing by its TCGplayer
// sub-type, and that name comes from the tcgcsv catalog — inventing one here
// would file a second, permanently empty variant beside the real one. The next
// snapshot after that ingest picks the card up.
func stashNonMagicTimeseries(ctx context.Context, start time.Time) {
	// Every ban_id below is resolved from this cache, so a cold one is not a
	// slow snapshot, it is an empty one.
	if err := warmVariantCache(ctx); err != nil {
		ServerNotify("timeseries", fmt.Sprintf("snapshot aborted, could not warm the variant cache: %s", err))
		return
	}

	var snapshot nonMagicSnapshot
	walkSnapshotPrices(start, func(card *mtgmatcher.CardObject, config DatasetConfig, date string, price float64) {
		snapshot.add(cachedBanIDForCard(card), config, date, price)
	})

	// UpsertLongPrices dedupes on (ban_id, date, provider) keeping the last
	// write, which is the same last-wins the wide path gets from overwriting a
	// column on an accumulated row.
	upserted, err := PricesArchiveDB.UpsertLongPrices(ctx, snapshot.Rows, 0)
	if err != nil {
		ServerNotify("timeseries", fmt.Sprintf("long-form upsert error: %s", err))
		return
	}

	SetLastStashUpdate(time.Now())
	ServerNotify("timeseries", fmt.Sprintf("Snapshot completed in %s: %d upserted%s",
		time.Since(start), upserted, snapshot.skipped()))
}

// nonMagicSnapshot accumulates a non-Magic snapshot's long price rows, along
// with the two reasons a scraped price can fail to become one.
type nonMagicSnapshot struct {
	Rows []timeseries.LongPrice

	// NoProvider counts prices whose dataset names no provider id; NoVariant
	// those whose card has no variant row to key on. They are separate faults —
	// a config mistake against a product the tcgcsv ingest has not reached —
	// and a snapshot that quietly reported one total could not tell an operator
	// which one to go fix.
	NoProvider, NoVariant int
}

// add records one scraped price against the ban_id resolved for its card, or
// counts why it could not be stored. A zero banID means no variant.
func (s *nonMagicSnapshot) add(banID int64, config DatasetConfig, date string, price float64) {
	if config.Provider == 0 {
		// buildProviderRegistry already named this dataset at startup; the
		// count is how much of the snapshot the omission cost.
		s.NoProvider++
		return
	}
	if banID == 0 {
		s.NoVariant++
		return
	}
	s.Rows = append(s.Rows, timeseries.LongPrice{
		BanID: banID, Date: date, Provider: config.Provider, Price: price,
	})
}

// skipped is the tail of the completion notice, empty when nothing was skipped.
func (s *nonMagicSnapshot) skipped() string {
	var out string
	if s.NoVariant > 0 {
		out += fmt.Sprintf(", %d skipped with no variant", s.NoVariant)
	}
	if s.NoProvider > 0 {
		out += fmt.Sprintf(", %d skipped with no provider id", s.NoProvider)
	}
	return out
}

func stashInTimeseries() {
	// Only one stash may run at a time. The cron fires every 12h and the
	// admin button can fire at any moment; CompareAndSwap is the real gate.
	if !stashingInProgress.CompareAndSwap(false, true) {
		log.Println("stashInTimeseries: another stash is already running, skipping")
		return
	}
	defer stashingInProgress.Store(false)

	if PricesArchiveDB == nil {
		log.Println("PricesArchiveDB not initialized, skipping stash")
		return
	}

	start := time.Now()
	ServerNotify("timeseries", "Taking snapshot...")

	// A non-Magic deployment cannot use the wide table at all, so it takes its
	// own snapshot path rather than writing one and dual-writing the other.
	if datastoreGame() != DefaultGame {
		stashNonMagicTimeseries(context.Background(), start)
		return
	}

	// Accumulate all prices into a single row per (date, uuid, foil, etched).
	accumulated := map[string]*timeseries.PriceRow{}
	walkSnapshotPrices(start, func(card *mtgmatcher.CardObject, config DatasetConfig, date string, price float64) {
		row := getRow(accumulated, card.UUID, card.Foil, card.Etched, card.IsAlternative, card.Language, date)
		row.SetPriceForDataset(config.Index, price)
	})

	// Upsert all accumulated rows in batches
	rows := make([]timeseries.PriceRow, 0, len(accumulated))
	for _, row := range accumulated {
		rows = append(rows, *row)
	}

	upserted, err := PricesArchiveDB.UpsertRows(context.Background(), rows, 500)
	var errCount int
	if err != nil {
		errCount = len(rows) - upserted
		ServerNotify("timeseries", fmt.Sprintf("batch upsert error: %s", err))
	}

	// Dual-write the same snapshot into the long form (variants + prices).
	// Best-effort: a long-form failure is logged but does not fail the stash,
	// since the legacy wide upsert above already persisted this snapshot.
	if Config.TimeseriesConfig.LongFormWrites {
		if n, lerr := stashLongForm(context.Background(), accumulated); lerr != nil {
			ServerNotify("timeseries", fmt.Sprintf("long-form dual-write error: %s", lerr))
		} else {
			log.Printf("long-form dual-write: %d price rows", n)
		}
	}

	SetLastStashUpdate(time.Now())
	msg := fmt.Sprintf("Snapshot completed in %s: %d upserted, %d errors", time.Since(start), upserted, errCount)
	ServerNotify("timeseries", msg)
}

// variantCacheScope is the slice of the shared variants table this process can
// use: the game it serves, plus every category it ingests, since the tcgcsv
// ingest resolves a ban_id for each price row it writes and a row outside the
// cache costs a round-trip.
//
// The game's own category comes from the loaded catalog, which names it - the
// same source GetTCGCategoryID exists to provide, so enabling a game stays a
// matter of shipping its dump. That means the scope is only complete once the
// catalog is in, which is why the warm waits for it; a call made before then
// falls back to the whole table, correct but fat.
func variantCacheScope() timeseries.VariantScope {
	var scope timeseries.VariantScope
	if Config.Game == DefaultGame {
		scope.Magic = true
	} else if id := GetTCGCategoryID(); id != 0 {
		scope.TCGCategoryIDs = append(scope.TCGCategoryIDs, id)
	} else {
		log.Printf("variant cache: no catalog loaded for game %q, warming every game", Config.Game)
		return timeseries.VariantScope{}
	}
	if Config.TCGCSVConfig != nil {
		for _, game := range Config.TCGCSVConfig.Games {
			if !slices.Contains(scope.TCGCategoryIDs, game.CategoryID) {
				scope.TCGCategoryIDs = append(scope.TCGCategoryIDs, game.CategoryID)
			}
		}
	}
	return scope
}

// warmVariantCache warms this process's slice of the variants table and reports
// what it loaded. Both callers log the counts: a scope that resolves to no rows
// does not fail, it just misses on every lookup afterwards, so the count is the
// only place a category that stopped matching shows up.
// warmVariantCacheIfEnabled warms the cache when the long form is in use,
// reporting a failure rather than returning it: every caller is past the point
// where it could do anything about one, and a cold cache costs round-trips
// rather than answers.
func warmVariantCacheIfEnabled() {
	if !longFormActive() {
		return
	}
	if PricesArchiveDB == nil {
		return
	}
	if err := warmVariantCache(context.Background()); err != nil {
		log.Println("warning: could not warm variant cache:", err)
	}
}

func warmVariantCache(ctx context.Context) error {
	counts, err := PricesArchiveDB.WarmVariantCache(ctx, variantCacheScope())
	if err != nil {
		return err
	}
	log.Printf("variant cache warmed: %d magic, %d non-magic", counts.Magic, counts.TCG)
	return nil
}

// stashLongForm mirrors the accumulated wide rows into the long prices table. It
// warms the variant cache once, resolves each row's ban_id (minting new
// printings on the fly), and emits one LongPrice per set provider column with a
// positive price (zeros are omitted, matching the backfill). Returns the number
// of price rows upserted.
func stashLongForm(ctx context.Context, accumulated map[string]*timeseries.PriceRow) (int, error) {
	if err := warmVariantCache(ctx); err != nil {
		return 0, fmt.Errorf("warm variant cache: %w", err)
	}
	longRows := make([]timeseries.LongPrice, 0, len(accumulated)*4)
	for _, row := range accumulated {
		lang := ""
		if row.Language != nil {
			lang = *row.Language
		}
		banID, err := PricesArchiveDB.ResolveMagicBanID(ctx, timeseries.MagicVariant{
			MtgjsonUUID: row.MtgjsonUUID,
			IsFoil:      row.IsFoil,
			IsEtched:    row.IsEtched,
			IsAlt:       row.IsAlt,
			Language:    lang,
		})
		if err != nil {
			log.Println("long-form: resolve ban_id:", err)
			continue
		}
		for _, ds := range Config.TimeseriesConfig.Datasets {
			if ds.Provider == 0 {
				continue
			}
			if p := row.PriceForDataset(ds.Index); p != nil && *p > 0 {
				longRows = append(longRows, timeseries.LongPrice{
					BanID:    banID,
					Date:     row.Date,
					Provider: ds.Provider,
					Price:    *p,
				})
			}
		}
	}
	return PricesArchiveDB.UpsertLongPrices(ctx, longRows, 0)
}
