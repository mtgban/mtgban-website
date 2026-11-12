package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mtgban/mtgban-website/internal/metricsreport"
	"github.com/mtgban/mtgban-website/observability"
)

// metricsStore is what the Metrics section reads and writes.
type metricsStore interface {
	DayTotals(context.Context, observability.DayQuery) ([]observability.DayTotal, error)
	HourTotals(context.Context, observability.DayQuery, time.Time) ([]observability.HourTotal, error)
	PageVisits(ctx context.Context, instance string, from, until time.Time) ([]observability.PageVisit, error)
	Instances(ctx context.Context, now time.Time) ([]string, error)
	FoldStamp(context.Context) (string, error)
	FoldedThrough(ctx context.Context, now time.Time) (time.Time, bool, error)
	CounterHealth(context.Context, time.Time) ([]observability.InstanceHealth, error)
	JobRuns(context.Context) ([]observability.JobRun, error)
	Reviews(ctx context.Context, instance string) ([]observability.Review, error)
	SetReview(context.Context, observability.Review) error
	DeleteReview(ctx context.Context, instance, name, scope, value string) error
}

var _ metricsStore = (*observability.Client)(nil)

// metricsStoreFn is the section's store; nil when the database or the feature tables are missing.
var metricsStoreFn = defaultMetricsStore

// defaultMetricsStore is ObservabilityDB once its feature tables are ready, else an untyped nil.
func defaultMetricsStore() metricsStore {
	if ObservabilityDB == nil || !ObservabilityDB.FeaturesReady() {
		return nil
	}
	return ObservabilityDB
}

// metricsReportCache is the process's report cache, built again only for another store.
var metricsReportCache struct {
	mu    sync.Mutex
	store metricsStore
	cache *metricsreport.Cache
}

// metricsCache is the report cache for store, which must be comparable (a pointer).
func metricsCache(store metricsStore) *metricsreport.Cache {
	metricsReportCache.mu.Lock()
	defer metricsReportCache.mu.Unlock()
	if metricsReportCache.cache == nil || metricsReportCache.store != store {
		metricsReportCache.store = store
		metricsReportCache.cache = metricsreport.NewCache(store.FoldStamp, time.Now)
	}
	return metricsReportCache.cache
}

// dropMetricsCache empties the report cache, when one was built.
func dropMetricsCache() {
	metricsReportCache.mu.Lock()
	c := metricsReportCache.cache
	metricsReportCache.mu.Unlock()
	c.Drop()
}

// How long a load may be served from the cache; zero is until the fold stamp moves.
const (
	metricsUntilFold     time.Duration = 0
	metricsMinuteMaxAge                = time.Minute      // feature_events rows
	metricsVisitsMaxAge                = 10 * time.Minute // raw events rows
	metricsVisitsFailFor               = time.Minute      // how long a failed page hits read is remembered
)

// metricsRequestTimeout is the one deadline over a Metrics request's loads.
const metricsRequestTimeout = 20 * time.Second

// metricsContext is a Metrics request's context: the request's, ended at metricsRequestTimeout.
func metricsContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), metricsRequestTimeout)
}

const (
	metricsDefaultView = "overview"
	metricsDefaultDays = 90
	metricsTopRows     = 10 // rows the Overview lists of Remove and Invest
	metricsStockDays   = 7  // days back the stored-state load looks for its newest day
	// metricsStockLookBack is how far back a stale stored-state count looks for its last day.
	metricsStockLookBack = 90
)

// metricsNoInstanceText is what the section says for a site with no instance name.
const metricsNoInstanceText = "This site has no instance name configured, so it counts nothing; pick another site above."

// metricsTiersFailedText is a tier cell's text when the tier split could not be read.
const metricsTiersFailedText = "tier split could not be read"

// metricsStockStale says the nightly stored-state count has not run lately, with its last day if one was found.
func metricsStockStale(last time.Time) string {
	if last.IsZero() {
		return fmt.Sprintf("no nightly count has run in the last %d days", metricsStockLookBack)
	}
	return fmt.Sprintf("the nightly count has not run in the last %d days; the last one counted %s", metricsStockDays, last.Format("Jan 2, 2006"))
}

// metricsLastSeen is a candidate's newest day, or that it had none in the span days read.
func metricsLastSeen(last time.Time, span int) string {
	if last.IsZero() {
		return fmt.Sprintf("not in the last %d days", span)
	}
	return last.Format("Jan 2, 2006")
}

// metricsRemoveEmpty is what no candidate to list says: a finding once one could be classed, else how many wait.
func metricsRemoveEmpty(names []observability.Name, lists metricsreport.Lists, totals []observability.DayTotal, w metricsreport.Window) string {
	expanded := metricsreport.Expand(names, lists)
	measured, most := metricsreport.Measured(expanded, totals, w)
	if measured > 0 {
		return "Nothing is unused or rare in this window."
	}
	waiting := 0
	for _, n := range expanded {
		if n.Family != observability.FamilyState && n.Family != observability.FamilyStock {
			waiting += len(metricsreport.Units(n))
		}
	}
	return fmt.Sprintf("No candidate has been measured long enough to be classed yet: %d are waiting for %d measured days, and the most any has is %d.",
		waiting, metricsreport.MinDaysMeasured, most)
}

// metricsWindows are the window lengths the picker offers.
var metricsWindows = []int{30, 90, 180}

// metricsViewList is the views this build answers, in tab order; any other view is the Overview.
var metricsViewList = []struct{ key, label string }{
	{"overview", "Overview"},
	{"remove", "Remove"},
	{"invest", "Invest"},
	{"feature", "Feature"},
	{"health", "Health"},
	{"explore", "Explore"},
}

// metricsNotPages are labels that only redirect or are opened from mail, never a page to remove.
var metricsNotPages = []string{"api-trial", "api-login", "alerts/confirm", "alerts/unsubscribe"}

// metricsKindOrder is the order of a Remove area's kinds; any other kind follows by name.
var metricsKindOrder = []string{"setting", "control", "option", "operator", "page", "palette"}

// metricsForeignPagesNote says why another site's unviewed pages are left out.
const metricsForeignPagesNote = "Pages with no views are not listed for another site: a hidden page and an unused page look the same from here."

// metricsPageHitDays is the page hits the sections read, the last complete days whatever the window.
const metricsPageHitDays = 30

// metricsPhonesNote is the Overview's line on its phone rows, which read the same page hits.
var metricsPhonesNote = fmt.Sprintf("Phone rows cover the last %d complete days of page hits, whatever the window above.", metricsPageHitDays)

// metricsPageHitsNote is the note of the Invest sections read from page hits.
var metricsPageHitsNote = fmt.Sprintf("Signed-in readers, from page hits over the last %d complete days, whatever the window above; the toggles do not apply.", metricsPageHitDays)

// metricsInvestSections are the Invest sections' titles and notes, in order.
var metricsInvestSections = []struct{ key, title, note string }{
	{metricsreport.SectionWalls, "Walls", ""},
	{metricsreport.SectionFailures, "Failures", ""},
	{metricsreport.SectionMobile, "Phones on desktop pages", metricsPageHitsNote},
	{metricsreport.SectionGrowing, "Growing", "The last 30 complete days against the 30 before, per counted day, whatever the window above."},
	{metricsreport.SectionNew, "New", "First seen inside the window, while the counter was already running in the window before it."},
	{metricsreport.SectionDepth, "Depth, pages only", metricsPageHitsNote},
}

// metricsParams is a request's validated view, instance, window and toggles.
type metricsParams struct {
	View        string // overview, remove, invest, feature, health, explore
	Instance    string
	Days        int
	Anon, Bots  bool   // include anonymous rows, include bot rows
	Name, Area  string // a registered name, an area some name has
	UnknownName bool   // a name was asked for that the registry does not have; Name is then ""
	Hourly      bool
	// Saved and Cleared are a review redirect's confirmation; no link the page builds carries them
	Saved, Cleared bool
}

// readMetricsParams validates every parameter against a fixed list or the registry; get is r.FormValue.
func readMetricsParams(get func(string) string, instances []string) metricsParams {
	p := metricsParams{View: metricsDefaultView, Instance: observabilityInstance, Days: metricsDefaultDays}
	if v := get("view"); slices.ContainsFunc(metricsViewList, func(e struct{ key, label string }) bool { return e.key == v }) {
		p.View = v
	}
	if v := get("instance"); v != "" && v != observability.SharedInstance && slices.Contains(instances, v) {
		p.Instance = v
	}
	if n, err := strconv.Atoi(get("days")); err == nil && slices.Contains(metricsWindows, n) {
		p.Days = n
	}
	p.Anon, p.Bots, p.Hourly = get("anon") == "1", get("bots") == "1", get("hourly") == "1"
	p.Saved, p.Cleared = get("saved") == "1", get("cleared") == "1"
	if v := get("name"); v != "" {
		if _, ok := observability.Lookup(v); ok {
			p.Name = v
		} else {
			p.UnknownName = true
		}
	}
	if v := get("area"); v != "" && slices.ContainsFunc(observability.All(), func(n observability.Name) bool { return n.Area == v }) {
		p.Area = v
	}
	return p
}

// window is the report window the params ask for.
func (p metricsParams) window() metricsreport.Window {
	return metricsreport.Window{Days: p.Days, Signed: !p.Anon, Humans: !p.Bots}
}

// foreign reports whether the view is about another site's instance, whose hidden pages this site does not know.
func (p metricsParams) foreign() bool {
	return p.Instance != observabilityInstance
}

// link is a URL of view keeping what differs from the defaults; extra is key, value pairs.
func (p metricsParams) link(view string, extra ...string) string {
	rest := p.rest(extra...)
	u := "?page=metrics&view=" + url.QueryEscape(view)
	if len(rest) > 0 {
		u += "&" + rest.Encode()
	}
	return u
}

// keep is the pairs a picker link carries to stay on the same name, area or hourly view.
func (p metricsParams) keep() []string {
	var out []string
	switch p.View {
	case "feature":
		if p.Name != "" {
			out = append(out, "name", p.Name)
		} else if p.Area != "" {
			out = append(out, "area", p.Area)
		}
	case "explore":
		if p.Name != "" {
			out = append(out, "name", p.Name)
		}
		if p.Hourly {
			out = append(out, "hourly", "1")
		}
	}
	return out
}

// rest is link's parameters after page and view.
func (p metricsParams) rest(extra ...string) url.Values {
	rest := url.Values{}
	if p.Instance != observabilityInstance {
		rest.Set("instance", p.Instance)
	}
	if p.Days != metricsDefaultDays {
		rest.Set("days", strconv.Itoa(p.Days))
	}
	if p.Anon {
		rest.Set("anon", "1")
	}
	if p.Bots {
		rest.Set("bots", "1")
	}
	for i := 0; i+1 < len(extra); i += 2 {
		rest.Set(extra[i], extra[i+1])
	}
	return rest
}

// pageHasMobile reports whether the page a label names has a mobile template; a page no nav owns answers true.
func pageHasMobile(label string) bool {
	if publicPagePaths["/"+label] {
		return true
	}
	base, _, _ := strings.Cut(label, "/")
	if base == "home" {
		base = ""
	}
	owns := func(link string) bool {
		path, _, _ := strings.Cut(link, "?")
		return strings.Trim(path, "/") == base
	}
	mobile := func(nav *NavElem) bool { return slices.Contains(mobileEnabledPages, nav.Name) }
	for i := range DefaultNav {
		if owns(DefaultNav[i].Link) {
			return mobile(&DefaultNav[i])
		}
	}
	for _, nav := range ExtraNavs {
		if owns(nav.Link) {
			return mobile(nav)
		}
	}
	for _, nav := range ExtraNavs {
		for i := range nav.SubPages {
			if owns(nav.SubPages[i].Link) {
				return mobile(&nav.SubPages[i])
			}
		}
	}
	return true
}

// metricsLists are the open-ended value sets Expand makes lists of, for this site and snapshot.
func metricsLists(s *site, p *prices) metricsreport.Lists {
	return metricsreport.Lists{Pages: metricsPages(s), Routes: metricsRoutes(), Stores: metricsStores(p)}
}

// metricsListsFor is metricsLists for instance; another site's pages are not filtered by this site's hiding.
func metricsListsFor(s *site, p *prices, instance string) metricsreport.Lists {
	if instance == observabilityInstance {
		return metricsLists(s, p)
	}
	return metricsreport.Lists{Pages: metricsPagesWith(func(*NavElem) bool { return false }), Routes: metricsRoutes(), Stores: metricsStores(p)}
}

// metricsPages are the page labels a page candidate may be on this site.
func metricsPages(s *site) []string {
	return metricsPagesWith(func(nav *NavElem) bool { return nav.hiddenOn(s) })
}

// metricsPagesWith is pageLabels without catch-alls, metricsNotPages and the labels of hidden pages.
func metricsPagesWith(hidden func(*NavElem) bool) []string {
	drop := map[string]bool{}
	for _, label := range metricsNotPages {
		drop[label] = true
	}
	for _, nav := range ExtraNavs {
		off := hidden(nav)
		if off {
			for _, label := range navLabels(nav.Link) {
				drop[label] = true
			}
		}
		// a hidden section takes its sub-pages with it
		for i := range nav.SubPages {
			if off || hidden(&nav.SubPages[i]) {
				for _, label := range navLabels(nav.SubPages[i].Link) {
					drop[label] = true
				}
			}
		}
	}
	var out []string
	for _, label := range pageLabels() {
		if !drop[label] && !strings.HasSuffix(label, "/other") {
			out = append(out, label)
		}
	}
	return out
}

// navLabels are the page labels a nav link answers with.
func navLabels(link string) []string {
	path, query, _ := strings.Cut(link, "?")
	base := strings.Trim(path, "/")
	if q, err := url.ParseQuery(query); err == nil && q.Get("page") != "" {
		return []string{observability.NormalizePath(base, q.Get("page"))}
	}
	labels := []string{observability.NormalizePath(base, "")}
	for _, sub := range observability.Subviews(base) {
		labels = append(labels, base+"/"+sub)
	}
	return labels
}

// metricsRoutes are the route labels the registry accepts, sorted.
func metricsRoutes() []string {
	return slices.Sorted(maps.Keys(routeLabelSet()))
}

// metricsStores are the seller and vendor shorthands of p, sorted; nil without a snapshot.
func metricsStores(p *prices) []string {
	if p == nil {
		return nil
	}
	set := map[string]bool{}
	for shorthand := range p.index.seller {
		set[shorthand] = true
	}
	for shorthand := range p.index.vendor {
		set[shorthand] = true
	}
	if len(set) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(set))
}

// familyLabel names a registry family for the page.
func familyLabel(f observability.Family) string {
	switch f {
	case observability.FamilyServer:
		return "Server"
	case observability.FamilyUI:
		return "Controls"
	case observability.FamilyState:
		return "Settings"
	case observability.FamilyStock:
		return "Stored state"
	}
	return "Family " + strconv.Itoa(int(f))
}

// MetricsView is the admin Metrics section: the pickers and the one view asked for.
type MetricsView struct {
	View        string
	Instance    string
	Instances   []MetricsLink // the instance picker
	Days        int
	Windows     []MetricsLink // 30, 90, 180
	Views       []MetricsLink // the view tabs
	Anon, Bots  bool
	AnonLink    MetricsLink // flips the toggle, keeps the rest
	BotsLink    MetricsLink
	Folded      bool      // a day has been folded; false reads "no day has been folded yet" only when FoldedKnown
	FoldedKnown bool      // the folded-through read answered; false shows only the failure
	PagesNote   string    // metricsForeignPagesNote on another instance's Overview and Remove, else ""
	Through     time.Time // the newest folded day the reports end on; zero when none
	Failed      bool      // a load failed: the view shows what loaded
	Message     string    // a refused review mark, for the mobile page, which prints no WarningMessage
	NoInstance  string    // metricsNoInstanceText when this site has no instance name and no other site was picked
	Confirm     string    // "Review saved." or "Review cleared." after a review redirect, else ""
	Coverage    []metricsreport.FamilyCoverage
	Notes       []string // "Controls: not measured yet.", one per unmeasured family this view loaded
	Charts      []MetricsChart
	Overview    *MetricsOverview
	Remove      *MetricsRemove
	Invest      *MetricsInvest
	Feature     *MetricsFeature
	Health      *MetricsHealth
	Explore     *MetricsExplore
}

// MetricsLink is one picker or tab entry.
type MetricsLink struct {
	Label, URL string
	Active     bool
}

// MetricsChart is one canvas's data, handed to the page script as JSON.
type MetricsChart struct {
	ID     string          `json:"id"`   // the canvas element's id
	Kind   string          `json:"kind"` // line, bars, spark
	Labels []string        `json:"labels"`
	Series []MetricsSeries `json:"series"`
}

// MetricsSeries is one line or bar set of a chart.
type MetricsSeries struct {
	Label string  `json:"label"`
	Data  []int64 `json:"data"`
}

// MetricsCandidateRow is a removal candidate with its links; RateText and Help are the Candidate's.
type MetricsCandidateRow struct {
	metricsreport.Candidate
	Tiers string // TierLine: "Any 12, Legacy 3", or ""
	URL   string // its feature page
	Key   string // name|scope|value, for the review form and the anchor
	// Reason says in words why a not-measured row is not; "" for any other class.
	Reason    string
	CountedOn string // what the days measured were counted on, in words
	OutOf     string // "305 views of every page": the count a rate is taken of; "" when counted on days
	Anchor    string // the row's id on the Remove view, [a-z0-9_.-] only
	RemoveURL string // the Remove view at this row
	// LastSeenText is the newest day with a row, or that there was none in the days loaded.
	LastSeenText string
	Gone         bool // a review mark whose unit is no longer a candidate: shown by its stored key, clear only
}

// MetricsSignalRow is an Invest row with its rate text, trend and link.
type MetricsSignalRow struct {
	metricsreport.Signal
	RateText string // "15.0%", "2.4x", or "" when HasRate is false
	Tiers    string // walls only
	Trend    string // walls and failures: up, down, flat, or "" when the two windows cannot be compared
	PrevText string // the Previous cell, metricsreport.PreviousText
	URL      string // its feature page, "" for a row with no registered name
}

// MetricsOverview is the Overview view.
type MetricsOverview struct {
	Live           bool                  // the instance flushed in the last ten minutes
	LiveKnown      bool                  // the health read answered; false shows only the failure
	ReviewsFailed  bool                  // the reviews read failed: reviewed rows may show as candidates
	LastFlush      time.Time             // the instance's newest flush since yesterday; zero when none
	DaysData       int                   // days of the window with server rows
	DigestReady    bool                  // every digest load answered; false shows no digest
	Changes        metricsreport.Digest  // last 7 folded days against the 7 before, signed-in, no bots
	NothingChanged string                // what an empty digest says
	Remove         []MetricsCandidateRow // the ten strongest unused, rare or unused-so-far rows
	MoreRows       []MetricsMoreArea     // how many more such rows each area has, Rows being the count
	Invest         []MetricsSignalRow    // metricsreport.Top of ten
	InvestEvidence bool                  // some Invest row has evidence; without one the column is left out
	Areas          []MetricsAreaRow
	Stock          []MetricsStockGroup // stored state, all sites, the newest day only
	StockDay       time.Time
	Counted        bool        // the window's counts were read on a complete day
	Read           MetricsRead // the counts' read; Failed too when the newest complete day could not be read
	StockRead      MetricsRead // the stored-state read
	StockStale     string      // why stored state has no day: the nightly count has not run lately; "" otherwise
	VisitsRead     MetricsRead // the page hits read: the phone and depth rows of Consider investing
	PhonesNote     string      // what span the phone rows cover: metricsPhonesNote
	RemoveEmpty    string      // what an empty Consider removing says once counted: metricsRemoveEmpty
}

// MetricsAreaRow is one area's counted events in the window, metricsreport.AreaCount.
type MetricsAreaRow struct {
	Area   string
	Events int64
	URL    string
}

// MetricsShare is one part of a whole; Share is a fraction (0.25 is 25%).
type MetricsShare struct {
	Label string
	N     int64
	Share float64
}

// MetricsStockGroup is one stored-state name on the newest stock day, its breakdown collapsed.
type MetricsStockGroup struct {
	Name, Help string
	Total      int64
	Rows       []MetricsShare // shares of Total, largest first
	Several    bool           // the parts do not add up to Total (not metricsreport.Partition): counts headed "Rows", no share
}

// MetricsMoreArea is how many more removable rows one area has past the Overview's ten.
type MetricsMoreArea struct {
	Area string
	Rows int64 // removable rows past the ten
}

// MetricsRemove is the Remove view.
type MetricsRemove struct {
	ReviewsFailed bool                  // the reviews read failed: reviewed rows may show as candidates
	Areas         []MetricsRemoveArea   // unused, rare, unused so far
	NotMeasured   []MetricsCandidateRow // collapsed
	Reviewed      []MetricsCandidateRow // collapsed
	Counted       bool                  // the window's counts were read on a complete day; an empty list is then a finding
	Read          MetricsRead           // the counts' read; Failed too when the newest complete day could not be read
	ReviewURL     string                // where the review forms post: this Remove view's link
	Total         string                // "12 candidates: 9 unused, 3 rare", or "" with no area
	ReviewedOpen  bool                  // a review was just saved, so the Reviewed group starts open
	Empty         string                // what no area says once counted: metricsRemoveEmpty
	ReviewsCap    string                // says the reviews read hit observability.ReviewsMax, so later marks are not shown; "" when it did not
}

// MetricsRemoveArea is one area's removal rows, by kind.
type MetricsRemoveArea struct {
	Area    string
	Kinds   []MetricsRemoveKind
	Summary string // "3 unused, 5 rare, 2 unused so far"
	Open    bool   // the page was asked for this area, so it starts open
}

// MetricsRemoveKind is one kind's removal rows, in Remove's order.
type MetricsRemoveKind struct {
	Kind     string
	Rows     []MetricsCandidateRow
	HasOutOf bool // some row has an Out of; without one the column is left out
	HasTiers bool // some row has a tier line; without one the column is left out
}

// MetricsInvest is the Invest view: always its six sections.
type MetricsInvest struct {
	Sections   []MetricsInvestSection
	Counted    bool        // the window's counts were read on a complete day; an empty section is then a finding
	Read       MetricsRead // the counts' read; Failed too when the newest complete day could not be read
	VisitsRead MetricsRead // the page hits read, behind Phones on desktop pages and Depth
}

// MetricsInvestSection is one Invest section.
type MetricsInvestSection struct {
	Key, Title, Note string
	Empty            string // what the section says with no rows once counted
	Rows             []MetricsSignalRow
	// Has* say some measured row fills that column; without one the column is left out
	HasPrevious, HasEvidence, HasTiers bool
	Span                               int // the columns after Signal, a not-measured row's colspan
}

// metricsHealth is the minute rows the Overview reads.
type metricsHealth struct {
	Counters []observability.InstanceHealth
	Jobs     []observability.JobRun
}

// metricsThrough is FoldedThrough's answer.
type metricsThrough struct {
	Day time.Time
	OK  bool
}

// metricsLoader is one request's loads through the cache; failed says one did not answer.
type metricsLoader struct {
	ctx    context.Context
	store  metricsStore
	cache  *metricsreport.Cache
	now    time.Time
	failed bool
}

// metricsGet loads k through the cache, logging and marking a failure, which is never cached.
func metricsGet[T any](l *metricsLoader, k metricsreport.Key, maxAge time.Duration, load func(context.Context) (T, error)) (T, bool) {
	v, err := metricsreport.LoadFor(l.ctx, l.cache, k, maxAge, load)
	if err != nil {
		log.Printf("metrics: %s: %v", k.Report, err)
		l.failed = true
		return v, false
	}
	return v, true
}

// metricsDate is a day as a cache key's To.
func metricsDate(t time.Time) string {
	return t.UTC().Format(time.DateOnly)
}

// through is the newest fully folded day, folded false when none is; known is false when the read failed.
func (l *metricsLoader) through() (day time.Time, folded, known bool) {
	now := l.now
	v, ok := metricsGet(l, metricsreport.Key{Report: "through", To: metricsDate(now)}, metricsMinuteMaxAge, func(ctx context.Context) (metricsThrough, error) {
		day, folded, err := l.store.FoldedThrough(ctx, now)
		return metricsThrough{Day: day, OK: folded}, err
	})
	return v.Day, ok && v.OK, ok
}

// instances lists the picker's instances: those with rows, this site's own first when missing.
func (l *metricsLoader) instances() []string {
	now := l.now
	got, _ := metricsGet(l, metricsreport.Key{Report: "instances"}, metricsUntilFold, func(ctx context.Context) ([]string, error) {
		return l.store.Instances(ctx, now)
	})
	var out []string
	for _, inst := range got {
		if inst != "" && inst != observability.SharedInstance {
			out = append(out, inst)
		}
	}
	if observabilityInstance != "" && !slices.Contains(out, observabilityInstance) {
		out = append([]string{observabilityInstance}, out...)
	}
	return out
}

// query loads an unsplit, unnamed day query under report, keyed by the query itself.
func (l *metricsLoader) query(report string, q observability.DayQuery) ([]observability.DayTotal, bool) {
	k := metricsreport.Key{Report: report, Instance: q.Instance, Days: q.Days, Signed: q.Signed, Humans: q.Humans, To: metricsDate(q.To)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) ([]observability.DayTotal, error) {
		return l.store.DayTotals(ctx, q)
	})
}

// totals is the window's bundle, metricsreport.BundleQuery.
func (l *metricsLoader) totals(inst string, to time.Time, w metricsreport.Window) ([]observability.DayTotal, bool) {
	return l.query("bundle", metricsreport.BundleQuery(inst, to, w))
}

// tiers is the window as one period split by tier.
func (l *metricsLoader) tiers(inst string, to time.Time, w metricsreport.Window) ([]observability.DayTotal, bool) {
	k := metricsreport.Key{Report: "tiers", Instance: inst, Days: w.Days, Signed: w.Signed, Humans: w.Humans, To: metricsDate(to)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) ([]observability.DayTotal, error) {
		return l.store.DayTotals(ctx, observability.DayQuery{Instance: inst, To: to, Days: w.Days, ByTier: true, Signed: w.Signed, Humans: w.Humans})
	})
}

// visits is the page hits of the metricsPageHitDays ending on to, signed-in humans whatever the
// toggles: one load a page view, shared by every section that reads it, a failure remembered a minute.
func (l *metricsLoader) visits(inst string, to time.Time) ([]observability.PageVisit, bool) {
	k := metricsreport.Key{Report: "visits", Instance: inst, Days: metricsPageHitDays, To: metricsDate(to)}
	v, err := metricsreport.LoadRemembering(l.ctx, l.cache, k, metricsVisitsMaxAge, metricsVisitsFailFor, func(ctx context.Context) ([]observability.PageVisit, error) {
		return l.store.PageVisits(ctx, inst, to.AddDate(0, 0, -metricsPageHitDays+1), to.AddDate(0, 0, 1))
	})
	if err != nil {
		log.Printf("metrics: %s: %v", k.Report, err)
		l.failed = true
		return nil, false
	}
	return v, true
}

// silent is the last 30 days as one period, every reader and bot, for Silent.
func (l *metricsLoader) silent(inst string, to time.Time) ([]observability.DayTotal, bool) {
	k := metricsreport.Key{Report: "silent", Instance: inst, Days: 30, To: metricsDate(to)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) ([]observability.DayTotal, error) {
		return l.store.DayTotals(ctx, observability.DayQuery{Instance: inst, To: to, Days: 30, Step: 30})
	})
}

// stock is the stored-state rows of the last days, under SharedInstance; loaded is false
// when the registry has no stored-state name or the load failed.
func (l *metricsLoader) stock(names []observability.Name) (rows []observability.DayTotal, loaded bool) {
	var stockNames []string
	for _, n := range names {
		if n.Family == observability.FamilyStock {
			stockNames = append(stockNames, n.Name)
		}
	}
	if len(stockNames) == 0 {
		return nil, false
	}
	today := utcDay(l.now)
	k := metricsreport.Key{Report: "stock", Instance: observability.SharedInstance, Days: metricsStockDays, To: metricsDate(today)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) ([]observability.DayTotal, error) {
		return l.store.DayTotals(ctx, observability.DayQuery{Instance: observability.SharedInstance, To: today, Days: metricsStockDays, Step: 1, Names: stockNames})
	})
}

// stockLast is the newest stored-state day in the last metricsStockLookBack days, zero when none.
func (l *metricsLoader) stockLast(names []observability.Name) (time.Time, bool) {
	var stockNames []string
	for _, n := range names {
		if n.Family == observability.FamilyStock {
			stockNames = append(stockNames, n.Name)
		}
	}
	today := utcDay(l.now)
	q := observability.DayQuery{Instance: observability.SharedInstance, To: today, Days: metricsStockLookBack, Names: stockNames}
	rows, ok := l.days("stocklast", "", q)
	var last time.Time
	for _, t := range rows {
		if t.Last.After(last) {
			last = t.Last
		}
	}
	return last, ok
}

// health is the counters' minute rows since yesterday and the jobs' last runs.
func (l *metricsLoader) health() (metricsHealth, bool) {
	yesterday := utcDay(l.now).AddDate(0, 0, -1)
	return metricsGet(l, metricsreport.Key{Report: "health", To: metricsDate(yesterday)}, metricsMinuteMaxAge, func(ctx context.Context) (metricsHealth, error) {
		counters, err := l.store.CounterHealth(ctx, yesterday)
		if err != nil {
			return metricsHealth{}, err
		}
		jobs, err := l.store.JobRuns(ctx)
		return metricsHealth{Counters: counters, Jobs: jobs}, err
	})
}

// reviews are the instance's review marks, read on every request, at most observability.ReviewsMax;
// ok is false when the read failed.
func (l *metricsLoader) reviews(inst string) ([]observability.Review, bool) {
	reviews, err := l.store.Reviews(l.ctx, inst)
	if err != nil {
		log.Printf("metrics: reviews: %v", err)
		l.failed = true
		return nil, false
	}
	return reviews, true
}

// metricsInstances lists the instances the picker offers, logging a failed load.
func metricsInstances(ctx context.Context, store metricsStore, cache *metricsreport.Cache, now time.Time) []string {
	l := &metricsLoader{ctx: ctx, store: store, cache: cache, now: now}
	return l.instances()
}

// loadMetricsView builds the view params asks for over the whole registry.
func loadMetricsView(ctx context.Context, store metricsStore, cache *metricsreport.Cache, lists metricsreport.Lists, params metricsParams, now time.Time) *MetricsView {
	return loadMetricsViewFor(ctx, store, cache, observability.All(), lists, params, now)
}

// loadMetricsViewFor builds the view params asks for over names; a failed load is shown, never cached.
func loadMetricsViewFor(ctx context.Context, store metricsStore, cache *metricsreport.Cache, names []observability.Name, lists metricsreport.Lists, params metricsParams, now time.Time) *MetricsView {
	l := &metricsLoader{ctx: ctx, store: store, cache: cache, now: now}
	v := newMetricsView(params, l.instances())
	if params.Instance == "" {
		// this site counts nothing, so there is nothing of its own to load
		v.NoInstance = metricsNoInstanceText
		return v
	}
	day, folded, known := l.through()
	v.FoldedKnown = known
	if folded {
		v.Folded, v.Through = true, day
	}
	if params.foreign() && (params.View == "remove" || params.View == metricsDefaultView) {
		v.PagesNote = metricsForeignPagesNote
	}
	switch params.View {
	case "remove":
		v.Remove = &MetricsRemove{Read: metricsRead(known)}
		if folded {
			w := params.window()
			totals, ok := l.totals(params.Instance, day, w)
			tiers, tiersOK := l.tiers(params.Instance, day, w)
			reviews, reviewsOK := l.reviews(params.Instance)
			if ok {
				span := metricsreport.BundleQuery(params.Instance, day, w).Days
				v.Remove = buildMetricsRemove(names, lists, totals, tiers, tiersOK, reviews, span, params)
				v.Coverage = metricsCoverage(totals, nil, false, w)
			}
			if len(reviews) >= observability.ReviewsMax {
				v.Remove.ReviewsCap = fmt.Sprintf("Only the first %d review marks were read; any after them are not shown and their rows may appear again.", observability.ReviewsMax)
			}
			v.Remove.ReviewsFailed = !reviewsOK
			v.Remove.Counted, v.Remove.Read = ok, metricsRead(ok)
		}
		v.Remove.ReviewURL = params.link("remove")
		v.Remove.ReviewedOpen = params.Saved
		switch {
		case params.Saved:
			v.Confirm = metricsReviewSaved
		case params.Cleared:
			v.Confirm = metricsReviewCleared
		}
	case "invest":
		v.Invest = &MetricsInvest{Sections: metricsSections(nil), Read: metricsRead(known)}
		if folded {
			w := params.window()
			totals, ok := l.totals(params.Instance, day, w)
			tiers, tiersOK := l.tiers(params.Instance, day, w)
			visits, visitsOK := l.visits(params.Instance, day)
			if ok {
				v.Invest = buildMetricsInvest(names, totals, tiers, tiersOK, metricsreport.PageDepths(visits, lists.Pages, pageHasMobile), visitsOK, params)
				v.Coverage = metricsCoverage(totals, nil, false, w)
			}
			v.Invest.Counted, v.Invest.Read = ok, metricsRead(ok)
			v.Invest.VisitsRead = metricsRead(visitsOK)
		}
	case "feature":
		v.Feature = l.feature(v, names, params, day, folded)
	case "health":
		v.Health = l.healthView(names, params, day, folded, known)
	case "explore":
		v.Explore = l.explore(v, names, params, day, folded)
	default:
		v.Overview = l.overview(v, names, lists, params, day, folded)
	}
	v.Notes = metricsNotes(v.Coverage)
	if ov := v.Overview; ov != nil && (ov.StockStale != "" || ov.StockRead.Failed) {
		// say it stopped, or could not be read, rather than "not measured yet"
		if i := slices.Index(v.Notes, metricsreport.CoverageStock+": not measured yet."); i >= 0 {
			v.Notes[i] = metricsreport.CoverageStock + ": " + ov.StockStale + "."
			if ov.StockRead.Failed {
				v.Notes[i] = metricsreport.CoverageStock + ": could not be read."
			}
		}
	}
	v.Failed = l.failed
	return v
}

// newMetricsView is the shell: the pickers and tabs for params.
func newMetricsView(p metricsParams, instances []string) *MetricsView {
	v := &MetricsView{View: p.View, Instance: p.Instance, Days: p.Days, Anon: p.Anon, Bots: p.Bots}
	keep := p.keep()
	for _, inst := range instances {
		q := p
		q.Instance = inst
		v.Instances = append(v.Instances, MetricsLink{Label: inst, URL: q.link(p.View, keep...), Active: inst == p.Instance})
	}
	for _, days := range metricsWindows {
		q := p
		q.Days = days
		v.Windows = append(v.Windows, MetricsLink{Label: fmt.Sprintf("%d days", days), URL: q.link(p.View, keep...), Active: days == p.Days})
	}
	for _, e := range metricsViewList {
		v.Views = append(v.Views, MetricsLink{Label: e.label, URL: p.link(e.key), Active: e.key == p.View})
	}
	anon, bots := p, p
	anon.Anon, bots.Bots = !p.Anon, !p.Bots
	v.AnonLink = MetricsLink{Label: "Anonymous readers", URL: anon.link(p.View, keep...), Active: p.Anon}
	v.BotsLink = MetricsLink{Label: "Bots", URL: bots.link(p.View, keep...), Active: p.Bots}
	return v
}

// overview builds the Overview, filling v's Coverage with what it loaded.
func (l *metricsLoader) overview(v *MetricsView, names []observability.Name, lists metricsreport.Lists, params metricsParams, day time.Time, folded bool) *MetricsOverview {
	ov := &MetricsOverview{NothingChanged: metricsreport.NothingChanged, PhonesNote: metricsPhonesNote}
	health, healthOK := l.health()
	ov.LiveKnown = healthOK
	if i := slices.IndexFunc(health.Counters, func(h observability.InstanceHealth) bool { return h.Instance == params.Instance }); i >= 0 {
		ov.LastFlush = health.Counters[i].LastFlush
		ov.Live = !metricsreport.FlushStale(l.now, ov.LastFlush)
	}
	stock, stockLoaded := l.stock(names)
	ov.StockDay, ov.Stock = metricsStockGroups(names, stock)
	hasStock := slices.ContainsFunc(names, func(n observability.Name) bool { return n.Family == observability.FamilyStock })
	ov.StockRead = metricsRead(stockLoaded || !hasStock)
	if stockLoaded && len(stock) == 0 {
		last, lastOK := l.stockLast(names)
		ov.StockRead = metricsRead(lastOK)
		if lastOK {
			ov.StockStale = metricsStockStale(last)
		}
	}
	ov.Read = metricsRead(v.FoldedKnown)
	if !folded {
		return ov
	}
	w := params.window()
	totals, ok := l.totals(params.Instance, day, w)
	ov.Counted, ov.Read = ok, metricsRead(ok)
	tiers, _ := l.tiers(params.Instance, day, w)
	visits, visitsOK := l.visits(params.Instance, day)
	ov.VisitsRead = metricsRead(visitsOK)
	reviews, reviewsOK := l.reviews(params.Instance)
	ov.ReviewsFailed = !reviewsOK
	if ok {
		v.Coverage = metricsCoverage(totals, stock, stockLoaded, w)
		for _, c := range v.Coverage {
			if c.Label == metricsreport.CoverageServer {
				ov.DaysData = c.Days
			}
		}
		candidates := metricsreport.Candidates(names, lists, observability.Settings(), totals, reviews, w, params.foreign())
		span := metricsreport.BundleQuery(params.Instance, day, w).Days
		ov.Remove, ov.MoreRows = metricsTopCandidates(candidates, tiers, span, params)
		if len(ov.Remove) == 0 {
			ov.RemoveEmpty = metricsRemoveEmpty(names, lists, totals, w)
		}
		signals := metricsreport.WithErrors(metricsreport.Invest(names, totals, metricsreport.PageDepths(visits, lists.Pages, pageHasMobile), w), nil, false)
		days, prevDays := metricsreport.WindowDays(totals, w)
		registered := metricsRegistered(names)
		for _, s := range metricsreport.Top(signals, metricsTopRows) {
			r := metricsSignalRow(s, tiers, days, prevDays, registered, params)
			ov.Invest = append(ov.Invest, r)
			ov.InvestEvidence = ov.InvestEvidence || r.Evidence != ""
		}
		for _, a := range metricsreport.Areas(names, totals, w) {
			ov.Areas = append(ov.Areas, MetricsAreaRow{Area: a.Area, Events: a.Events, URL: params.link("feature", "area", a.Area)})
		}
	}
	ov.Changes, ov.DigestReady = l.digest(names, lists, reviews, params.Instance, day, health, healthOK)
	ov.DigestReady = ov.DigestReady && reviewsOK
	return ov
}

// digest is what changed, at its fixed windows whatever the picker says; ready is false when a load failed.
func (l *metricsLoader) digest(names []observability.Name, lists metricsreport.Lists, reviews []observability.Review, inst string, day time.Time, health metricsHealth, healthOK bool) (metricsreport.Digest, bool) {
	loads := metricsreport.DigestQueries(inst, day)
	week, okWeek := l.query("week", loads.Week)
	devices, okDevices := l.days("weekdevices", "page.view", loads.Devices)
	nowRows, okNow := l.query("bundle", loads.Now)
	prevRows, okPrev := l.query("bundle", loads.Prev)
	allReaders, okSilent := l.silent(inst, day)
	if !okWeek || !okDevices || !okNow || !okPrev || !okSilent || !healthOK {
		return metricsreport.Digest{}, false
	}
	broken, _ := metricsreport.Silent(names, allReaders)
	problems := metricsreport.Problems(metricsreport.HealthInput{
		Now: l.now, Instance: inst, Counters: health.Counters, Jobs: health.Jobs, JobNames: metricsJobNames(names), Broken: broken,
	})
	now, prev := metricsreport.DigestSnapshots(metricsreport.DigestInput{
		Names: names, Lists: lists, Settings: observability.Settings(),
		Week: week, Now: nowRows, Prev: prevRows,
		Devices: devices, Pages: lists.Pages, HasMobile: pageHasMobile,
		Reviews: reviews, Problems: problems, Foreign: inst != observabilityInstance,
	})
	return metricsreport.Changes(now, prev), true
}

// metricsJobNames are the jobs job.run is registered with, in order; nil without it.
func metricsJobNames(names []observability.Name) []string {
	if i := slices.IndexFunc(names, func(n observability.Name) bool { return n.Name == "job.run" }); i >= 0 {
		return slices.Clone(names[i].Scopes)
	}
	return nil
}

// metricsRegistered is the set of names a row may link to.
func metricsRegistered(names []observability.Name) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n.Name] = true
	}
	return set
}

// metricsCoverage is Coverage without the Stored state entry when stock was not loaded.
func metricsCoverage(totals, stock []observability.DayTotal, stockLoaded bool, w metricsreport.Window) []metricsreport.FamilyCoverage {
	var out []metricsreport.FamilyCoverage
	for _, c := range metricsreport.Coverage(totals, stock, w) {
		if c.Label == metricsreport.CoverageStock && !stockLoaded {
			continue
		}
		out = append(out, c)
	}
	return out
}

// metricsNotes is one line per unmeasured family.
func metricsNotes(coverage []metricsreport.FamilyCoverage) []string {
	var notes []string
	for _, c := range coverage {
		if !c.Measured {
			notes = append(notes, c.Label+": not measured yet.")
		}
	}
	return notes
}

// metricsStockGroups is the newest stock day's names, each with its breakdown.
func metricsStockGroups(names []observability.Name, stock []observability.DayTotal) (time.Time, []MetricsStockGroup) {
	day, groups := metricsreport.Stock(names, stock)
	byName := map[string]observability.Name{}
	for _, n := range names {
		byName[n.Name] = n
	}
	var out []MetricsStockGroup
	for _, g := range groups {
		sg := MetricsStockGroup{Name: g.Name, Help: byName[g.Name].Help, Total: g.Total, Several: !metricsreport.Partition(byName[g.Name])}
		for _, r := range g.Rows {
			label := strings.TrimSpace(r.Scope + " " + r.Value)
			if label == "" {
				label = g.Name
			}
			sg.Rows = append(sg.Rows, MetricsShare{Label: label, N: r.N, Share: r.Share})
		}
		out = append(out, sg)
	}
	return day, out
}

// metricsCandidateRow decorates a candidate with its tier line, link and key; span is the days its rows were read over.
func metricsCandidateRow(c metricsreport.Candidate, tiers []observability.DayTotal, span int, p metricsParams) MetricsCandidateRow {
	anchor := metricsAnchor(c.Name, c.Scope, c.Value)
	c.RateText = metricsRateWords(c.RateText)
	return MetricsCandidateRow{
		Candidate:    c,
		LastSeenText: metricsLastSeen(c.LastSeen, span),
		Tiers:        metricsreport.TierLine(tiers, metricsreport.Unit{Name: c.Name, Scope: c.Scope, Value: c.Value}),
		URL:          p.link("feature", "name", c.Name),
		Key:          c.Name + "|" + c.Scope + "|" + c.Value,
		Reason:       metricsReason(c),
		CountedOn:    metricsBasisWords(c.On),
		OutOf:        metricsOutOf(c),
		Anchor:       anchor,
		RemoveURL:    metricsRemoveLink(p, c.Area) + "#" + anchor,
	}
}

// metricsCountWords names in words the counts a Denom points at.
var metricsCountWords = map[string]string{
	"alerts.create": "alerts created",
	"api.call":      "price API calls",
	"search.result": "results page views",
	"sleepers.page": "sleepers page views",
	"upload.mode":   "priced upload views",
}

// metricsRateWords swaps a rate text's trailing registry name for its words; anything else is left as is.
func metricsRateWords(text string) string {
	body, suffix := text, ""
	if i := strings.Index(text, " ("); i >= 0 {
		body, suffix = text[:i], text[i:]
	}
	i := strings.LastIndex(body, " ")
	if words, ok := metricsCountWords[body[i+1:]]; ok && i >= 0 {
		return body[:i+1] + words + suffix
	}
	return text
}

// metricsBasisWords says what a candidate is counted on in words.
func metricsBasisWords(on metricsreport.CountedOn) string {
	switch on.Kind {
	case metricsreport.OnFlushDays:
		if on.Scripts {
			return "days the counter ran and a page loaded its scripts"
		}
		return "days the counter ran"
	case metricsreport.OnEveryPage:
		if on.Scripts {
			return "page loads with scripts, on every page"
		}
		return "views of every page"
	case metricsreport.OnPages:
		if on.Scripts {
			return "page loads with scripts on the " + metricsPagesWords(on.Pages)
		}
		return "views of the " + metricsPagesWords(on.Pages)
	case metricsreport.OnDenom:
		if w, ok := metricsCountWords[on.Name]; ok {
			return w
		}
		return on.Name
	case metricsreport.OnNoRows:
		return "no rows for this metric on this site in the window"
	}
	return "nothing named"
}

// metricsPagesWords is "search page" or "search and alerts pages" for a comma list.
func metricsPagesWords(list string) string {
	pages := strings.Split(list, ",")
	if len(pages) == 1 {
		return pages[0] + " page"
	}
	return strings.Join(pages[:len(pages)-1], ", ") + " and " + pages[len(pages)-1] + " pages"
}

// metricsOutOf is the count a candidate's rate is taken of, in words; "" when it is counted on days.
func metricsOutOf(c metricsreport.Candidate) string {
	if c.Denom <= 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", c.Denom, metricsBasisWords(c.On))
}

// metricsAnchor is a row id from its key: lowercase, anything outside [a-z0-9_.-] made "_".
func metricsAnchor(name, scope, value string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
				return r
			}
			return '_'
		}, strings.ToLower(s))
	}
	return "rm-" + clean(name) + "--" + clean(scope) + "--" + clean(value)
}

// metricsRemoveLink is the Remove view with area open; an empty area adds nothing.
func metricsRemoveLink(p metricsParams, area string) string {
	if area == "" {
		return p.link("remove")
	}
	return p.link("remove", "area", area)
}

// metricsSummary counts rows by class in words.
func metricsSummary(kinds []MetricsRemoveKind) string {
	n := map[string]int{}
	for _, k := range kinds {
		for _, r := range k.Rows {
			n[r.Class]++
		}
	}
	var parts []string
	for _, c := range []struct{ class, word string }{
		{metricsreport.ClassUnused, "unused"},
		{metricsreport.ClassRare, "rare"},
		{metricsreport.ClassUnusedSoFar, "unused so far"},
	} {
		if n[c.class] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[c.class], c.word))
		}
	}
	return strings.Join(parts, ", ")
}

// metricsTotal is every area's candidates in words: "12 candidates: 9 unused, 3 rare", or
// "12 candidates, all unused" when one class holds them all; "" with none.
func metricsTotal(areas []MetricsRemoveArea) string {
	var kinds []MetricsRemoveKind
	rows := 0
	for _, a := range areas {
		for _, k := range a.Kinds {
			kinds = append(kinds, k)
			rows += len(k.Rows)
		}
	}
	if rows == 0 {
		return ""
	}
	summary := metricsSummary(kinds)
	// one class holds every row: say it once
	if !strings.Contains(summary, ", ") {
		_, class, _ := strings.Cut(summary, " ")
		if rows == 1 {
			return "1 candidate, " + class
		}
		return fmt.Sprintf("%d candidates, all %s", rows, class)
	}
	return fmt.Sprintf("%d candidates: %s", rows, summary)
}

// metricsReason says why a not-measured candidate is not; "" for any other class.
func metricsReason(c metricsreport.Candidate) string {
	switch {
	case c.Class != metricsreport.ClassNotMeasured:
		return ""
	case c.On.Kind == metricsreport.OnNoRows:
		return "No rows for this metric on this site in the window."
	}
	return fmt.Sprintf("%d days measured, %d needed; counted on %s", c.DaysMeasured, metricsreport.MinDaysMeasured, metricsBasisWords(c.On))
}

// metricsRemovable reports whether a class is one the Overview lists to remove.
func metricsRemovable(class string) bool {
	switch class {
	case metricsreport.ClassUnused, metricsreport.ClassRare, metricsreport.ClassUnusedSoFar:
		return true
	}
	return false
}

// metricsTopCandidates are the first ten removable rows and, by area, how many more there are.
func metricsTopCandidates(candidates []metricsreport.Candidate, tiers []observability.DayTotal, span int, p metricsParams) ([]MetricsCandidateRow, []MetricsMoreArea) {
	var top []MetricsCandidateRow
	more := map[string]int64{}
	for _, c := range candidates {
		if !metricsRemovable(c.Class) {
			continue
		}
		if len(top) < metricsTopRows {
			top = append(top, metricsCandidateRow(c, tiers, span, p))
		} else {
			more[c.Area]++
		}
	}
	var areas []MetricsMoreArea
	for area, n := range more {
		areas = append(areas, MetricsMoreArea{Area: area, Rows: n})
	}
	slices.SortFunc(areas, func(a, b MetricsMoreArea) int {
		return cmp.Or(cmp.Compare(b.Rows, a.Rows), cmp.Compare(a.Area, b.Area))
	})
	return top, areas
}

// buildMetricsRemove groups the removal candidates by area and kind, the rest collapsed; span is the days totals cover.
// tiersOK says the tier split was read.
func buildMetricsRemove(names []observability.Name, lists metricsreport.Lists, totals, tiers []observability.DayTotal, tiersOK bool, reviews []observability.Review, span int, p metricsParams) *MetricsRemove {
	candidates := metricsreport.Candidates(names, lists, observability.Settings(), totals, reviews, p.window(), p.foreign())
	out := &MetricsRemove{}
	byArea := map[string]map[string][]MetricsCandidateRow{}
	for _, c := range candidates {
		row := metricsCandidateRow(c, tiers, span, p)
		if !tiersOK {
			row.Tiers = metricsTiersFailedText
		}
		switch {
		case c.Class == metricsreport.ClassNotMeasured:
			out.NotMeasured = append(out.NotMeasured, row)
		case c.Class == metricsreport.ClassReviewed:
			out.Reviewed = append(out.Reviewed, row)
		case metricsRemovable(c.Class):
			if byArea[c.Area] == nil {
				byArea[c.Area] = map[string][]MetricsCandidateRow{}
			}
			byArea[c.Area][c.Kind] = append(byArea[c.Area][c.Kind], row)
		}
	}
	// areas in the registry's order of first appearance
	var seen []string
	for _, n := range names {
		if kinds, ok := byArea[n.Area]; ok && !slices.Contains(seen, n.Area) {
			seen = append(seen, n.Area)
			area := MetricsRemoveArea{Area: n.Area}
			for _, kind := range metricsKinds(kinds) {
				rows := kinds[kind]
				area.Kinds = append(area.Kinds, MetricsRemoveKind{Kind: kind, Rows: rows,
					HasOutOf: slices.ContainsFunc(rows, func(r MetricsCandidateRow) bool { return r.OutOf != "" }),
					HasTiers: slices.ContainsFunc(rows, func(r MetricsCandidateRow) bool { return r.Tiers != "" })})
			}
			area.Summary, area.Open = metricsSummary(area.Kinds), p.Area != "" && n.Area == p.Area
			out.Areas = append(out.Areas, area)
		}
	}
	for _, r := range metricsreport.Orphans(reviews, candidates) {
		out.Reviewed = append(out.Reviewed, metricsGoneRow(r))
	}
	out.Total = metricsTotal(out.Areas)
	if len(out.Areas) == 0 {
		out.Empty = metricsRemoveEmpty(names, lists, totals, p.window())
	}
	return out
}

// metricsGoneRow is a review mark whose unit is no longer listed: its stored key as text, with
// its area and help while the name is registered.
func metricsGoneRow(r observability.Review) MetricsCandidateRow {
	row := MetricsCandidateRow{
		Candidate: metricsreport.Candidate{Name: r.Name, Scope: r.Scope, Value: r.Value, Class: metricsreport.ClassReviewed, Verdict: r.Verdict, Note: r.Note},
		Key:       r.Name + "|" + r.Scope + "|" + r.Value,
		Anchor:    metricsAnchor(r.Name, r.Scope, r.Value),
		Gone:      true,
	}
	if n, ok := observability.Lookup(r.Name); ok {
		row.Area, row.Help = n.Area, n.Help
	}
	return row
}

// metricsKinds orders an area's kinds: metricsKindOrder first, then any other by name.
func metricsKinds(kinds map[string][]MetricsCandidateRow) []string {
	rank := func(kind string) int {
		if i := slices.Index(metricsKindOrder, kind); i >= 0 {
			return i
		}
		return len(metricsKindOrder)
	}
	out := slices.Collect(maps.Keys(kinds))
	slices.SortFunc(out, func(a, b string) int { return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a, b)) })
	return out
}

// buildMetricsInvest is Invest's six sections over the window, script errors not measured until 2f;
// visitsOK says the page hits behind pages were read.
func buildMetricsInvest(names []observability.Name, totals, tiers []observability.DayTotal, tiersOK bool, pages []metricsreport.PageDepth, visitsOK bool, p metricsParams) *MetricsInvest {
	w := p.window()
	signals := metricsreport.WithErrors(metricsreport.Invest(names, totals, pages, w), nil, false)
	days, prevDays := metricsreport.WindowDays(totals, w)
	registered := metricsRegistered(names)
	var rows []MetricsSignalRow
	for _, s := range signals {
		r := metricsSignalRow(s, tiers, days, prevDays, registered, p)
		if !tiersOK && r.Section == metricsreport.SectionWalls && !r.NotMeasured {
			r.Tiers = metricsTiersFailedText
		}
		rows = append(rows, r)
	}
	sections := metricsSections(rows)
	reach := metricsreport.ReachOf(totals, w)
	for i := range sections {
		sections[i].Empty = metricsSectionEmpty(sections[i].Key, reach, visitsOK, w)
	}
	return &MetricsInvest{Sections: sections, VisitsRead: metricsRead(visitsOK)}
}

// metricsSectionEmpty is what an Invest section with no rows says once the counts were read.
func metricsSectionEmpty(key string, reach metricsreport.Reach, visitsOK bool, w metricsreport.Window) string {
	switch {
	case (key == metricsreport.SectionMobile || key == metricsreport.SectionDepth) && !visitsOK:
		return "The page hits could not be read just now, so this is not known; reload the page to try again."
	case key == metricsreport.SectionGrowing && !reach.Growing:
		return fmt.Sprintf("Not enough counted days to compare yet: it needs %d in each of the last two 30-day periods; the earlier has %d, the later %d.",
			metricsreport.MinDaysMeasured, reach.GrowingDays[1], reach.GrowingDays[0])
	case key == metricsreport.SectionNew && !reach.New:
		return fmt.Sprintf("Not enough counted days to compare yet: it needs %d in the %d days before the window; they have %d.",
			metricsreport.MinDaysMeasured, w.Days, reach.NewDays)
	}
	return metricsNothingToReport
}

// metricsNothingToReport is an Invest section's empty text once it could be counted and compared.
const metricsNothingToReport = "Nothing to report"

// metricsSections puts rows under the six sections, each present even when empty.
func metricsSections(rows []MetricsSignalRow) []MetricsInvestSection {
	out := make([]MetricsInvestSection, len(metricsInvestSections))
	for i, s := range metricsInvestSections {
		out[i] = MetricsInvestSection{Key: s.key, Title: s.title, Note: s.note, Empty: metricsNothingToReport}
		for _, r := range rows {
			if r.Section == s.key {
				out[i].Rows = append(out[i].Rows, r)
				if !r.NotMeasured {
					out[i].HasPrevious = out[i].HasPrevious || r.PrevText != ""
					out[i].HasEvidence = out[i].HasEvidence || r.Evidence != ""
					out[i].HasTiers = out[i].HasTiers || r.Tiers != ""
				}
			}
		}
		out[i].Span = 3
		for _, has := range []bool{out[i].HasPrevious, out[i].HasEvidence, out[i].HasTiers} {
			if has {
				out[i].Span++
			}
		}
	}
	return out
}

// metricsSignalRow decorates an Invest row; days and prevDays are the counted days of the window and the one before.
func metricsSignalRow(s metricsreport.Signal, tiers []observability.DayTotal, days, prevDays int, registered map[string]bool, p metricsParams) MetricsSignalRow {
	r := MetricsSignalRow{Signal: s}
	if registered[s.Name] {
		r.URL = p.link("feature", "name", s.Name)
	}
	if s.NotMeasured {
		return r
	}
	if s.HasRate() {
		if s.Section == metricsreport.SectionGrowing {
			r.RateText = fmt.Sprintf("%.1fx", s.Rate)
		} else {
			r.RateText = fmt.Sprintf("%.1f%%", s.Rate*100)
		}
	}
	if s.Section == metricsreport.SectionWalls {
		r.Tiers = metricsreport.TierLine(tiers, metricsreport.Unit{Name: s.Name, Scope: s.Scope, Value: s.Value})
	}
	r.PrevText, r.Trend = metricsreport.PreviousText(s, days, prevDays)
	return r
}

// metricsReadFailedText is what a block says when its read did not answer.
const metricsReadFailedText = "This part could not be read just now; reload the page to try again."

// The chart ids the page script finds its canvases by.
const (
	metricsDaysChart    = "metrics-days"
	metricsExploreChart = "metrics-explore"
	metricsSparkChart   = "metrics-spark-" // plus the row's index
)

const (
	metricsHourDays   = metricsreport.MinuteDays // the hourly view's reach: what the minute rows keep
	metricsClientDays = 7                        // days of beacon reasons Health reads
	metricsNoneLabel  = "(none)"                 // an empty scope or value listed beside named ones
	metricsNoArea     = "no area"                // Explore's group word for a name with no area
)

// metricsClientNames are the beacon endpoint's reason names, in the order Health lists them.
var metricsClientNames = []string{"metrics.beacon", "metrics.client"}

// MetricsRead says whether one block's read answered; Message is the fixed text when it did not.
type MetricsRead struct {
	Failed  bool
	Message string
}

// metricsRead is the MetricsRead of a read that answered or not.
func metricsRead(ok bool) MetricsRead {
	if ok {
		return MetricsRead{}
	}
	return MetricsRead{Failed: true, Message: metricsReadFailedText}
}

// MetricsFeature is the Feature view: the area index, an area's names, or one name.
type MetricsFeature struct {
	// The index, when neither a name nor an area is asked for.
	Areas      []MetricsAreaRow // areas of candidate and signal names, most counted events first
	OtherAreas []MetricsAreaRow // areas whose names are context, internal or stored state; Events is 0
	// Counted is true once the page's counts were read on a complete day (a stored-state name:
	// read at all): an empty list is then a finding. False with Read not failed: nothing complete yet.
	Counted bool

	// The area page.
	Area  string
	Names []MetricsNameRow // one a name of the area, registry order

	// The name page.
	NoSuchName bool                // a name was asked for that this registry does not have; nothing was read
	Name       *observability.Name // the name, its Help, Kind and Area
	Family     string              // familyLabel of the name's family
	Standing   bool                // a stored-state name: Total and shares are StockDay's alone
	Several    bool                // the parts do not add up to Total, so no share is shown: not metricsreport.Partition
	StockDay   time.Time           // the newest day with a row of the name; zero when none
	HasRows    bool                // the name has a row in the window (on StockDay when Standing)
	Total      int64
	Values     []MetricsShare // shares of Total, largest first; with registry values that have no rows
	Scopes     []MetricsShare
	Tiers      []MetricsShare // shares of the tier split's own total; empty for a stored-state name
	Devices    []MetricsShare
	DaysID     string // id of the line per day; "" when no chart was built
	AreaURL    string // the name's area page; "" for a name with no area
	ExploreURL string

	Read        MetricsRead // the area or name rows (and the index's counts); Failed too when the newest complete day could not be read
	TiersRead   MetricsRead // as Read, for the tier split
	DevicesRead MetricsRead // as Read, for the device split
}

// MetricsNameRow is one name on an area page.
type MetricsNameRow struct {
	Name, Kind, Help string
	Family           string    // familyLabel
	Standing         bool      // a stored-state name: Count is Day's standing count, never a sum
	Day              time.Time // Standing only: the newest stock day; zero when the name has no row
	Counted          bool      // Count was read: false before a fold (day names) or when the read failed
	Count, Denom     int64
	Rate             float64 // Count over Denom as a fraction, 0 without Denom
	RateText         string  // "0.50% of results page views", "1.25% of requests", or ""
	NoRate           string  // metricsreport.Use's NoRate: why a counted day name has no RateText; "" otherwise
	SparkID          string  // "" when no spark was built
	URL              string
}

// MetricsHealth is the Health view; nothing in it depends on the toggles or the window.
type MetricsHealth struct {
	Counters      []MetricsCounterRow // every instance's counter, shared and blank left out
	Jobs          []MetricsJobRow     // one a job.run scope, in registry order
	CountersRead  MetricsRead         // counters and job runs come from one read
	Problems      []string            // metricsreport.Problems for the instance; nil when the read failed
	Rejected      int64               // metrics.rejected for the instance since yesterday
	MinuteDays    int                 // how far back job runs reach: metricsreport.MinuteDays
	SilentCounted bool                // Silent was judged on a complete day; false with SilentRead not failed: nothing complete yet
	SilentRead    MetricsRead         // Failed too when the newest complete day could not be read
	Broken        []MetricsNameLink   // every-view counts missing while their pages had views
	Quiet         []MetricsNameLink   // every-view counts missing on pages with no views
	// ClientMeasured is false while metrics.beacon is not registered: Client then reads "not measured".
	ClientMeasured bool
	ClientCounted  bool                 // the reasons were read on a complete day; only then is an empty Client "no reasons in 7 days"
	ClientRead     MetricsRead          // Failed too when the newest complete day could not be read
	Client         []MetricsClientRow   // the last 7 folded days' reasons
	ScriptErrors   *MetricsScriptErrors // nil reads "not measured"; 2f fills it
	// Checked is true when every block above was read on a complete day, so an empty Problems means none.
	Checked   bool
	Unchecked []string // what could not be checked and why, one line a block; empty when Checked
	// DroppedHelp and RejectedHelp are the registry Help of metrics.dropped and metrics.rejected, for the legend.
	DroppedHelp, RejectedHelp string
}

// MetricsCounterRow is one instance's counter since the start of yesterday.
type MetricsCounterRow struct {
	Instance                       string
	Current                        bool      // the instance the view is about
	LastFlush                      time.Time // zero when none since yesterday
	Live                           bool      // LastFlush is at most ten minutes old
	Rows                           int64     // minute rows stamped yesterday
	RowsNote                       string    // in place of Rows when it saved today with no rows yesterday; "" otherwise
	Dropped, FlushFailed, Rejected int64
	NoRows                         bool   // the instance wrote nothing since the start of yesterday; the row is there so the table says so
	Reason                         string // why, when NoRows: metricsCounterOffText or metricsNoCountsText
}

// MetricsJobRow is one metrics job's newest run on whichever instance ran it.
type MetricsJobRow struct {
	Job, Instance, Result string        // Instance and Result of the deciding run (newest ok or fail); "" when none
	At                    time.Time     // that run; zero when none in 14 days
	LastOK                time.Time     // the newest ok run on any instance; zero when none
	Status                string        // metricsreport.JobOK, JobNoRun, JobFailed or JobOverdue
	StatusText            string        // Status in words
	LastRunText           string        // At, its result and instance in words, or "none in 14 days"
	LastOKText            string        // LastOK's time, or "none in 14 days"
	Problem               string        // the same line Problems gives for the job; "" when it is fine
	Threshold             time.Duration // the age past which an ok run is overdue (36 hours)
	Runners               []string      // every instance with a run of the job, sorted
	Note                  string        // metricsreport.JobNote
}

// MetricsNameLink is a registry name with its Help and feature page.
type MetricsNameLink struct {
	Name, Help, URL string
}

// MetricsClientRow is one reason the beacon endpoint gave, never a name.
type MetricsClientRow struct {
	Name, Reason string // metrics.beacon or metrics.client, and its value
	Help         string // the name's registry Help
	N            int64
	Share        float64 // of that name's total, a fraction
}

// MetricsScriptErrors is the Health view's script error block.
type MetricsScriptErrors struct {
	Build     string // the build the rows are for
	RowsToday int    // feature_errors rows written today, of the day's cap
	Rows      []MetricsScriptError
}

// MetricsScriptError is one script error row.
type MetricsScriptError struct {
	Script, Class       string
	Line                int
	N, Desktop, Mobile  int64
	FirstSeen, LastSeen time.Time
}

// MetricsExplore is the Explore view: one name's rows by scope and value.
type MetricsExplore struct {
	Groups     []MetricsNameGroup // every registry name, by family and area
	Hidden     []MetricsField     // the name form's other parameters
	NoSuchName bool               // a name was asked for that this registry does not have; nothing was read
	Name, Help string
	Standing   bool      // a stored-state name: rows and Total are StockDay's alone
	Several    bool      // the rows do not add up to Total, so no share is shown: not metricsreport.Partition
	StockDay   time.Time // zero when the name has no row
	Hourly     bool      // rows and line are by hour since HoursFrom
	MinuteDays int       // how far back by hour reads: metricsreport.MinuteDays
	HoursFrom  time.Time // the first hour read, metricsHourDays back
	Rows       []MetricsExploreRow
	Total      int64
	LineID     string      // "" when no chart was built
	Counted    bool        // the rows were read on a complete day (by hour or stored state: read at all); false with Read not failed: nothing complete yet
	HourlyLink MetricsLink // flips by hour and by day; zero for a stored-state name or no name
	FeatureURL string
	Read       MetricsRead
}

// MetricsNameGroup is one family and area of names; Active marks the name shown.
type MetricsNameGroup struct {
	Label string // "Server: search"
	Names []MetricsLink
}

// MetricsField is one hidden form parameter.
type MetricsField struct {
	Key, Value string
}

// MetricsExploreRow is one scope and value of the name.
type MetricsExploreRow struct {
	Scope, Value string
	N            int64
	Share        float64 // of Total, a fraction
}

// metricsName finds name in names.
func metricsName(names []observability.Name, name string) (observability.Name, bool) {
	i := slices.IndexFunc(names, func(n observability.Name) bool { return n.Name == name })
	if i < 0 || name == "" {
		return observability.Name{}, false
	}
	return names[i], true
}

// metricsStanding reports whether a name is a standing count, read under SharedInstance by day.
func metricsStanding(n observability.Name) bool {
	return n.Family == observability.FamilyStock
}

// metricsDayQuery is names by day over the window: stored state under SharedInstance up to
// today with the toggles off (its rows carry their day and no reader), anything else up to day.
func metricsDayQuery(names []string, standing bool, inst string, day, now time.Time, w metricsreport.Window) observability.DayQuery {
	if standing {
		return observability.DayQuery{Instance: observability.SharedInstance, To: utcDay(now), Days: w.Days, Step: 1, Names: names}
	}
	return observability.DayQuery{Instance: inst, To: day, Days: w.Days, Step: 1, Signed: w.Signed, Humans: w.Humans, Names: names}
}

// days loads q under report and label; every part of q comes from validated values.
func (l *metricsLoader) days(report, label string, q observability.DayQuery) ([]observability.DayTotal, bool) {
	k := metricsreport.Key{Report: report, Instance: q.Instance, Name: label, Days: q.Days, Signed: q.Signed, Humans: q.Humans, To: metricsDate(q.To)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) ([]observability.DayTotal, error) {
		return l.store.DayTotals(ctx, q)
	})
}

// metricsNameRows is one metric's rows by day and, for a day name, its tier and device splits.
type metricsNameRows struct {
	Days, Tiers, Devices []observability.DayTotal
}

// nameRows loads a metric page under one key: its by-day query q (metricsDayQuery's) and, for a
// day name, the window split by tier and by device. Feature and Explore share the entry.
func (l *metricsLoader) nameRows(n observability.Name, inst string, day time.Time, w metricsreport.Window) (metricsNameRows, observability.DayQuery, bool) {
	standing := metricsStanding(n)
	q := metricsDayQuery([]string{n.Name}, standing, inst, day, l.now, w)
	k := metricsreport.Key{Report: "name", Instance: q.Instance, Name: n.Name, Days: q.Days, Signed: q.Signed, Humans: q.Humans, To: metricsDate(q.To)}
	rows, ok := metricsGet(l, k, metricsUntilFold, func(ctx context.Context) (metricsNameRows, error) {
		var out metricsNameRows
		var err error
		if out.Days, err = l.store.DayTotals(ctx, q); err != nil || standing {
			return out, err
		}
		split := observability.DayQuery{Instance: inst, To: day, Days: w.Days, Signed: w.Signed, Humans: w.Humans, Names: q.Names}
		byTier, byDevice := split, split
		byTier.ByTier, byDevice.ByDevice = true, true
		if out.Tiers, err = l.store.DayTotals(ctx, byTier); err != nil {
			return out, err
		}
		out.Devices, err = l.store.DayTotals(ctx, byDevice)
		return out, err
	})
	return rows, q, ok
}

// metricsAreaRows is an area page's rows by day: its day names' and its stored-state names'.
type metricsAreaRows struct {
	Days, Stock []observability.DayTotal
}

// areaRows loads an area page's by-day rows under one key; day names are read only after a fold.
func (l *metricsLoader) areaRows(area string, dayNames, stockNames []string, inst string, day time.Time, folded bool, w metricsreport.Window) (metricsAreaRows, bool) {
	if !folded {
		dayNames = nil
		day = time.Time{}
	}
	if len(dayNames) == 0 && len(stockNames) == 0 {
		return metricsAreaRows{}, true
	}
	today := utcDay(l.now)
	k := metricsreport.Key{Report: "area", Instance: inst, Name: area, Days: w.Days, Signed: w.Signed, Humans: w.Humans, To: metricsDate(day) + "/" + metricsDate(today)}
	return metricsGet(l, k, metricsUntilFold, func(ctx context.Context) (metricsAreaRows, error) {
		var out metricsAreaRows
		var err error
		if len(dayNames) > 0 {
			if out.Days, err = l.store.DayTotals(ctx, metricsDayQuery(dayNames, false, inst, day, l.now, w)); err != nil {
				return out, err
			}
		}
		if len(stockNames) > 0 {
			out.Stock, err = l.store.DayTotals(ctx, metricsDayQuery(stockNames, true, inst, day, l.now, w))
		}
		return out, err
	})
}

// metricsHourSince is the first hour of the hourly view: metricsHourDays of hours ending with now's.
func metricsHourSince(now time.Time) time.Time {
	return now.UTC().Truncate(time.Hour).Add(-(metricsHourDays*24 - 1) * time.Hour)
}

// hours is one name's minute rows by hour since since, at most a minute old. The key holds no
// hour: the minute maximum age keeps it fresh, and a row before since is dropped when filled.
func (l *metricsLoader) hours(name, inst string, w metricsreport.Window, since time.Time) ([]observability.HourTotal, bool) {
	k := metricsreport.Key{Report: "hours", Instance: inst, Name: name, Days: metricsHourDays, Signed: w.Signed, Humans: w.Humans}
	return metricsGet(l, k, metricsMinuteMaxAge, func(ctx context.Context) ([]observability.HourTotal, error) {
		return l.store.HourTotals(ctx, observability.DayQuery{Instance: inst, Names: []string{name}, Signed: w.Signed, Humans: w.Humans}, since)
	})
}

// feature builds the Feature view: a name page, an area page or the area index.
func (l *metricsLoader) feature(v *MetricsView, names []observability.Name, p metricsParams, day time.Time, folded bool) *MetricsFeature {
	f := &MetricsFeature{}
	w := p.window()
	switch {
	case p.Name != "" || p.UnknownName:
		n, ok := metricsName(names, p.Name)
		if !ok {
			f.NoSuchName = true
			return f
		}
		standing := metricsStanding(n)
		metricsFeatureName(f, n, p)
		if !standing {
			f.Read = metricsRead(v.FoldedKnown)
			f.TiersRead, f.DevicesRead = f.Read, f.Read
		}
		if !standing && !folded {
			return f
		}
		rows, q, ok := l.nameRows(n, p.Instance, day, w)
		f.Read, f.Counted = metricsRead(ok), ok
		if !standing {
			f.TiersRead, f.DevicesRead = f.Read, f.Read
		}
		if ok {
			if c := fillMetricsName(f, n, rows.Days, rows.Tiers, rows.Devices, q.To, w.Days); c != nil {
				v.Charts = append(v.Charts, *c)
			}
		}
	case p.Area != "" && slices.ContainsFunc(names, func(n observability.Name) bool { return n.Area == p.Area }):
		f.Area = p.Area
		var members []observability.Name
		var dayNames, stockNames []string
		for _, n := range names {
			if n.Area != p.Area {
				continue
			}
			members = append(members, n)
			if metricsStanding(n) {
				stockNames = append(stockNames, n.Name)
			} else {
				dayNames = append(dayNames, n.Name)
			}
		}
		var totals []observability.DayTotal
		totalsOK := v.FoldedKnown || len(dayNames) == 0
		if folded && len(dayNames) > 0 {
			totals, totalsOK = l.totals(p.Instance, day, w)
			if totalsOK {
				v.Coverage = metricsCoverage(totals, nil, false, w)
			}
		}
		rows, rowsOK := l.areaRows(p.Area, dayNames, stockNames, p.Instance, day, folded, w)
		dayOK := totalsOK && rowsOK
		f.Read = metricsRead(dayOK)
		f.Counted = rowsOK && (len(dayNames) == 0 || (folded && totalsOK))
		v.Charts = append(v.Charts, fillMetricsArea(f, members, totals, rows.Days, rows.Stock, metricsAreaDays{
			day: day, today: utcDay(l.now), w: w, dayCounted: folded && dayOK, stockCounted: rowsOK,
		}, p)...)
	default:
		var totals []observability.DayTotal
		f.Read = metricsRead(v.FoldedKnown)
		if folded {
			var ok bool
			totals, ok = l.totals(p.Instance, day, w)
			f.Read = metricsRead(ok)
			f.Counted = ok
			if ok {
				v.Coverage = metricsCoverage(totals, nil, false, w)
			}
		}
		f.Areas, f.OtherAreas = metricsAreaIndex(names, totals, f.Counted, w, p)
	}
	return f
}

// metricsFeatureName fills the name page's registry facts and links.
func metricsFeatureName(f *MetricsFeature, n observability.Name, p metricsParams) {
	f.Name = &n
	f.Family = familyLabel(n.Family)
	f.Standing = metricsStanding(n)
	f.Several = !metricsreport.Partition(n)
	if n.Area != "" {
		f.AreaURL = p.link("feature", "area", n.Area)
	}
	f.ExploreURL = p.link("explore", "name", n.Name)
}

// fillMetricsName fills the name page from its rows by day ending on to and its splits; the chart is nil when there is none.
func fillMetricsName(f *MetricsFeature, n observability.Name, rows, tiers, devices []observability.DayTotal, to time.Time, days int) *MetricsChart {
	values, scopes := map[string]int64{}, map[string]int64{}
	last := to
	if metricsStanding(n) {
		day, groups := metricsreport.Stock([]observability.Name{n}, rows)
		f.StockDay, last = day, day
		for _, g := range groups {
			f.Total += g.Total
			for _, r := range g.Rows {
				values[r.Value] += r.N
				scopes[r.Scope] += r.N
			}
		}
		f.HasRows = len(groups) > 0
		// a bucket with no row is absent, not zero, so no registry values are added
		f.Values, f.Scopes = metricsShares(values, nil), metricsShares(scopes, nil)
		if day.IsZero() {
			return nil
		}
	} else {
		for _, t := range rows {
			if t.Name != n.Name {
				continue
			}
			f.Total += t.N
			values[t.Value] += t.N
			scopes[t.Scope] += t.N
			f.HasRows = true
		}
		var enum []string
		if n.Values == observability.ValueEnum || n.Values == observability.ValueBucket {
			enum = n.Enum
		}
		f.Values, f.Scopes = metricsShares(values, enum), metricsShares(scopes, nil)
		f.Tiers = metricsShares(metricsSplit(tiers, n.Name, func(t observability.DayTotal) string { return t.Tier }), nil)
		f.Devices = metricsShares(metricsSplit(devices, n.Name, func(t observability.DayTotal) string { return t.Device }), nil)
	}
	labels, data := metricsDaySeries(rows, n.Name, to, days, last)
	if len(data) == 0 {
		return nil
	}
	f.DaysID = metricsDaysChart
	return &MetricsChart{ID: metricsDaysChart, Kind: "line", Labels: labels, Series: []MetricsSeries{{Label: n.Name, Data: data}}}
}

// metricsSplit sums a name's rows by the key part gives.
func metricsSplit(rows []observability.DayTotal, name string, part func(observability.DayTotal) string) map[string]int64 {
	out := map[string]int64{}
	for _, t := range rows {
		if t.Name == name {
			out[part(t)] += t.N
		}
	}
	return out
}

// metricsShares is counts as shares of their sum, largest first; order's labels are listed even
// with no count. Empty when every label is "", since then there is nothing to break down.
func metricsShares(counts map[string]int64, order []string) []MetricsShare {
	labels := slices.Clone(order)
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		if !slices.Contains(labels, k) {
			labels = append(labels, k)
		}
	}
	if !slices.ContainsFunc(labels, func(s string) bool { return s != "" }) {
		return nil
	}
	var total int64
	for _, n := range counts {
		total += n
	}
	out := make([]MetricsShare, 0, len(labels))
	for _, label := range labels {
		s := MetricsShare{Label: label, N: counts[label]}
		if s.Label == "" {
			s.Label = metricsNoneLabel
		}
		if total > 0 {
			s.Share = float64(s.N) / float64(total)
		}
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b MetricsShare) int { return cmp.Compare(b.N, a.N) })
	return out
}

// metricsDaySeries is one point a day of a name's Step 1 rows counted back from to, oldest first,
// from the window's first day through last; a day with no row is zero.
func metricsDaySeries(rows []observability.DayTotal, name string, to time.Time, days int, last time.Time) ([]string, []int64) {
	end := max(0, int(to.Sub(last).Hours()/24)) // the period of last
	if end >= days {
		return nil, nil
	}
	data := make([]int64, days-end)
	for _, t := range rows {
		if t.Name == name && t.Period >= end && t.Period < days {
			data[days-1-t.Period] += t.N
		}
	}
	labels := make([]string, len(data))
	for i := range labels {
		labels[i] = metricsDate(to.AddDate(0, 0, -(days - 1 - i)))
	}
	return labels, data
}

// metricsAreaDays is what an area page's rows were read over.
type metricsAreaDays struct {
	day, today   time.Time // the folded day day names end on; today, stored state's last day
	w            metricsreport.Window
	dayCounted   bool // day names' bundle and rows answered after a fold
	stockCounted bool // the stored-state rows answered
}

// fillMetricsArea lists an area's names in registry order, each with its count and spark.
func fillMetricsArea(f *MetricsFeature, members []observability.Name, totals, rows, stock []observability.DayTotal, d metricsAreaDays, p metricsParams) []MetricsChart {
	stockDay, groups := metricsreport.Stock(members, stock)
	standing := map[string]int64{}
	for _, g := range groups {
		standing[g.Name] = g.Total
	}
	var charts []MetricsChart
	for i, n := range members {
		row := MetricsNameRow{Name: n.Name, Kind: n.Kind, Help: n.Help, Family: familyLabel(n.Family), URL: p.link("feature", "name", n.Name)}
		var labels []string
		var data []int64
		if metricsStanding(n) {
			row.Standing, row.Counted = true, d.stockCounted
			if total, ok := standing[n.Name]; ok && row.Counted {
				row.Count, row.Day = total, stockDay
				labels, data = metricsDaySeries(stock, n.Name, d.today, d.w.Days, stockDay)
			}
		} else if row.Counted = d.dayCounted; row.Counted {
			u := metricsreport.NameUse(n, totals, d.w)
			row.Count, row.Denom, row.Rate, row.RateText, row.NoRate = u.Count, u.Denom, u.Rate, metricsRateWords(u.RateText), u.NoRate
			labels, data = metricsDaySeries(rows, n.Name, d.day, d.w.Days, d.day)
		}
		if len(data) > 0 {
			row.SparkID = metricsSparkChart + strconv.Itoa(i)
			charts = append(charts, MetricsChart{ID: row.SparkID, Kind: "spark", Labels: labels, Series: []MetricsSeries{{Label: n.Name, Data: data}}})
		}
		f.Names = append(f.Names, row)
	}
	return charts
}

// metricsAreaIndex is the areas Areas lists, then every other area of the registry in its order.
func metricsAreaIndex(names []observability.Name, totals []observability.DayTotal, counted bool, w metricsreport.Window, p metricsParams) (ranked, other []MetricsAreaRow) {
	seen := map[string]bool{}
	for _, a := range metricsreport.Areas(names, totals, w) {
		row := MetricsAreaRow{Area: a.Area, URL: p.link("feature", "area", a.Area)}
		if counted {
			row.Events = a.Events
		}
		ranked = append(ranked, row)
		seen[a.Area] = true
	}
	for _, n := range names {
		if n.Area != "" && !seen[n.Area] {
			seen[n.Area] = true
			other = append(other, MetricsAreaRow{Area: n.Area, URL: p.link("feature", "area", n.Area)})
		}
	}
	return ranked, other
}

// healthView builds the Health view; it reads neither the toggles nor the window.
func (l *metricsLoader) healthView(names []observability.Name, p metricsParams, day time.Time, folded, known bool) *MetricsHealth {
	h := &MetricsHealth{SilentRead: metricsRead(known), MinuteDays: metricsHourDays}
	dropped, _ := metricsName(names, "metrics.dropped")
	rejected, _ := metricsName(names, "metrics.rejected")
	h.DroppedHelp, h.RejectedHelp = dropped.Help, rejected.Help
	// links ignore the toggles and the window, so the view is the same whatever they say
	links := metricsParams{View: "health", Instance: p.Instance, Days: metricsDefaultDays}
	health, ok := l.health()
	h.CountersRead = metricsRead(ok)
	var broken []string
	if folded {
		allReaders, silentOK := l.silent(p.Instance, day)
		h.SilentCounted, h.SilentRead = silentOK, metricsRead(silentOK)
		if silentOK {
			var quiet []string
			broken, quiet = metricsreport.Silent(names, allReaders)
			h.Broken, h.Quiet = metricsNameLinks(names, broken, links), metricsNameLinks(names, quiet, links)
		}
	}
	if _, measured := metricsName(names, "metrics.beacon"); measured {
		h.ClientMeasured, h.ClientRead = true, metricsRead(known)
		if folded {
			rows, clientOK := l.client(names, p.Instance, day)
			h.ClientCounted, h.ClientRead = clientOK, metricsRead(clientOK)
			h.Client = metricsClientRows(names, rows)
		}
	}
	if ok {
		h.Counters = metricsCounterRows(health.Counters, p.Instance, l.now, FeatureCounter != nil)
		for _, c := range h.Counters {
			if c.Current {
				h.Rejected = c.Rejected
			}
		}
		jobs := metricsJobNames(names)
		h.Jobs = metricsJobRows(jobs, health.Jobs, l.now)
		h.Problems = metricsreport.Problems(metricsreport.HealthInput{
			Now: l.now, Instance: p.Instance, Counters: health.Counters, Jobs: health.Jobs, JobNames: jobs, Broken: broken,
		})
	}
	h.Unchecked = metricsUnchecked(h)
	h.Checked = len(h.Unchecked) == 0
	return h
}

// client is the beacon endpoint's reasons over the last days ending on day, every reader.
func (l *metricsLoader) client(names []observability.Name, inst string, day time.Time) ([]observability.DayTotal, bool) {
	var want []string
	for _, name := range metricsClientNames {
		if _, ok := metricsName(names, name); ok {
			want = append(want, name)
		}
	}
	return l.days("client", "", observability.DayQuery{Instance: inst, To: day, Days: metricsClientDays, Names: want})
}

// metricsNameLinks are names with their Help and feature pages.
func metricsNameLinks(names []observability.Name, list []string, p metricsParams) []MetricsNameLink {
	var out []MetricsNameLink
	for _, name := range list {
		n, _ := metricsName(names, name)
		out = append(out, MetricsNameLink{Name: name, Help: n.Help, URL: p.link("feature", "name", name)})
	}
	return out
}

// What a counter row with no rows says.
const (
	metricsCounterOffText = "The counter is not running on this site."
	metricsNoCountsText   = "No counts received since the start of yesterday."
)

// metricsCounterRows are every instance's counters but shared and blank, as read, then a
// NoRows row for the viewed instance and this site's own when they wrote nothing; counterOn
// says whether this site's counter runs.
func metricsCounterRows(counters []observability.InstanceHealth, inst string, now time.Time, counterOn bool) []MetricsCounterRow {
	var out []MetricsCounterRow
	for _, c := range counters {
		if c.Instance == "" || c.Instance == observability.SharedInstance {
			continue
		}
		out = append(out, MetricsCounterRow{
			Instance: c.Instance, Current: c.Instance == inst, LastFlush: c.LastFlush,
			Live: !metricsreport.FlushStale(now, c.LastFlush),
			Rows: c.Rows, Dropped: c.Dropped, FlushFailed: c.FlushFailed, Rejected: c.Rejected,
			RowsNote: metricsRowsNote(c),
		})
	}
	for _, want := range []string{inst, observabilityInstance} {
		if want == "" || slices.ContainsFunc(out, func(r MetricsCounterRow) bool { return r.Instance == want }) {
			continue
		}
		reason := metricsNoCountsText
		if want == observabilityInstance && !counterOn {
			reason = metricsCounterOffText
		}
		out = append(out, MetricsCounterRow{Instance: want, Current: want == inst, NoRows: true, Reason: reason})
	}
	return out
}

// metricsJobRows is one row a job, judged by metricsreport.JobStateOf, with who ran it.
func metricsJobRows(jobs []string, runs []observability.JobRun, now time.Time) []MetricsJobRow {
	var out []MetricsJobRow
	for _, job := range jobs {
		st := metricsreport.JobStateOf(job, runs, now)
		row := MetricsJobRow{
			Job: job, Instance: st.Newest.Instance, Result: st.Newest.Result, At: st.Newest.At, LastOK: st.LastOK.At,
			Status: st.Status, StatusText: metricsJobStatusWords(st.Status, st.Threshold), Problem: st.Problem(),
			LastRunText: metricsRunWords(st.Newest), LastOKText: metricsWhen(st.LastOK.At), Threshold: st.Threshold, Note: metricsreport.JobNote(job),
		}
		for _, r := range runs {
			if r.Job == job && !slices.Contains(row.Runners, r.Instance) {
				row.Runners = append(row.Runners, r.Instance)
			}
		}
		slices.Sort(row.Runners)
		out = append(out, row)
	}
	return out
}

// metricsClientRows is one row a reason with rows, beacon first, each name's in its Enum order.
func metricsClientRows(names []observability.Name, rows []observability.DayTotal) []MetricsClientRow {
	var out []MetricsClientRow
	for _, name := range metricsClientNames {
		n, ok := metricsName(names, name)
		if !ok {
			continue
		}
		byReason := metricsSplit(rows, name, func(t observability.DayTotal) string { return t.Value })
		var total int64
		for _, c := range byReason {
			total += c
		}
		for _, reason := range n.Enum {
			if c := byReason[reason]; c > 0 {
				out = append(out, MetricsClientRow{Name: name, Reason: reason, Help: n.Help, N: c, Share: float64(c) / float64(total)})
			}
		}
	}
	return out
}

// explore builds the Explore view: the name picker and, for a name, its rows and line.
func (l *metricsLoader) explore(v *MetricsView, names []observability.Name, p metricsParams, day time.Time, folded bool) *MetricsExplore {
	e := &MetricsExplore{Groups: metricsNameGroups(names, p), Hidden: metricsHidden(p), MinuteDays: metricsHourDays}
	if p.Name == "" && !p.UnknownName {
		return e
	}
	n, ok := metricsName(names, p.Name)
	if !ok {
		e.NoSuchName = true
		return e
	}
	e.Name, e.Help, e.Standing, e.Several = n.Name, n.Help, metricsStanding(n), !metricsreport.Partition(n)
	e.FeatureURL = p.link("feature", "name", n.Name)
	w := p.window()
	if !e.Standing {
		flip := p
		flip.Hourly = !p.Hourly
		e.HourlyLink = MetricsLink{Label: fmt.Sprintf("By hour, last %d days", metricsHourDays), URL: flip.link("explore", flip.keep()...), Active: p.Hourly}
	}
	if !e.Standing && !p.Hourly {
		e.Read = metricsRead(v.FoldedKnown)
	}
	switch {
	case p.Hourly && !e.Standing:
		e.Hourly = true
		e.HoursFrom = metricsHourSince(l.now)
		hours, ok := l.hours(n.Name, p.Instance, w, e.HoursFrom)
		e.Read, e.Counted = metricsRead(ok), ok
		if ok {
			v.Charts = append(v.Charts, fillMetricsExploreHours(e, hours))
		}
	case e.Standing || folded:
		rows, q, ok := l.nameRows(n, p.Instance, day, w)
		e.Read, e.Counted = metricsRead(ok), ok
		if ok {
			if c := fillMetricsExploreDays(e, n, rows.Days, q.To, w.Days); c != nil {
				v.Charts = append(v.Charts, *c)
			}
		}
	}
	return e
}

// metricsNameGroups lists every name, Internal ones too, grouped by family and area in registry order.
func metricsNameGroups(names []observability.Name, p metricsParams) []MetricsNameGroup {
	var out []MetricsNameGroup
	at := map[string]int{}
	for _, n := range names {
		area := n.Area
		if area == "" {
			area = metricsNoArea
		}
		label := familyLabel(n.Family) + ": " + area
		i, ok := at[label]
		if !ok {
			i = len(out)
			at[label] = i
			out = append(out, MetricsNameGroup{Label: label})
		}
		extra := []string{"name", n.Name}
		if p.Hourly && !metricsStanding(n) {
			extra = append(extra, "hourly", "1")
		}
		out[i].Names = append(out[i].Names, MetricsLink{Label: n.Name, URL: p.link("explore", extra...), Active: n.Name == p.Name})
	}
	return out
}

// metricsHidden is the name form's parameters besides name, in link's order.
func metricsHidden(p metricsParams) []MetricsField {
	out := []MetricsField{{"page", "metrics"}, {"view", "explore"}}
	var extra []string
	if p.Hourly {
		extra = []string{"hourly", "1"}
	}
	rest := p.rest(extra...)
	for _, k := range slices.Sorted(maps.Keys(rest)) {
		out = append(out, MetricsField{Key: k, Value: rest.Get(k)})
	}
	return out
}

// metricsExploreRows is counts by scope and value, largest first, as shares of their total.
func metricsExploreRows(counts map[[2]string]int64) ([]MetricsExploreRow, int64) {
	var total int64
	var out []MetricsExploreRow
	for k, n := range counts {
		total += n
		out = append(out, MetricsExploreRow{Scope: k[0], Value: k[1], N: n})
	}
	for i := range out {
		if total > 0 {
			out[i].Share = float64(out[i].N) / float64(total)
		}
	}
	slices.SortFunc(out, func(a, b MetricsExploreRow) int {
		return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
	})
	return out, total
}

// fillMetricsExploreDays fills the rows from a name's rows by day ending on to: a stored-state
// name's newest day only, any other name's whole window. The chart is nil when there is none.
func fillMetricsExploreDays(e *MetricsExplore, n observability.Name, rows []observability.DayTotal, to time.Time, days int) *MetricsChart {
	counts := map[[2]string]int64{}
	last := to
	if metricsStanding(n) {
		day, groups := metricsreport.Stock([]observability.Name{n}, rows)
		e.StockDay, last = day, day
		for _, g := range groups {
			for _, r := range g.Rows {
				counts[[2]string{r.Scope, r.Value}] += r.N
			}
		}
	} else {
		for _, t := range rows {
			if t.Name == n.Name {
				counts[[2]string{t.Scope, t.Value}] += t.N
			}
		}
	}
	e.Rows, e.Total = metricsExploreRows(counts)
	if last.IsZero() {
		return nil
	}
	labels, data := metricsDaySeries(rows, n.Name, to, days, last)
	if len(data) == 0 {
		return nil
	}
	e.LineID = metricsExploreChart
	return &MetricsChart{ID: metricsExploreChart, Kind: "line", Labels: labels, Series: []MetricsSeries{{Label: n.Name, Data: data}}}
}

// fillMetricsExploreHours fills the rows and the hourly line from HoursFrom through the
// metricsHourDays of hours after it; an hour outside them is left out.
func fillMetricsExploreHours(e *MetricsExplore, hours []observability.HourTotal) MetricsChart {
	n := metricsHourDays * 24
	data := make([]int64, n)
	counts := map[[2]string]int64{}
	for _, h := range hours {
		if h.Hour.Before(e.HoursFrom) {
			continue
		}
		i := int(h.Hour.Sub(e.HoursFrom) / time.Hour)
		if i >= n {
			continue
		}
		data[i] += h.N
		counts[[2]string{h.Scope, h.Value}] += h.N
	}
	labels := make([]string, n)
	for i := range labels {
		labels[i] = e.HoursFrom.Add(time.Duration(i) * time.Hour).Format("2006-01-02 15:00")
	}
	e.Rows, e.Total = metricsExploreRows(counts)
	e.LineID = metricsExploreChart
	return MetricsChart{ID: metricsExploreChart, Kind: "line", Labels: labels, Series: []MetricsSeries{{Label: e.Name, Data: data}}}
}

// metricsJobStatusWords is a job's status in words; threshold is the age an ok run becomes overdue past.
func metricsJobStatusWords(status string, threshold time.Duration) string {
	switch status {
	case metricsreport.JobOK:
		return "ran on time"
	case metricsreport.JobNoRun:
		return fmt.Sprintf("no run in the last %d days", metricsHourDays)
	case metricsreport.JobFailed:
		return "last run failed"
	case metricsreport.JobOverdue:
		return fmt.Sprintf("overdue: no successful run in %d hours", int(threshold.Hours()))
	}
	return status
}

// metricsUnchecked is one line a Health block that was not read on a complete day, saying why.
func metricsUnchecked(h *MetricsHealth) []string {
	var out []string
	if h.CountersRead.Failed {
		out = append(out, "Counters and job runs could not be read.")
	}
	why := func(what string, r MetricsRead) string {
		if r.Failed {
			return what + " could not be read."
		}
		return what + " are checked only after the first nightly summary has run."
	}
	if !h.SilentCounted {
		out = append(out, why("Missing counts", h.SilentRead))
	}
	if h.ClientMeasured && !h.ClientCounted {
		out = append(out, why("Browser report outcomes", h.ClientRead))
	}
	return out
}

// MetricsPoint is one label and count of a chart, for the table printed beside it.
type MetricsPoint struct {
	Label string
	N     int64
}

// ChartPoints is the first series of the chart with this id as label and count pairs; nil when there is none.
func (v *MetricsView) ChartPoints(id string) []MetricsPoint {
	if v == nil || id == "" {
		return nil
	}
	for _, c := range v.Charts {
		if c.ID != id || len(c.Series) == 0 {
			continue
		}
		data := c.Series[0].Data
		out := make([]MetricsPoint, 0, len(c.Labels))
		for i, label := range c.Labels {
			if i < len(data) {
				out = append(out, MetricsPoint{Label: label, N: data[i]})
			}
		}
		return out
	}
	return nil
}

// metricsRowsNote says a counter saved today though it wrote no rows yesterday, so a live 0 is not read as a fault.
func metricsRowsNote(c observability.InstanceHealth) string {
	if c.Rows == 0 && !c.LastFlush.IsZero() {
		return "none yesterday; saved today"
	}
	return ""
}

// metricsWhen is a job time in UTC, or none in the days the minute rows keep.
func metricsWhen(t time.Time) string {
	if t.IsZero() {
		return fmt.Sprintf("none in %d days", metricsHourDays)
	}
	return t.UTC().Format("Jan 2 15:04")
}

// metricsRunWords is a job run in words: its time, result and instance, or none in the days the minute rows keep.
func metricsRunWords(r observability.JobRun) string {
	if r.At.IsZero() {
		return metricsWhen(r.At)
	}
	result := "failed"
	if r.Result == "ok" {
		result = "succeeded"
	}
	return fmt.Sprintf("%s, %s on %s", metricsWhen(r.At), result, r.Instance)
}

// The review form's refusals; a refusal never echoes what was sent.
const (
	metricsReviewNoCandidate = "Review not saved: no such candidate"
	metricsReviewNoVerdict   = "Review not saved: unknown verdict"
	metricsReviewNoSite      = "Review not saved: no such site"
	metricsReviewStoreFailed = "Review not saved: the database did not answer"
)

// What the Remove view says after a review redirect.
const (
	metricsReviewSaved   = "Review saved."
	metricsReviewCleared = "Review cleared."
)

// adminMetricsReview saves a review mark a POST carries; done means it answered. Its reads run on
// the page's ctx; the write runs on the request's own context, as the other admin tools' do.
func adminMetricsReview(ctx context.Context, w http.ResponseWriter, r *http.Request, store metricsStore, lists metricsreport.Lists, params metricsParams, pv *PageVars) (done bool) {
	if r.Method != http.MethodPost || r.PostFormValue("reviewName") == "" {
		return false
	}
	name, scope, value := r.PostFormValue("reviewName"), r.PostFormValue("reviewScope"), r.PostFormValue("reviewValue")
	verdict := r.PostFormValue("reviewVerdict")
	// no site, or one the picker does not offer, is refused, not written under this site's
	if asked := r.FormValue("instance"); params.Instance == "" || (asked != "" && asked != params.Instance) {
		pv.WarningMessage = metricsReviewNoSite
		return false
	}
	if verdict != "clear" && !observability.ValidVerdict(verdict) {
		pv.WarningMessage = metricsReviewNoVerdict
		return false
	}
	// a save needs a real candidate; a clear also takes a mark the instance holds for a unit no longer listed
	if u := (metricsreport.Unit{Name: name, Scope: scope, Value: value}); !metricsReviewUnit(lists, u) &&
		(verdict != "clear" || !metricsStoredReview(ctx, store, params.Instance, u)) {
		pv.WarningMessage = metricsReviewNoCandidate
		return false
	}
	var err error
	if verdict == "clear" {
		err = store.DeleteReview(r.Context(), params.Instance, name, scope, value)
	} else {
		err = store.SetReview(r.Context(), observability.Review{
			Instance: params.Instance, Name: name, Scope: scope, Value: value,
			Verdict: verdict, Note: cleanReviewNote(r.PostFormValue("reviewNote")),
		})
	}
	if err != nil {
		log.Printf("metrics: review: %v", err)
		pv.WarningMessage = metricsReviewStoreFailed
		return false
	}
	n, _ := observability.Lookup(name)
	confirm := "saved"
	if verdict == "clear" {
		confirm = "cleared"
	}
	extra := []string{confirm, "1"}
	if n.Area != "" {
		extra = append(extra, "area", n.Area)
	}
	http.Redirect(w, r, "/admin"+params.link("remove", extra...)+"#"+url.PathEscape(metricsAnchor(name, scope, value)), http.StatusSeeOther)
	return true
}

// metricsStoredReview reports whether the instance holds a review mark for u; a failed read is no.
func metricsStoredReview(ctx context.Context, store metricsStore, instance string, u metricsreport.Unit) bool {
	reviews, err := store.Reviews(ctx, instance)
	if err != nil {
		log.Printf("metrics: review: %v", err)
		return false
	}
	return slices.ContainsFunc(reviews, func(r observability.Review) bool { return r.Name == u.Name && r.Scope == u.Scope && r.Value == u.Value })
}

// metricsReviewUnit reports whether u is one of its registered name's candidate units.
func metricsReviewUnit(lists metricsreport.Lists, u metricsreport.Unit) bool {
	n, ok := observability.Lookup(u.Name)
	if !ok {
		return false
	}
	return slices.Contains(metricsreport.Units(metricsreport.Expand([]observability.Name{n}, lists)[0]), u)
}

// cleanReviewNote makes a note one line of at most 200 characters, format characters dropped.
func cleanReviewNote(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	words := strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	return strings.TrimSpace(observability.CleanReviewNote(strings.Join(words, " ")))
}
