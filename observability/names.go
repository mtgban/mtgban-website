package observability

import (
	"slices"
	"strconv"
)

// Family says where a name is emitted from.
type Family int

// The families a name belongs to.
const (
	FamilyServer Family = iota
	FamilyUI
	FamilyState
	FamilyStock
)

// ValueKind says what a name's value may hold.
type ValueKind int

// The kinds of value a name takes.
const (
	ValueNone ValueKind = iota
	ValueEnum
	ValueBucket
	ValueStore
	ValueFlag
	ValuePage
	ValueSetting
	ValueOrigin
)

// ScopeKind says what a name's scope may hold.
type ScopeKind int

// The kinds of scope a name takes.
const (
	ScopeNone ScopeKind = iota
	ScopeRoute
	ScopePage
	ScopeEnum
	ScopeStore
	ScopeSetting
)

// ReportKind says how a report treats a name.
type ReportKind int

// The report treatments.
const (
	ReportCandidate ReportKind = iota
	ReportSignal
	ReportContext
	ReportInternal
)

// UnitKind says what one candidate is in a report.
type UnitKind int

// The candidate units.
const (
	UnitValue UnitKind = iota
	UnitScope
	UnitScopeAndValue
)

// Name is one thing the counter may count.
type Name struct {
	Name   string
	Family Family
	Values ValueKind
	Enum   []string
	Scope  ScopeKind
	Scopes []string
	Area   string
	Page   string // "", "*" or comma-separated page labels with no spaces
	Denom  string // a registered name; used instead of Page when set
	Report ReportKind
	Unit   UnitKind
	Kind   string
	Help   string
}

// Validators answers the checks the registry cannot make by itself.
type Validators struct {
	Store        func(string) bool
	Page         func(string) bool
	Route        func(string) bool
	Setting      func(string) bool
	SettingValue func(setting, value string) bool
	Origin       func(string) bool
}

var names = []Name{
	{Name: "metrics.flush", Report: ReportInternal, Help: "Counter flushes written to the database."},
	{Name: "metrics.dropped", Report: ReportInternal, Help: "Counts dropped because the counter was full."},
	{Name: "metrics.flush_fail", Report: ReportInternal, Help: "Counter flushes that failed."},
	{Name: "metrics.rejected", Report: ReportInternal, Help: "Counts the registry refused to store."},
	{Name: "page.view", Values: ValuePage, Report: ReportCandidate, Unit: UnitValue, Kind: "page", Area: "site", Help: "Page views, by page."},
	{Name: "http.status", Report: ReportContext, Values: ValueEnum, Enum: []string{"2xx", "3xx", "4xx", "5xx"}, Scope: ScopeRoute, Help: "Responses by status class, per route."},
	{Name: "http.duration", Report: ReportContext, Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Scope: ScopeRoute, Help: "Response time buckets, per route."},
	{Name: "auth.refuse", Report: ReportSignal, Area: "account", Values: ValueEnum, Enum: []string{"unauthenticated", "no_access", "rate_limited", "other"}, Scope: ScopeRoute, Help: "Requests refused at the door, by reason."},
	{Name: "ratelimit.reject", Report: ReportSignal, Area: "site", Values: ValueEnum, Enum: []string{"page", "api", "vote", "upload_share", "favorites_share", "userstate", "alerts", "alerts_confirm", "metrics"}, Help: "Requests a rate limiter refused, by limiter."},
	{Name: "search.mode", Area: "search", Values: ValueEnum, Enum: []string{"default", "exact", "any", "prefix", "regexp", "hashing", "sealed", "mixed", "scryfall"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "search.result", Help: "Search strategy the request ran with."},
	{Name: "search.sort", Area: "search", Values: ValueEnum, Enum: []string{"chrono", "hybrid", "alpha", "number", "retail", "buylist", "velocity", "odds"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "search.result", Help: "Order the results were sorted in."},
	{Name: "search.sort_from", Area: "search", Values: ValueEnum, Enum: []string{"param", "operator", "cookie", "default"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Where the sort came from; page links carry sort= so param is inflated."},
	{Name: "search.reverse", Area: "search", Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "search.result", Help: "The request asked for the reversed order."},
	{Name: "search.filter", Area: "search", Values: ValueEnum, Enum: searchFilters, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "An operator the reader typed, negated as -name; once per distinct operator per results page view; a pinned bar the search ignored is not counted."},
	{Name: "search.is", Area: "search", Values: ValueEnum, Enum: []string{"foil", "nonfoil", "reserved", "token", "oversize", "funny", "wcd", "gold", "fullart", "promo", "gamechanger", "extendedart", "showcase", "borderless", "future", "reskin", "japanese", "phyrexian", "commander", "productless", "ampersand", "p9", "altfoil", "promo_type", "tag", "other"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "An is: or not: value, aliases folded."},
	{Name: "search.on", Area: "search", Values: ValueEnum, Enum: []string{"mtgstocks", "tcgsyp", "hotlist", "newhigh", "cksell", "ckwait", "newspaper", "backpack"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "An on: list of the site's own."},
	{Name: "search.region", Area: "search", Values: ValueEnum, Enum: []string{"us", "eu", "jp"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "A region: value."},
	{Name: "search.pool", Area: "search", Values: ValueEnum, Enum: []string{"in", "not_in", "backpack_name"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "An in: pool, or an on: naming one of the reader's backpacks."},
	{Name: "search.finish_suffix", Area: "search", Values: ValueEnum, Enum: []string{"nonfoil", "foil", "etched", "altfoil"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "The trailing & * ~ or backtick shorthand."},
	{Name: "search.syntax", Area: "search", Values: ValueEnum, Enum: []string{"scryfall_bot", "set_number", "set_total", "bare_number", "name_number", "regexp"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "operator", Denom: "search.result", Help: "A non-operator form the parser rewrote."},
	{Name: "search.filter_count", Area: "search", Values: ValueBucket, Enum: []string{"0", "1", "2", "3-5", "6+"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Operator tokens typed across both bars."},
	{Name: "search.scope", Area: "search", Values: ValueEnum, Enum: []string{"none", "set", "ignored"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "The pinned bar: empty, holding a filter (set, whether or not this search applied it; a hashing or scryfall search passes over it), or holding none."},
	{Name: "search.page", Area: "search", Values: ValueBucket, Enum: []string{"1", "2", "3-5", "6+"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Page of results asked for."},
	{Name: "search.page_size", Area: "search", Values: ValueEnum, Enum: []string{"25", "100"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Results per page."},
	{Name: "search.source", Area: "search", Values: ValueEnum, Enum: []string{"banbot", "autocard", "chart", "own_site", "other_site", "direct"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Where the request came from."},
	{Name: "search.chart", Area: "chart", Page: "search,sealed,sets", Values: ValueEnum, Enum: []string{"single", "multi", "modal"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The request drew a chart or was the chart picker."},
	{Name: "search.view", Area: "settings", Values: ValueEnum, Enum: []string{"sellers", "buyers", "NM", "SP", "MP", "HP", "PO", "INDEX", "stores", "prices", "credit", "market", "contents", "decklist", "variable", "expanded", "compact"}, Scope: ScopeEnum, Scopes: []string{"SearchDefaultTab", "SearchDefaultView", "SearchListingPriority", "SearchSealedContents", "MobileSearchLayout"}, Report: ReportCandidate, Unit: UnitScope, Kind: "setting", Denom: "search.result", Help: "A view cookie the request carried; scope is the cookie."},
	{Name: "search.misc", Area: "settings", Values: ValueEnum, Enum: []string{"noSussy", "hidePrelPack", "hidePromos", "preferFlavor", "hideBLconds", "skipEmpty", "noUpsell"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "setting", Denom: "search.result", Help: "A SearchMiscOpts flag in force."},
	{Name: "search.store_factors", Area: "settings", Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "setting", Denom: "search.result", Help: "The request carried store factors."},
	{Name: "search.custom_buylist", Area: "settings", Scope: ScopeEnum, Scopes: searchPages, Report: ReportCandidate, Unit: UnitValue, Kind: "setting", Denom: "search.result", Help: "The custom buylist was appended."},
	{Name: "search.result", Area: "search", Values: ValueEnum, Enum: []string{"found", "empty", "single"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportSignal, Help: "Outcome of a results page view, not of a search: page 2, a re-sort, a reload, a chart page and the chart picker each count again, options with them."},
	{Name: "search.results", Area: "search", Values: ValueBucket, Enum: []string{"0", "1-9", "10-99", "100-999", "1000-9999", "10000+"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Cards matched."},
	{Name: "search.suggestion_shown", Area: "search", Values: ValueEnum, Enum: []string{"did_you_mean", "try_one_of", "popular", "unpin_scope"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "What an empty page offered."},
	{Name: "search.duration", Area: "search", Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Scope: ScopeEnum, Scopes: searchPages, Report: ReportContext, Help: "Parse to ready-to-render."},
	{Name: "sets.sort", Area: "search", Page: "sets", Values: ValueEnum, Enum: []string{"date", "name", "size"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "Order of the /sets tree."},
	{Name: "search.oembed", Area: "search", Values: ValueEnum, Enum: []string{"json", "unsupported", "not_found"}, Report: ReportContext, Help: "An oEmbed consumer's request and its answer."},
	{Name: "export.search", Area: "search", Page: "search,sealed", Values: ValueEnum, Enum: []string{"retail", "buylist", "list"}, Scope: ScopeEnum, Scopes: []string{"singles", "sealed"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A CSV download from the results sidebar, labelled by what was asked for, which a restricted reader may not have received in full."},
	{Name: "export.decklist", Area: "search", Page: "search,sealed", Values: ValueEnum, Enum: []string{"tcgplayer", "cardmarket"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A sealed product's decklist CSV."},
	{Name: "export.raw", Area: "search", Report: ReportInternal, Help: "The admin raw card record."},
	{Name: "data.chart", Area: "chart", Values: ValueEnum, Enum: []string{"30", "90", "180", "365", "730", "1825", "3650", "all", "other"}, Scope: ScopeEnum, Scopes: []string{"single", "multi"}, Report: ReportContext, Help: "A chart data fetch: on desktop a widening one at the tier ceiling, on mobile two per chart open (the saved range, then the ceiling); requests, a not-found after the ids parsed included."},
	{Name: "data.chart_ids", Area: "chart", Values: ValueBucket, Enum: []string{"1", "2", "3-5", "6+"}, Report: ReportContext, Help: "Cards in a chart fetch."},
	{Name: "data.prices", Area: "site", Values: ValueBucket, Enum: []string{"0", "1-9", "10-24", "25-49", "50+"}, Report: ReportContext, Help: "Ids in a batch price fetch."},
	{Name: "suggest.fetch", Area: "search", Values: ValueEnum, Enum: []string{"all", "prefix"}, Scope: ScopeEnum, Scopes: []string{"cards", "sealed"}, Report: ReportContext, Help: "A name list or prefix suggestion fetch."},
	{Name: "palette.list", Area: "palette", Values: ValueEnum, Enum: []string{"sets", "stores", "rarities", "finishes", "promos", "colors"}, Report: ReportContext, Help: "A list fetch, not a use; the search box and the guide fetch these too; most are cached an hour, stores is not cached."},
	{Name: "palette.chip_fetch", Area: "palette", Values: ValueEnum, Enum: []string{"card", "sealed"}, Report: ReportContext, Help: "A fetch of a locked chip's data, cached five minutes; not a count of chips locked."},
	{Name: "settings.modal_fetch", Area: "settings", Report: ReportContext, Help: "The settings modal body was fetched."},
	{Name: "settings.values_fetch", Area: "settings", Scope: ScopePage, Report: ReportContext, Help: "Another page's cookies fetched for the modal."},
	{Name: "opensearch.fetch", Area: "search", Report: ReportContext, Help: "A browser fetched the search engine descriptor."},
}

// searchPages are the paths a search runs on, the scope of most search.* names.
var searchPages = []string{"search", "sealed", "sets"}

// searchFilters are the parser's operators as typed, plus in, each also negated but sm and sort.
var searchFilters = []string{
	"arb_price", "buy_price", "c", "ci", "cn", "cne", "cns", "color", "cond", "condb", "condr", "container",
	"contents", "date", "decklist", "e", "edition", "ee", "f", "format", "id", "identity", "in", "is", "legal",
	"name", "namee", "not", "number", "on", "price", "qty", "quantity", "r", "ratio", "region", "rev_price", "s",
	"se", "seller", "set", "skip", "sm", "sort", "store", "t", "unpack", "v", "variable", "velocity", "vendor",
	"year", "-arb_price", "-buy_price", "-c", "-ci", "-cn", "-cne", "-cns", "-color", "-cond", "-condb",
	"-condr", "-container", "-contents", "-date", "-decklist", "-e", "-edition", "-ee", "-f", "-format", "-id",
	"-identity", "-in", "-is", "-legal", "-name", "-namee", "-not", "-number", "-on", "-price", "-qty",
	"-quantity", "-r", "-ratio", "-region", "-rev_price", "-s", "-se", "-seller", "-set", "-skip", "-store",
	"-t", "-unpack", "-v", "-variable", "-velocity", "-vendor", "-year",
}

var byName map[string]Name

func init() {
	byName = make(map[string]Name, len(names))
	for _, n := range names {
		byName[n.Name] = n
	}
}

// Lookup returns the registered name.
func Lookup(name string) (Name, bool) {
	n, ok := byName[name]
	return n, ok
}

// All returns every registered name.
func All() []Name {
	return slices.Clone(names)
}

func foldOther(f func(string) bool, s string) string {
	if f == nil || !f(s) {
		return "other"
	}
	return s
}

// Check returns the scope and value to store, or ok=false to reject.
func (n Name) Check(scope, value string, v Validators) (string, string, bool) {
	if n.Scope == ScopeNone {
		if scope != "" {
			return "", "", false
		}
	} else {
		if scope == "" {
			return "", "", false
		}
		switch n.Scope {
		case ScopeEnum:
			if !slices.Contains(n.Scopes, scope) {
				return "", "", false
			}
		case ScopeSetting:
			if v.Setting == nil || !v.Setting(scope) {
				return "", "", false
			}
		case ScopeRoute:
			scope = foldOther(v.Route, scope)
		case ScopePage:
			scope = foldOther(v.Page, scope)
		case ScopeStore:
			scope = foldOther(v.Store, scope)
		}
	}

	switch n.Values {
	case ValueNone:
		if value != "" {
			return "", "", false
		}
	case ValueEnum, ValueBucket:
		if !slices.Contains(n.Enum, value) {
			return "", "", false
		}
	case ValueFlag:
		if value != "on" && value != "off" {
			return "", "", false
		}
	case ValueSetting:
		if v.SettingValue == nil || !v.SettingValue(scope, value) {
			return "", "", false
		}
	case ValueStore:
		value = foldOther(v.Store, value)
	case ValuePage:
		value = foldOther(v.Page, value)
	case ValueOrigin:
		value = foldOther(v.Origin, value)
	}
	return scope, value, true
}

// Bucket names the range of edges that n falls in.
func Bucket(edges []int64, n int64) string {
	if len(edges) == 0 || n < edges[0] {
		return "0"
	}
	i := 0
	for i+1 < len(edges) && edges[i+1] <= n {
		i++
	}
	lo := strconv.FormatInt(edges[i], 10)
	if i == len(edges)-1 {
		return lo + "+"
	}
	if edges[i+1]-1 == edges[i] {
		return lo
	}
	return lo + "-" + strconv.FormatInt(edges[i+1]-1, 10)
}
