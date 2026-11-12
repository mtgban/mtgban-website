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
	{Name: "upload.source", Area: "upload", Values: ValueEnum, Enum: append(slices.Clone(uploadSources), "url_prefix"), Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "Where an upload's list came from; a URL prefix upload also counts url at the upload."},
	{Name: "upload.url_host", Area: "upload", Values: ValueEnum, Enum: []string{"tcgplayer", "moxfield", "manabox", "archidekt", "cubecobra", "mythictools", "collectr", "gdocs", "other"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "The site a remote URL upload pointed at."},
	{Name: "upload.handoff_origin", Area: "upload", Page: "upload", Values: ValueOrigin, Report: ReportContext, Help: "The site that handed a list over; an unconfigured host is other."},
	{Name: "upload.from", Area: "upload", Values: ValueEnum, Enum: []string{"search_sidebar", "favorites", "backpack", "news", "screener", "palette", "results_reload", "upload_form", "unknown"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Denom: "upload.mode", Help: "The control that posted a list of card ids."},
	{Name: "upload.mode", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"retail", "buylist"}, Report: ReportContext, Help: "The side an upload was priced on, once per priced results view; a reload from the results counts again, as upload.from:results_reload shows."},
	{Name: "upload.rows", Area: "upload", Page: "upload", Values: ValueBucket, Enum: []string{"0", "1-9", "10-99", "100-999", "1000+"}, Report: ReportContext, Help: "Rows in an upload after merging."},
	{Name: "upload.sealed", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"none", "some", "all"}, Report: ReportContext, Help: "How much of an upload was sealed product."},
	{Name: "upload.option", Area: "upload", Values: ValueEnum, Enum: []string{"lowval", "lowvalabs", "highval", "highvalabs", "minmargin", "nocond", "noprice", "customperc"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "A buylist option set away from the page's default in the reader's saved settings and in force; a default-on option counts when turned off. Counted on buylist runs only, while upload.mode counts retail too."},
	{Name: "upload.value_set", Area: "upload", Values: ValueEnum, Enum: []string{"percspread", "percspreadmax", "minval", "maxval", "margin", "custompercmax", "multiplier", "maxqty"}, Report: ReportCandidate, Unit: UnitValue, Kind: "setting", Denom: "upload.mode", Help: "A numeric upload setting off its default; margin only when the option is on and the margin is not the page's 10."},
	{Name: "upload.sorting", Area: "upload", Values: ValueEnum, Enum: []string{"highprice", "alphabetical", "setalpha", "setchrono", "highspread", "profitability"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "The sort an upload's results ran with."},
	{Name: "upload.price_source", Area: "upload", Values: ValueEnum, Enum: []string{"default", "credit", "marketCredit"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "The price a buylist upload compared in. Counted on buylist runs only, while upload.mode counts retail too."},
	{Name: "upload.custom_buylist", Area: "upload", Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "An upload priced a custom buylist."},
	{Name: "upload.stores", Area: "upload", Page: "upload", Values: ValueBucket, Enum: []string{"0", "1-4", "5-9", "10-19", "20+"}, Report: ReportContext, Help: "Stores an upload was priced against, singles and sealed."},
	{Name: "upload.index_pref", Area: "upload", Report: ReportCandidate, Unit: UnitValue, Kind: "option", Denom: "upload.mode", Help: "An upload ran with a changed index selection."},
	{Name: "upload.unpack", Area: "upload", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Denom: "upload.mode", Help: "An upload opened its sealed rows."},
	{Name: "upload.publish", Area: "upload", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Denom: "upload.mode", Help: "An upload was published as a store."},
	{Name: "upload.parse_error", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"no_list", "load_error"}, Scope: ScopeEnum, Scopes: append([]string{"none"}, uploadSources...), Report: ReportSignal, Help: "An upload that could not be read, scoped by where its list came from."},
	{Name: "upload.duration", Area: "upload", Page: "upload", Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Report: ReportContext, Help: "Time to price an upload."},
	{Name: "upload_share.open", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"ok", "gone"}, Report: ReportSignal, Help: "A share link was opened."},
	{Name: "upload.export", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"download", "estimate", "deckbox", "tcgplayer_csv"}, Scope: ScopeEnum, Scopes: []string{"all", "singles", "sealed"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "An export run from upload results, scoped by the rows a download kept."},
	{Name: "upload.tag", Area: "upload", Page: "upload,arbit,reverse,global", Values: ValueEnum, Enum: []string{"load_at", "csv", "tcg_remove"}, Scope: ScopeEnum, Scopes: []string{"CK", "SCG", "TCG"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A per-store transfer from the upload results or the arbitrage tables."},
	{Name: "upload.handoff_page", Area: "upload", Page: "upload/handoff", Values: ValueEnum, Enum: []string{"shown", "locked"}, Report: ReportContext, Help: "The handoff page was opened; locked when the reader lacks the Upload grant."},
	{Name: "upload_share.create", Area: "upload", Page: "upload", Values: ValueEnum, Enum: []string{"retail", "buylist"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A share link was made for upload results, by their side."},
	{Name: "arbit.view", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"landing", "store"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportContext, Help: "An arbitrage page was shown, with or without a store picked."},
	{Name: "arbit.source", Area: "arbit", Page: "arbit,reverse,global", Values: ValueStore, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportContext, Help: "The store an arbitrage view compared from."},
	{Name: "arbit.apply", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"apply", "reset"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "The filter form was submitted, or Restore defaults was followed."},
	{Name: "arbit.bound", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"minsell", "maxsell", "minbuy", "maxbuy", "minspread", "maxspread", "mindiff", "minqty", "minprof"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "A numeric limit the view ran with."},
	{Name: "arbit.pick", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"cond", "finish", "rarity"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "A picker narrowed from its full list."},
	{Name: "arbit.toggle", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"rl", "abu4h", "nocollector", "nooversize", "notoken", "decklists", "syp", "stocks", "legit", "stable", "tradable"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "An on/off option set away from the page's default, chosen by the reader, defaults not counted."},
	{Name: "arbit.sort", Area: "arbit", Page: "arbit,reverse,global", Values: ValueEnum, Enum: []string{"profitability", "spread", "diff", "available", "sell_price", "buy_price", "edition", "alpha"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The sort the tables ran with."},
	{Name: "arbit.excluded_vendors", Area: "arbit", Page: "arbit,reverse,global", Values: ValueBucket, Enum: []string{"0", "1-4", "5-9", "10+"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportContext, Help: "Stores the reader hides from the page."},
	{Name: "arbit.sections", Area: "arbit", Page: "arbit,reverse,global", Values: ValueBucket, Enum: []string{"0", "1-4", "5-9", "10-19", "20+"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportContext, Help: "Store tables a view returned."},
	{Name: "arbit.duration", Area: "arbit", Page: "arbit,reverse,global", Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Scope: ScopeEnum, Scopes: arbitPages, Report: ReportContext, Help: "Time to build a view."},
	{Name: "news.report", Area: "news", Page: "newspaper/index,newspaper/syp,newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueEnum, Enum: []string{"combined_spike_score", "spike_score", "greatest_increase_listings", "greatest_decrease_listings", "greatest_increase_buylist", "greatest_decrease_buylist", "syp", "index"}, Report: ReportContext, Help: "A newspaper page was served to a reader with the tier."},
	{Name: "news.three_day", Area: "news", Page: "newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueEnum, Enum: []string{"on", "off"}, Report: ReportContext, Help: "A report ran on the delayed edition."},
	{Name: "news.sort", Area: "news", Page: "newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueEnum, Enum: []string{"ranking", "product_name", "set_name", "product_number", "variant", "bucket_name", "bucket_rank", "ck_buy_price", "ck_buy_1d", "ck_buy_7d", "ck_buy_30d", "ck_retail_price", "current_price", "tcg_market_price", "pct_decrease_7d", "pct_drop_7d", "pct_gain_7d", "pct_increase_7d", "sellers_Today", "sellers_d7", "sellers_d30"}, Scope: ScopeEnum, Scopes: []string{"asc", "desc"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A report was sorted by a column."},
	{Name: "news.filter", Area: "news", Page: "newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueEnum, Enum: []string{"rarity", "bucket", "finish", "min_price", "max_price", "min_change", "max_change", "edition"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A report filter in force."},
	{Name: "news.page", Area: "news", Page: "newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueBucket, Enum: []string{"1", "2", "3-5", "6+"}, Report: ReportContext, Help: "The page of a report that was read."},
	{Name: "news.syp_csv", Area: "news", Page: "newspaper/syp", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "The SYP list was downloaded as CSV."},
	{Name: "news.syp_sort", Area: "news", Page: "newspaper/syp", Values: ValueEnum, Enum: []string{"alpha", "edition", "available", "sell_price"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The sort the SYP list ran with."},
	{Name: "news.editions_hidden", Area: "news", Page: "newspaper/combined_spike_score,newspaper/spike_score,newspaper/greatest_increase_listings,newspaper/greatest_decrease_listings,newspaper/greatest_increase_buylist,newspaper/greatest_decrease_buylist", Values: ValueBucket, Enum: []string{"0", "1-4", "5-19", "20+"}, Report: ReportContext, Help: "Editions the reader hides from reports."},
	{Name: "sleepers.page", Area: "sleepers", Page: "sleepers/index,sleepers/reprint,sleepers/mismatch,sleepers/gap,sleepers/hotlist,sleepers/velocity", Values: ValueEnum, Enum: []string{"reprint", "mismatch", "gap", "hotlist", "velocity", "index"}, Report: ReportContext, Help: "A sleepers page was built."},
	{Name: "sleepers.gap", Area: "sleepers", Page: "sleepers/gap", Values: ValueEnum, Enum: []string{"preset", "custom"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An Ocean Gap comparison came from a preset link or a custom pair."},
	{Name: "sleepers.ref", Area: "sleepers", Page: "sleepers/gap", Values: ValueStore, Report: ReportContext, Help: "The reference store of a gap comparison."},
	{Name: "sleepers.target", Area: "sleepers", Page: "sleepers/gap", Values: ValueStore, Report: ReportContext, Help: "The target store of a gap comparison."},
	{Name: "sleepers.lists", Area: "sleepers", Values: ValueEnum, Enum: []string{"sellers", "vendors", "editions"}, Report: ReportCandidate, Unit: UnitValue, Kind: "setting", Denom: "sleepers.page", Help: "A sleepers hide list the reader keeps."},
	{Name: "sleepers.duration", Area: "sleepers", Page: "sleepers/index,sleepers/reprint,sleepers/mismatch,sleepers/gap,sleepers/hotlist,sleepers/velocity", Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Report: ReportContext, Help: "Time to build a sleepers page."},
	{Name: "screener.provider", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"CKRetail", "CKBuylist", "TCGLow", "TCGMarket", "TCGMid", "TCGHigh", "TCGDirectLow", "MKMLow", "MKMTrend", "SCGBuylist", "ABUBuylist", "CSIBuylist", "SealedEV"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The price the screener compared."},
	{Name: "screener.window", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"1", "7", "14", "30", "60", "90", "180", "365"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The screener's window in days."},
	{Name: "screener.kind", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"singles", "sealed", "both"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "What the screener listed."},
	{Name: "screener.move", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"up", "down", "either"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The direction the screener kept."},
	{Name: "screener.filter", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"min_price", "min_was", "min_pct", "max_pct", "edition"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A screener filter the reader set away from the landing's."},
	{Name: "screener.size", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"25", "50", "100"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The screener's page size."},
	{Name: "screener.sort", Area: "screener", Page: "screener", Values: ValueEnum, Enum: []string{"current", "prior", "pct", "abs"}, Scope: ScopeEnum, Scopes: []string{"asc", "desc"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "The column the screener sorted by."},
	{Name: "screener.page", Area: "screener", Page: "screener", Values: ValueBucket, Enum: []string{"1", "2", "3-5", "6+"}, Report: ReportContext, Help: "The page of screener rows read."},
	{Name: "alerts.create", Area: "alerts", Page: "search,alerts", Values: ValueEnum, Enum: []string{"retail", "buylist"}, Scope: ScopePage, Report: ReportCandidate, Unit: UnitScope, Kind: "control", Help: "An alert was created, by the page it was created from."},
	{Name: "alerts.create_delivery", Area: "alerts", Denom: "alerts.create", Values: ValueEnum, Enum: []string{"discord", "email"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The channel a new alert fires on."},
	{Name: "alerts.create_condition", Area: "alerts", Denom: "alerts.create", Values: ValueEnum, Enum: []string{"NM", "SP", "MP", "HP", "PO"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The grade a new alert watches."},
	{Name: "alerts.create_threshold", Area: "alerts", Denom: "alerts.create", Values: ValueEnum, Enum: []string{"above_abs", "above_pct", "below_abs", "below_pct"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "A threshold a new alert set."},
	{Name: "alerts.create_stores", Area: "alerts", Denom: "alerts.create", Values: ValueBucket, Enum: []string{"0", "1-2", "3-9", "10+"}, Report: ReportContext, Help: "Stores a new alert is scoped to, 0 being every store."},
	{Name: "alerts.edit", Area: "alerts", Page: "alerts", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An alert was edited."},
	{Name: "alerts.pause", Area: "alerts", Page: "alerts", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An alert was paused."},
	{Name: "alerts.resume", Area: "alerts", Page: "alerts", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An alert was resumed."},
	{Name: "alerts.delete", Area: "alerts", Page: "search,alerts", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An alert was deleted."},
	{Name: "alerts.delete_all", Area: "alerts", Page: "alerts", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "Every alert was deleted at once."},
	{Name: "alerts.channel", Area: "alerts", Page: "alerts", Values: ValueEnum, Enum: []string{"add", "change", "resend", "remove", "enable", "confirm", "unsubscribe"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "An email channel action."},
	{Name: "alerts.fired", Area: "alerts", Values: ValueEnum, Enum: []string{"retail", "buylist"}, Report: ReportContext, Help: "A firing settled: delivered, refused or failed, once per attempt; a deferred firing counts when it is finally attempted."},
	{Name: "alerts.delivered", Area: "alerts", Values: ValueEnum, Enum: []string{"ok", "fail", "refused", "deferred"}, Scope: ScopeEnum, Scopes: []string{"discord", "email"}, Report: ReportSignal, Help: "How a firing's delivery ended: fail is retried, refused parks the alert, deferred counts again on each run until sent."},
	{Name: "alerts.mail_event", Area: "alerts", Values: ValueEnum, Enum: []string{"hard_bounce", "soft_bounce", "complaint", "other"}, Report: ReportSignal, Help: "A mail provider event the webhook verified."},
	{Name: "alerts.deep_link", Area: "alerts", Page: "alerts", Values: ValueEnum, Enum: []string{"card", "edit"}, Report: ReportContext, Help: "The alerts page was opened on a card or an alert."},
	{Name: "auth.login", Area: "account", Values: ValueEnum, Enum: []string{"ok", "no_code", "fail_patreon", "fail_tier"}, Report: ReportSignal, Help: "How a Patreon login callback ended: fail_patreon is Patreon failing or giving no usable answer, fail_tier a reader with no qualifying pledge; the row carries whatever cookie the browser already held."},
	{Name: "auth.renew", Area: "account", Values: ValueEnum, Enum: []string{"renewed", "not_renewed", "ended", "refused", "gone", "session_gone"}, Report: ReportContext, Help: "What a renewal came to, one row per refresh call made to Patreon, plus session_gone when the session is found gone before any call; a Refresh now press that reaches Patreon also counts under account.refresh, so the two are not added. The row carries the signature from before the renewal, so a grace renewal reads tier Any, unsigned."},
	{Name: "auth.logout", Area: "account", Page: "home,user", Values: ValueEnum, Enum: []string{"here", "everywhere"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A reader logged out, of this browser or of every session."},
	{Name: "account.refresh", Area: "account", Page: "user", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "Refresh now was pressed on the Account page; a press that reaches Patreon also counts under auth.renew, so the two are not added."},
	{Name: "userstate.get", Area: "account", Page: "*", Report: ReportContext, Help: "A browser read its synced state, answered 200 or 304."},
	{Name: "userstate.put", Area: "account", Page: "*", Report: ReportContext, Help: "A browser wrote its whole synced state."},
	{Name: "userstate.patch", Area: "account", Page: "*", Values: ValueEnum, Enum: []string{"favorites", "recents", "preferences", "backpack"}, Report: ReportContext, Help: "A browser wrote one section of its synced state."},
	{Name: "userstate.conflict", Area: "account", Page: "*", Report: ReportSignal, Help: "A sync write lost to a newer version."},
	{Name: "favshare.create", Area: "favorites", Page: "search,sealed", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A favorites share link was made or replaced."},
	{Name: "favshare.stop", Area: "favorites", Page: "search,sealed", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A favorites share link was ended."},
	{Name: "favshare.view", Area: "favorites", Page: "search/shared", Report: ReportContext, Help: "A shared favorites list was shown."},
	{Name: "favshare.view_gone", Area: "favorites", Page: "search/shared", Report: ReportSignal, Help: "A share link was opened after it ended, or was never valid."},
	{Name: "patreon.webhook", Area: "account", Values: ValueEnum, Enum: []string{"pledge_create", "pledge_update", "pledge_delete", "member_create", "member_update", "member_delete", "other", "bad_signature", "no_email"}, Report: ReportContext, Help: "A call to the Patreon member webhook: its event once handled, or why it was not."},
	{Name: "go.click", Area: "site", Page: "*", Values: ValueEnum, Enum: []string{"r", "b", "i"}, Scope: ScopeStore, Report: ReportContext, Help: "A /go/ link sent a reader to a store, by the kind of link."},
	{Name: "redirect.random", Area: "search", Page: "home,search,sealed", Values: ValueEnum, Enum: []string{"card", "sealed", "chart_modal"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A random card or product was asked for."},
	{Name: "redirect.card", Area: "site", Report: ReportContext, Help: "A /card/ link was followed."},
	{Name: "redirect.sealed", Area: "site", Report: ReportContext, Help: "A /sealed/ link was followed."},
	{Name: "redirect.discord", Area: "nav", Page: "*", Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "The /discord invite link was followed."},
	{Name: "redirect.partner", Area: "site", Report: ReportCandidate, Unit: UnitValue, Kind: "page", Help: "The /monroecards partner link was followed."},
	{Name: "view.toggle", Area: "nav", Page: "*", Values: ValueEnum, Enum: []string{"to_mobile", "to_desktop"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "The mobile or desktop view was forced."},
	{Name: "apiplans.view", Area: "api", Page: "api-plans", Values: ValueEnum, Enum: []string{"plain", "prefilled"}, Report: ReportContext, Help: "The API pricing page was shown, plain or opened on an invite, a change or a package."},
	{Name: "apiplans.handoff", Area: "api", Page: "api-plans", Values: ValueEnum, Enum: []string{"trial", "login", "unknown"}, Scope: ScopeEnum, Scopes: []string{"start", "ok", "refused"}, Report: ReportSignal, Help: "A step of the handoff to the API gateway."},
	{Name: "api.call", Area: "api", Values: ValueEnum, Enum: []string{"json", "csv", "other"}, Scope: ScopeEnum, Scopes: APIFamilies(), Report: ReportContext, Help: "A price API call that passed the gate, by endpoint family; tier api is the gateway's, api-legacy any other verified signature. A handler refusal is also a call, so refusal rate is api.refuse over api.call."},
	{Name: "api.option", Area: "api", Denom: "api.call", Values: ValueEnum, Enum: []string{"quantities", "conditions"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "A price API call asked for an optional column, counted on v1 and v2 CSV calls only, where the options apply, while api.call counts every family."},
	{Name: "api.refuse", Area: "api", Values: ValueEnum, Enum: []string{"no_key", "bad_sig", "expired", "rate_limited", "plan"}, Scope: ScopeEnum, Scopes: APIFamilies(), Report: ReportSignal, Help: "A price API call that was refused, by endpoint family and reason; plan is a verified key whose plan lacks the add-on; rate_limited is the same refusal ratelimit.reject:api counts, so the two are not added."},
	{Name: "offlineapi.fetch", Area: "offline", Page: "offline", Values: ValueEnum, Enum: []string{"manifest", "catalog", "prices", "bucket_auth"}, Report: ReportContext, Help: "An offline API endpoint was fetched."},
	{Name: "discord.message", Area: "site", Values: ValueEnum, Enum: []string{"card", "sealed", "last_sold", "brackets", "pricefall", "gatherer_link"}, Report: ReportCandidate, Unit: UnitValue, Kind: "control", Help: "A message the Discord bot took as a command or lookup, by its form, counted even when the bot then answered nothing (a failed parse, an unclosed bracket, a Gatherer link with no match)."},
	{Name: "discord.store_link", Area: "site", Values: ValueEnum, Enum: []string{"ck", "csi", "tcg", "scg", "mp", "ct", "amzn"}, Report: ReportCandidate, Unit: UnitValue, Kind: "option", Help: "The Discord bot answered a store link with an affiliate link."},
	{Name: "discord.guild_join", Area: "site", Report: ReportContext, Help: "The Discord bot was installed on a server."},
}

// uploadSources are where the upload handler reads a list from.
var uploadSources = []string{"hashes", "text", "file_csv", "file_txt", "file_xls", "file_xlsx", "url", "share", "handoff"}

// arbitPages are the arbitrage pages, the scope of every arbit.* name.
var arbitPages = []string{"arbit", "reverse", "global"}

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

// maxStoreLen is the longest shorthand stored; a longer one folds to other.
const maxStoreLen = 40

// storeShaped reports whether s is short and spelled as shorthands are, TCGSI's , and + included.
func storeShaped(s string) bool {
	if s == "" || len(s) > maxStoreLen {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '.', c == '-', c == ',', c == '+':
		default:
			return false
		}
	}
	return true
}

// foldStore is foldOther for a shorthand, which must also be store-shaped.
func foldStore(f func(string) bool, s string) string {
	if !storeShaped(s) {
		return "other"
	}
	return foldOther(f, s)
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
			scope = foldStore(v.Store, scope)
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
		value = foldStore(v.Store, value)
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
