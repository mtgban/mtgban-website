package main

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/observability"
)

// searchRun is what one search request ran with.
type searchRun struct {
	Page       string                     // search, sealed or sets
	Config     SearchConfig               // the main bar's parse
	Pinned     []string                   // the pinned bar's AppliedFilters
	Scope      string                     // none, set or ignored
	Sort       string                     // the order asked for, as read
	SortFrom   string                     // operator, param, cookie or default
	Reverse    bool                       // the reversed order was asked for
	PageIndex  int                        // the page of results asked for, 1-based
	PageSize   int                        // results per page
	Source     string                     // a search.source value
	Chart      string                     // "", single, multi or modal
	Views      map[string]string          // view cookie name to its raw value
	Misc       []string                   // SearchMiscOpts as read
	Factors    bool                       // store factors were applied
	Custom     bool                       // the custom buylist was appended
	Packs      map[string]map[string]bool // the reader's backpacks, by on: value
	PromoTypes []string                   // the datastore's promo types
}

// searchModes are the modes search.mode counts as themselves.
var searchModes = []string{"exact", "any", "prefix", "regexp", "hashing", "sealed", "mixed", "scryfall"}

// searchSorts are the orders search.sort counts as themselves; any other ran as chrono.
var searchSorts = []string{"hybrid", "alpha", "number", "retail", "buylist", "velocity", "odds"}

// searchOnLists are the site's own on: lists.
var searchOnLists = []string{"mtgstocks", "tcgsyp", "hotlist", "newhigh", "cksell", "ckwait", "newspaper"}

// searchMiscFlags are the SearchMiscOpts flags search.misc counts.
var searchMiscFlags = []string{"noSussy", "hidePrelPack", "hidePromos", "preferFlavor", "hideBLconds", "skipEmpty", "noUpsell"}

// searchViewCookies are the view cookies search.view reads, in order, each with its own values.
var searchViewCookies = []struct {
	name   string
	values []string
}{
	{"SearchDefaultTab", []string{"sellers", "buyers"}},
	{"SearchDefaultView", []string{"NM", "SP", "MP", "HP", "PO", "INDEX"}},
	{"SearchListingPriority", []string{"stores", "prices", "credit", "market"}},
	{"SearchSealedContents", []string{"contents", "decklist", "variable"}},
	{"MobileSearchLayout", []string{"expanded", "compact"}},
}

// isCanonical maps each value cardFilterIs has a case for to the name search.is stores.
var isCanonical = map[string]string{
	"foil":        "foil",
	"nonfoil":     "nonfoil",
	"reserved":    "reserved",
	"token":       "token",
	"oversize":    "oversize",
	"funny":       "funny",
	"wcd":         "wcd",
	"gold":        "gold",
	"fullart":     "fullart",
	"promo":       "promo",
	"gamechanger": "gamechanger",
	"extendedart": "extendedart",
	"showcase":    "showcase",
	"borderless":  "borderless",
	"future":      "future",
	"reskin":      "reskin",
	"japanese":    "japanese",
	"phyrexian":   "phyrexian",
	"commander":   "commander",
	"productless": "productless",
	"ampersand":   "ampersand",
	"p9":          "p9",
	"altfoil":     "altfoil",
	"oversized":   "oversize",
	"fa":          "fullart",
	"gc":          "gamechanger",
	"ea":          "extendedart",
	"sc":          "showcase",
	"sh":          "showcase",
	"bd":          "borderless",
	"bl":          "borderless",
	"jpn":         "japanese",
	"jp":          "japanese",
	"ja":          "japanese",
	"ph":          "phyrexian",
}

// isTagValues are the values of specialTags and specialEditionTags.
var isTagValues = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	for _, tag := range specialTags {
		out[tag] = true
	}
	for _, tag := range specialEditionTags {
		out[tag] = true
	}
	return out
})

// distinctValues keeps values in first-seen order, each once.
type distinctValues struct {
	seen map[string]bool
	list []string
}

func (d *distinctValues) add(v string) {
	if d.seen[v] {
		return
	}
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	d.seen[v] = true
	d.list = append(d.list, v)
}

// searchModeValue is search.mode's value: the mode, or default for the game's own or an unknown one.
func searchModeValue(config SearchConfig) string {
	if !slices.Contains(searchModes, config.SearchMode) || (config.DefaultMode && config.SearchMode == "any") {
		return "default"
	}
	return config.SearchMode
}

// isValue folds one is: or not: value to search.is's value.
func isValue(v string, promoTypes []string) string {
	if canonical, ok := isCanonical[v]; ok {
		return canonical
	}
	if isTagValues()[v] {
		return "tag"
	}
	if _, ok := isKnownPromo[v]; ok || slices.Contains(promoTypes, v) {
		return "promo_type"
	}
	return "other"
}

// searchFacts lists what one search ran with, from the tokens the reader typed.
func searchFacts(run searchRun) []fact {
	page := run.Page
	mode := run.Config.SearchMode
	facts := []fact{newFact(page, "search.mode", searchModeValue(run.Config))}

	sortValue := "chrono"
	if slices.Contains(searchSorts, run.Sort) {
		sortValue = run.Sort
	}
	facts = append(facts, newFact(page, "search.sort", sortValue), newFact(page, "search.sort_from", run.SortFrom))
	if run.Reverse {
		facts = append(facts, newFact(page, "search.reverse", ""))
	}

	tokens := run.Config.AppliedFilters
	// A pinned bar the search passed over was not used.
	if mode != "hashing" && mode != "scryfall" && run.Scope != "ignored" {
		tokens = slices.Concat(tokens, run.Pinned)
	}
	var filters, is, on, pools, regions distinctValues
	kept, regexp := 0, false
	for _, token := range tokens {
		var option, code string
		var negate bool
		if lower := strings.ToLower(token); strings.HasPrefix(lower, "in:") || strings.HasPrefix(lower, "-in:") {
			option, negate = "in", strings.HasPrefix(lower, "-")
		} else {
			var ok bool
			option, _, code, negate, ok = splitFilterToken(token)
			if !ok {
				continue
			}
		}
		// The rest of a scryfall query is Scryfall's syntax.
		if mode == "scryfall" && option != "sm" {
			continue
		}
		kept++
		if negate && option != "sm" && option != "sort" {
			filters.add("-" + option)
		} else {
			filters.add(option)
		}

		switch option {
		case "in":
			if negate {
				pools.add("not_in")
			} else {
				pools.add("in")
			}
		case "is", "not":
			for _, v := range strings.Split(strings.ToLower(code), ",") {
				is.add(isValue(v, run.PromoTypes))
			}
		case "on":
			for _, v := range fixupOnNG(code) {
				_, isPack := run.Packs[v]
				switch {
				case v == "backpack":
					on.add(v)
				case isPack:
					pools.add("backpack_name")
				case v == "syp":
					on.add("tcgsyp")
				case slices.Contains(searchOnLists, v):
					on.add(v)
				}
			}
		case "region":
			for _, v := range strings.Split(strings.ToLower(code), ",") {
				if v == "us" || v == "eu" || v == "jp" {
					regions.add(v)
				}
			}
		case "namee", "se", "ee", "cne":
			regexp = true
		}
	}

	for _, v := range filters.list {
		facts = append(facts, newFact(page, "search.filter", v))
	}
	facts = append(facts, newFact(page, "search.filter_count", smallCount(kept)))
	for _, v := range is.list {
		facts = append(facts, newFact(page, "search.is", v))
	}
	for _, v := range on.list {
		facts = append(facts, newFact(page, "search.on", v))
	}
	for _, v := range pools.list {
		facts = append(facts, newFact(page, "search.pool", v))
	}
	for _, v := range regions.list {
		facts = append(facts, newFact(page, "search.region", v))
	}

	if run.Config.FinishSuffix != "" {
		facts = append(facts, newFact(page, "search.finish_suffix", run.Config.FinishSuffix))
	}
	var syntax distinctValues
	for _, v := range run.Config.Syntax {
		syntax.add(v)
	}
	if regexp {
		syntax.add("regexp")
	}
	for _, v := range syntax.list {
		facts = append(facts, newFact(page, "search.syntax", v))
	}

	facts = append(facts,
		newFact(page, "search.scope", run.Scope),
		newFact(page, "search.page", pageBucket(run.PageIndex)),
	)
	switch run.PageSize {
	case 25:
		facts = append(facts, newFact(page, "search.page_size", "25"))
	case 100:
		facts = append(facts, newFact(page, "search.page_size", "100"))
	}
	facts = append(facts, newFact(page, "search.source", run.Source))
	if run.Chart != "" {
		facts = append(facts, newFact(page, "search.chart", run.Chart))
	}

	for _, cookie := range searchViewCookies {
		if v, ok := run.Views[cookie.name]; ok && slices.Contains(cookie.values, v) {
			facts = append(facts, newFact(cookie.name, "search.view", v))
		}
	}

	var misc distinctValues
	for _, v := range run.Misc {
		if slices.Contains(searchMiscFlags, v) {
			misc.add(v)
		}
	}
	for _, v := range misc.list {
		facts = append(facts, newFact(page, "search.misc", v))
	}
	if run.Factors {
		facts = append(facts, newFact(page, "search.store_factors", ""))
	}
	if run.Custom {
		facts = append(facts, newFact(page, "search.custom_buylist", ""))
	}
	return facts
}

// searchPageName is the page a search path draws: search, sealed or sets.
func searchPageName(path string) string {
	switch path {
	case "/sealed":
		return "sealed"
	case "/sets":
		return "sets"
	}
	return "search"
}

// exportKind is export.search's value and scope, from searchPrices' path tests.
func exportKind(isRetail, isBuylist, isSealed bool) (kind, scope string) {
	kind, scope = "list", "singles"
	switch {
	case isRetail:
		kind = "retail"
	case isBuylist:
		kind = "buylist"
	}
	if isSealed {
		scope = "sealed"
	}
	return kind, scope
}

// searchSource is search.source's value: where the search came from.
func searchSource(utm, referer string, charting bool) string {
	switch {
	case utm == "banbot":
		return "banbot"
	case utm == "autocard":
		return "autocard"
	case charting:
		return "chart"
	case referer == "":
		return "direct"
	}
	if u, err := url.Parse(referer); err == nil && ownSiteHost(u.Host) {
		return "own_site"
	}
	return "other_site"
}

// searchChartKind is search.chart's value for a roster: modal, multi, single or "".
func searchChartKind(roster chartRoster) string {
	switch {
	case roster.modal:
		return "modal"
	case roster.id != "" && len(roster.ids) > 1:
		return "multi"
	case roster.id != "":
		return "single"
	}
	return ""
}

// buildSearchRun is readSearchRun, swapped by a test that watches when a search reads its run.
var buildSearchRun = readSearchRun

// readSearchRun reads what one search ran with from its request and parse.
func readSearchRun(r *http.Request, b *matcher.Backend, config SearchConfig, pinned []string,
	scope string, scopeIgnored, listingLocked bool, roster chartRoster,
	packs map[string]map[string]bool) searchRun {
	run := searchRun{
		Page:       searchPageName(r.URL.Path),
		Config:     config,
		Pinned:     pinned,
		Scope:      "set",
		PageSize:   searchPageSize(r),
		Source:     searchSource(r.FormValue("utm_source"), r.Referer(), roster.id != ""),
		Chart:      searchChartKind(roster),
		Misc:       readSearchMiscOpts(r),
		Factors:    len(readStoreFactors(r)) > 0,
		Custom:     config.CustomBuylist && !config.SkipBuylist && readCustomBuylistRule(r).rate != 0,
		Packs:      packs,
		PromoTypes: b.AllPromoTypes,
	}
	switch {
	case scope == "":
		run.Scope = "none"
	case scopeIgnored:
		run.Scope = "ignored"
	}
	run.Sort, run.SortFrom = searchSortFrom(r, config)
	run.Reverse, _ = strconv.ParseBool(r.FormValue("reverse"))
	run.PageIndex, _ = strconv.Atoi(r.FormValue("p"))
	for _, cookie := range searchViewCookies {
		// The server ignores the listing cookie while the listing is locked.
		if listingLocked && cookie.name == "SearchListingPriority" {
			continue
		}
		if v := readCookie(r, cookie.name); v != "" {
			if run.Views == nil {
				run.Views = map[string]string{}
			}
			run.Views[cookie.name] = v
		}
	}
	return run
}

// observeSearch counts what a search page view ran with and found.
func observeSearch(r *http.Request, run searchRun, out searchOutcome) {
	if FeatureCounter == nil || !isPageView(r) {
		return
	}
	// No search fact is store-valued, so no prices snapshot.
	observeFacts(r, nil, append(searchFacts(run), searchResultFacts(run.Page, out)...))
}

// searchOutcome is how one search ended.
type searchOutcome struct {
	Unique, Total                        int  // cards shown once each; all that matched when cut or repeated
	DidYouMean, TryOneOf, Popular, Unpin bool // what the empty page offered
	Took                                 time.Duration
}

// searchResultEdges are search.results' bucket edges.
var searchResultEdges = []int64{1, 10, 100, 1000, 10000}

// searchResultFacts lists what one search found and how long it took.
func searchResultFacts(page string, out searchOutcome) []fact {
	result := "found"
	switch out.Unique {
	case 0:
		result = "empty"
	case 1:
		result = "single"
	}
	facts := []fact{
		newFact(page, "search.result", result),
		newFact(page, "search.results", observability.Bucket(searchResultEdges, int64(max(out.Unique, out.Total)))),
	}
	if out.Unique == 0 {
		if out.DidYouMean {
			facts = append(facts, newFact(page, "search.suggestion_shown", "did_you_mean"))
		}
		if out.TryOneOf {
			facts = append(facts, newFact(page, "search.suggestion_shown", "try_one_of"))
		}
		if out.Popular {
			facts = append(facts, newFact(page, "search.suggestion_shown", "popular"))
		}
		if out.Unpin {
			facts = append(facts, newFact(page, "search.suggestion_shown", "unpin_scope"))
		}
	}
	return append(facts, newFact(page, "search.duration", durationBucket(out.Took)))
}

// searchLandingFacts is what a request with nothing to search counts.
func searchLandingFacts(page, setsSort, chart string) []fact {
	var facts []fact
	if chart != "" {
		facts = append(facts, newFact(page, "search.chart", chart))
	}
	if page == "sets" {
		switch setsSort {
		case "name", "size":
			facts = append(facts, newFact("", "sets.sort", setsSort))
		default:
			facts = append(facts, newFact("", "sets.sort", "date"))
		}
	}
	return facts
}
