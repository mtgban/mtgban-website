package main

import (
	"errors"
	"go/ast"
	"go/token"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
)

func TestSplitFilterToken(t *testing.T) {
	for _, c := range []struct {
		field, option, operation, code string
		negate, ok                     bool
	}{
		{"s:lea", "s", ":", "lea", false, true},
		{"-F:foil", "f", ":", "foil", true, true},
		{"cn>5", "cn", ">", "5", false, true},
		{"cn:lea:5", "cn", ":", "lea:5", false, true},
		{"date<2020-01-01", "date", "<", "2020-01-01", false, true},
		{"price:5", "", "", "", false, false}, // price takes > and < only
		{"nokey", "", "", "", false, false},
	} {
		option, operation, code, negate, ok := splitFilterToken(c.field)
		if ok != c.ok {
			t.Errorf("%q: ok = %v, want %v", c.field, ok, c.ok)
			continue
		}
		if ok && (option != c.option || operation != c.operation || code != c.code || negate != c.negate) {
			t.Errorf("%q: got (%q, %q, %q, %v)", c.field, option, operation, code, negate)
		}
	}
}

// The queries are the ones the sibling parser tests already pin
// (searchfilter_test.go, searchfilter_number_test.go, searchfilter_pool_test.go).
func TestParserKeepsTheSyntaxItRewrote(t *testing.T) {
	skipWithoutDatastore(t)
	t.Parallel()
	ds := currentDatastore()
	withNumbers := func(q string) SearchConfig { return parseSearchQuery(ds, currentPrices(), q, nil, nil, nil) }
	for _, c := range []struct {
		query  string
		parse  func(string) SearchConfig
		suffix string
		syntax []string
	}{
		{"lightning bolt", withNumbers, "", nil},
		{"lightning bolt&", withNumbers, "nonfoil", nil},
		{"lightning bolt*", withNumbers, "foil", nil},
		{"lightning bolt~", withNumbers, "etched", nil},
		{"lightning bolt`", withNumbers, "altfoil", nil},
		{"in:CMR se:^Dom.*", parseSearchOptionsWrapper, "", nil}, // the * is the pattern's
		{"neo 234", parseSearchOptionsWrapper, "", []string{"set_number"}},
		{"plst c16-177", parseSearchOptionsWrapper, "", []string{"set_number"}},
		{"123", withNumbers, "", []string{"bare_number"}},
		{"123*", withNumbers, "foil", []string{"bare_number"}},
		{"command tower 7029", withNumbers, "", []string{"name_number"}},
		{"222/236", parseSearchOptionsWrapper, "", []string{"set_total"}},
		{"cn:222/236", parseSearchOptionsWrapper, "", nil}, // the operator form is an operator
		{`Dark Ritual|"Fourth Edition"|32`, parseSearchOptionsWrapper, "", []string{"scryfall_bot"}},
	} {
		config := c.parse(c.query)
		if config.FinishSuffix != c.suffix || !slices.Equal(config.Syntax, c.syntax) {
			t.Errorf("%q: suffix %q syntax %v, want %q %v", c.query, config.FinishSuffix, config.Syntax, c.suffix, c.syntax)
		}
	}
}

// factValues returns the values of the facts named name, sorted, with scopes checked.
func factValues(t *testing.T, facts []fact, name, scope string) []string {
	t.Helper()
	var out []string
	for _, f := range facts {
		if f.name != name {
			continue
		}
		if f.scope != scope {
			t.Errorf("%s:%s has scope %q, want %q", name, f.value, f.scope, scope)
		}
		out = append(out, f.value)
	}
	slices.Sort(out)
	return out
}

func TestSearchFacts(t *testing.T) {
	plain := searchRun{Page: "search", Scope: "none", SortFrom: "default", PageSize: 100, Source: "direct"}
	with := func(edit func(*searchRun)) searchRun { run := plain; edit(&run); return run }
	applied := func(tokens ...string) searchRun {
		return with(func(run *searchRun) { run.Config.AppliedFilters = tokens })
	}

	for _, c := range []struct {
		desc string
		run  searchRun
		want map[string][]string // name to sorted values; a nil slice means no such fact
	}{
		{"a plain name", plain, map[string][]string{
			"search.mode": {"default"}, "search.sort": {"chrono"}, "search.sort_from": {"default"},
			"search.filter_count": {"0"}, "search.scope": {"none"}, "search.page": {"1"},
			"search.page_size": {"100"}, "search.source": {"direct"},
			"search.filter": nil, "search.reverse": nil, "search.is": nil, "search.chart": nil,
			"search.misc": nil, "search.store_factors": nil, "search.custom_buylist": nil,
		}},
		{"operators as typed, negated, refused and in upper case",
			applied("s:lea", "-f:foil", "CN>5", "price:5", "-sort:retail", "ee:^a"),
			map[string][]string{
				"search.filter":       {"-f", "cn", "ee", "s", "sort"},
				"search.filter_count": {"3-5"},
				"search.syntax":       {"regexp"},
			}},
		{"aliases stay apart and repeat once", applied("s:lea", "set:leb", "s:2ed"), map[string][]string{
			"search.filter": {"s", "set"}, "search.filter_count": {"3-5"},
		}},
		{"a negated mode is the mode", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"-sm:exact"}
			run.Config.SearchMode = "exact"
		}), map[string][]string{"search.filter": {"sm"}, "search.mode": {"exact"}}},
		{"pools", applied("in:(s:CMR is:foil)", "-in:lea", "-IN:leb"), map[string][]string{
			"search.filter": {"-in", "in"}, "search.pool": {"in", "not_in"},
			"search.is": nil, "search.filter_count": {"3-5"},
		}},
		{"is values fold", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"is:foil,fa,ea,dual,abu4h,judge,fixturea,zzz", "not:promo", "-is:bl"}
			run.PromoTypes = []string{"fixturea"}
		}), map[string][]string{
			"search.is":     {"borderless", "extendedart", "foil", "fullart", "other", "promo", "promo_type", "tag"},
			"search.filter": {"-is", "is", "not"},
		}},
		{"on lists and a backpack by name", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"on:hotlist,syp,backpack", `on:"My List"`, "on:nothing"}
			run.Packs = map[string]map[string]bool{"my list": {}, "backpack": {}}
		}), map[string][]string{
			"search.on": {"backpack", "hotlist", "tcgsyp"}, "search.pool": {"backpack_name"},
		}},
		{"a backpack named like a site list wins", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"on:hotlist"}
			run.Packs = map[string]map[string]bool{"hotlist": {}, "backpack": {}}
		}), map[string][]string{"search.on": nil, "search.pool": {"backpack_name"}}},
		{"a backpack name with no backpacks read is not stored", applied(`on:"My List"`), map[string][]string{
			"search.on": nil, "search.pool": nil, "search.filter": {"on"},
		}},
		{"regions", applied("region:EU,mars"), map[string][]string{"search.region": {"eu"}}},
		{"a repeated region counts once", applied("region:eu,EU", "region:eu"), map[string][]string{
			"search.region": {"eu"}, "search.filter": {"region"},
		}},
		{"a known promo alias is a promo type", applied("is:judge"), map[string][]string{"search.is": {"promo_type"}}},
		{"the datastore's promo types are promo types", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"is:fixturea"}
			run.PromoTypes = []string{"fixturea"}
		}), map[string][]string{"search.is": {"promo_type"}}},
		{"a promo type the datastore lacks is other", applied("is:fixturea"), map[string][]string{"search.is": {"other"}}},
		{"a repeated form counts once", with(func(run *searchRun) {
			run.Config.Syntax = []string{"set_number", "set_number"}
			run.Config.AppliedFilters = []string{"ee:^a", "se:^b"}
		}), map[string][]string{"search.syntax": {"regexp", "set_number"}}},
		{"another page size is not counted", with(func(run *searchRun) { run.PageSize = 50 }),
			map[string][]string{"search.page_size": nil}},
		{"the suffix and the rewritten forms", with(func(run *searchRun) {
			run.Config.FinishSuffix = "altfoil"
			run.Config.Syntax = []string{"set_number"}
		}), map[string][]string{"search.finish_suffix": {"altfoil"}, "search.syntax": {"set_number"}}},
		{"scryfall keeps only its mode", with(func(run *searchRun) {
			run.Config.SearchMode = "scryfall"
			run.Config.AppliedFilters = []string{"sm:scryfall", "t:goblin", "c:r"}
			run.Pinned = []string{"s:lea"}
		}), map[string][]string{
			"search.mode": {"scryfall"}, "search.filter": {"sm"}, "search.filter_count": {"1"},
		}},
		{"a hashing search passes over the pinned bar", with(func(run *searchRun) {
			run.Config.SearchMode = "hashing"
			run.Pinned = []string{"s:lea"}
			run.Scope = "set"
		}), map[string][]string{
			"search.mode": {"hashing"}, "search.filter": nil, "search.scope": {"set"},
		}},
		{"the pinned bar's operators count", with(func(run *searchRun) {
			run.Config.AppliedFilters = []string{"is:foil"}
			run.Pinned = []string{"s:sos", "is:foil"}
			run.Scope = "set"
		}), map[string][]string{"search.filter": {"is", "s"}, "search.filter_count": {"3-5"}}},
		{"an ignored pinned bar counts nothing", with(func(run *searchRun) {
			run.Pinned = []string{"region:eu"}
			run.Scope = "ignored"
		}), map[string][]string{
			"search.filter": nil, "search.region": nil, "search.filter_count": {"0"}, "search.scope": {"ignored"},
		}},
		{"an applied pinned bar counts", with(func(run *searchRun) {
			run.Pinned = []string{"s:lea"}
			run.Scope = "set"
		}), map[string][]string{"search.filter": {"s"}, "search.filter_count": {"1"}, "search.scope": {"set"}}},
		{"a game's default mode is default", with(func(run *searchRun) {
			run.Config.SearchMode, run.Config.DefaultMode = "any", true
		}), map[string][]string{"search.mode": {"default"}}},
		{"a sealed search on a game with a default mode is sealed", with(func(run *searchRun) {
			run.Page = "sealed"
			run.Config.SearchMode, run.Config.DefaultMode = "sealed", true
		}), map[string][]string{"search.mode": {"sealed"}}},
		{"a typed any is any", with(func(run *searchRun) { run.Config.SearchMode = "any" }),
			map[string][]string{"search.mode": {"any"}}},
		{"an unknown mode is default", with(func(run *searchRun) { run.Config.SearchMode = "bogus" }),
			map[string][]string{"search.mode": {"default"}}},
		{"an unknown sort ran as chrono", with(func(run *searchRun) {
			run.Sort, run.SortFrom = "<script>", "param"
		}), map[string][]string{"search.sort": {"chrono"}, "search.sort_from": {"param"}}},
		{"odds by parameter", with(func(run *searchRun) { run.Sort, run.SortFrom = "odds", "param" }),
			map[string][]string{"search.sort": {"odds"}}},
		{"flags", with(func(run *searchRun) {
			run.Reverse, run.Factors, run.Custom, run.Chart = true, true, true, "multi"
			run.Misc = []string{"noSussy", "", "bogus", "hidePromos", "noSussy"}
			run.PageIndex, run.PageSize = 4, 25
		}), map[string][]string{
			"search.reverse": {""}, "search.store_factors": {""}, "search.custom_buylist": {""},
			"search.chart": {"multi"}, "search.misc": {"hidePromos", "noSussy"},
			"search.page": {"3-5"}, "search.page_size": {"25"},
		}},
		{"page seven", with(func(run *searchRun) { run.PageIndex = 7 }),
			map[string][]string{"search.page": {"6+"}}},
	} {
		facts := searchFacts(c.run)
		for name, want := range c.want {
			if got := factValues(t, facts, name, c.run.Page); !slices.Equal(got, want) {
				t.Errorf("%s: %s = %v, want %v", c.desc, name, got, want)
			}
		}
	}
}

// Review focus 1: hidePromos adds an is filter the reader did not type.
func TestSearchFactsReadTypedTokensOnly(t *testing.T) {
	run := searchRun{Page: "search", Scope: "none", SortFrom: "default", PageSize: 100, Source: "direct"}
	run.Config.CardFilters = []FilterElem{{Name: "is", Negate: true, Values: []string{"promo"}}}
	run.Misc = []string{"hidePromos"}
	facts := searchFacts(run)
	if got := factValues(t, facts, "search.is", "search"); got != nil {
		t.Errorf("search.is = %v from a filter the reader did not type", got)
	}
	if got := factValues(t, facts, "search.filter", "search"); got != nil {
		t.Errorf("search.filter = %v from a filter the reader did not type", got)
	}
}

func TestSearchViewFacts(t *testing.T) {
	run := searchRun{Page: "sealed", Views: map[string]string{
		"SearchDefaultTab":      "buyers",
		"SearchDefaultView":     "<b>",
		"SearchListingPriority": "market",
		"SearchSealedContents":  "",
		"MobileSearchLayout":    "NM", // another cookie's value
	}}
	var got []string
	for _, f := range searchFacts(run) {
		if f.name == "search.view" {
			got = append(got, f.scope+"="+f.value)
		}
	}
	want := []string{"SearchDefaultTab=buyers", "SearchListingPriority=market"}
	if !slices.Equal(got, want) {
		t.Errorf("search.view = %v, want %v", got, want)
	}
	if mode := factValues(t, searchFacts(run), "search.mode", "sealed"); !slices.Equal(mode, []string{"default"}) {
		t.Errorf("search.mode on /sealed = %v, want scope sealed", mode)
	}
}

// Every fact searchFacts can build passes the registry.
func TestSearchFactsPassTheRegistry(t *testing.T) {
	run := searchRun{
		Page: "sets", Scope: "ignored", Sort: "velocity", SortFrom: "cookie", Reverse: true,
		PageIndex: 2, PageSize: 25, Source: "banbot", Chart: "modal", Factors: true, Custom: true,
		Misc:       []string{"noSussy", "hidePrelPack", "hidePromos", "preferFlavor", "hideBLconds", "skipEmpty", "noUpsell"},
		Views:      map[string]string{"SearchDefaultTab": "sellers", "SearchDefaultView": "INDEX", "SearchListingPriority": "stores", "SearchSealedContents": "variable", "MobileSearchLayout": "compact"},
		PromoTypes: []string{"fixturea"},
		Packs:      map[string]map[string]bool{"my list": {}},
	}
	run.Config.FinishSuffix = "etched"
	run.Config.Syntax = []string{"scryfall_bot", "set_number", "bare_number", "name_number", "set_total"}
	for option := range FilterOperations {
		run.Config.AppliedFilters = append(run.Config.AppliedFilters, option+FilterOperations[option][0]+"x", "-"+option+FilterOperations[option][0]+"x")
	}
	run.Config.AppliedFilters = append(run.Config.AppliedFilters, "in:x", "-in:x", "is:foil,dual,fixturea,zzz", "on:mtgstocks,tcgsyp,hotlist,newhigh,cksell,ckwait,newspaper,backpack", "region:us,eu,jp", `on:"My List"`)
	facts := searchFacts(run)
	if got := factValues(t, facts, "search.pool", "sets"); !slices.Contains(got, "backpack_name") {
		t.Errorf("search.pool = %v, want backpack_name among them", got)
	}
	facts = append(facts, searchResultFacts("sets", searchOutcome{DidYouMean: true, TryOneOf: true, Popular: true, Unpin: true, Took: time.Minute})...)
	facts = append(facts, searchResultFacts("sealed", searchOutcome{Unique: 9999, Total: 10000})...)
	facts = append(facts, searchLandingFacts("sets", "size", "modal")...)
	for _, f := range facts {
		n, ok := observability.Lookup(f.name)
		if !ok {
			t.Errorf("%s is not registered", f.name)
			continue
		}
		if _, _, ok := n.Check(f.scope, f.value, observability.Validators{}); !ok {
			t.Errorf("the registry refuses %s scope %q value %q", f.name, f.scope, f.value)
		}
	}
}

// The search.filter enum is the parser's operator table, plus in.
func TestSearchFilterEnumMatchesTheParser(t *testing.T) {
	n, _ := observability.Lookup("search.filter")
	want := map[string]bool{"in": true, "-in": true}
	for option := range FilterOperations {
		want[option] = true
		if option != "sm" && option != "sort" {
			want["-"+option] = true
		}
	}
	got := map[string]bool{}
	for _, v := range n.Enum {
		got[v] = true
	}
	if !maps.Equal(got, want) {
		t.Errorf("search.filter enum has %d values, the parser implies %d", len(got), len(want))
	}
}

// switchCases returns the string case values of the first switch in searchfilter.go's function fn.
func switchCases(t *testing.T, fn string) []string {
	t.Helper()
	var cases []string
	for _, decl := range parseGoFile(t, token.NewFileSet(), "searchfilter.go").Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn {
			continue
		}
		var sw *ast.SwitchStmt
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if s, ok := n.(*ast.SwitchStmt); ok && sw == nil {
				sw = s
			}
			return sw == nil
		})
		if sw == nil {
			t.Fatalf("%s has no switch", fn)
		}
		for _, stmt := range sw.Body.List {
			for _, e := range stmt.(*ast.CaseClause).List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				cases = append(cases, s)
			}
		}
	}
	if len(cases) == 0 {
		t.Fatalf("found no case values in %s", fn)
	}
	return cases
}

// Every value cardFilterIs has a case for is in isCanonical, and every
// canonical name is in the registry.
func TestIsCanonicalCoversTheFilter(t *testing.T) {
	for _, c := range switchCases(t, "cardFilterIs") {
		if _, ok := isCanonical[c]; !ok {
			t.Errorf("isCanonical lacks cardFilterIs's case %q", c)
		}
	}
	n, _ := observability.Lookup("search.is")
	for _, v := range isCanonical {
		if !slices.Contains(n.Enum, v) {
			t.Errorf("search.is lacks the canonical value %q", v)
		}
	}
}

// searchOnLists is cardFilterOn's case list, syp folded into tcgsyp.
func TestSearchOnListsCoverTheFilter(t *testing.T) {
	var cases []string
	for _, c := range switchCases(t, "cardFilterOn") {
		if c != "syp" {
			cases = append(cases, c)
		}
	}
	slices.Sort(cases)
	lists := slices.Sorted(slices.Values(searchOnLists))
	if !slices.Equal(cases, lists) {
		t.Errorf("cardFilterOn's lists are %v, searchOnLists %v", cases, lists)
	}
	n, _ := observability.Lookup("search.on")
	for _, v := range searchOnLists {
		if !slices.Contains(n.Enum, v) {
			t.Errorf("search.on lacks the list %q", v)
		}
	}
}

func TestSearchResultFacts(t *testing.T) {
	for _, c := range []struct {
		desc string
		out  searchOutcome
		want map[string][]string
	}{
		{"nothing found", searchOutcome{DidYouMean: true, Popular: true, Unpin: true, Took: 30 * time.Millisecond}, map[string][]string{
			"search.result": {"empty"}, "search.results": {"0"},
			"search.suggestion_shown": {"did_you_mean", "popular", "unpin_scope"},
			"search.duration":         {"<50ms"},
		}},
		{"one card", searchOutcome{Unique: 1, Took: 120 * time.Millisecond}, map[string][]string{
			"search.result": {"single"}, "search.results": {"1-9"}, "search.duration": {"<200ms"},
			"search.suggestion_shown": nil,
		}},
		{"a page of cards", searchOutcome{Unique: 250, Took: 3 * time.Second}, map[string][]string{
			"search.result": {"found"}, "search.results": {"100-999"}, "search.duration": {"<5s"},
		}},
		{"cut at the cap", searchOutcome{Unique: 10000, Total: 43000}, map[string][]string{
			"search.result": {"found"}, "search.results": {"10000+"},
		}},
		{"a decklist's repeats", searchOutcome{Unique: 60, Total: 100}, map[string][]string{
			"search.results": {"100-999"},
		}},
		{"suggestions are an empty page's", searchOutcome{Unique: 3, DidYouMean: true}, map[string][]string{
			"search.suggestion_shown": nil,
		}},
		{"other spellings to try", searchOutcome{TryOneOf: true}, map[string][]string{
			"search.suggestion_shown": {"try_one_of"},
		}},
		{"nine cards", searchOutcome{Unique: 9}, map[string][]string{"search.results": {"1-9"}}},
		{"ten cards", searchOutcome{Unique: 10}, map[string][]string{"search.results": {"10-99"}}},
		{"ninety-nine cards", searchOutcome{Unique: 99}, map[string][]string{"search.results": {"10-99"}}},
		{"a hundred cards", searchOutcome{Unique: 100}, map[string][]string{"search.results": {"100-999"}}},
	} {
		facts := searchResultFacts("sealed", c.out)
		for name, want := range c.want {
			if got := factValues(t, facts, name, "sealed"); !slices.Equal(got, want) {
				t.Errorf("%s: %s = %v, want %v", c.desc, name, got, want)
			}
		}
	}
}

func TestSearchLandingFacts(t *testing.T) {
	if got := searchLandingFacts("search", "", ""); len(got) != 0 {
		t.Errorf("the plain landing page counts %v", got)
	}
	for sortOpt, want := range map[string]string{"": "date", "name": "name", "size": "size", "<x>": "date"} {
		got := searchLandingFacts("sets", sortOpt, "")
		if len(got) != 1 || got[0] != newFact("", "sets.sort", want) {
			t.Errorf("sets sorted %q counts %v, want sets.sort:%s", sortOpt, got, want)
		}
	}
	got := searchLandingFacts("search", "", "modal")
	if len(got) != 1 || got[0] != newFact("search", "search.chart", "modal") {
		t.Errorf("the chart picker counts %v", got)
	}
	got = searchLandingFacts("sets", "name", "single")
	if want := []fact{newFact("sets", "search.chart", "single"), newFact("", "sets.sort", "name")}; !slices.Equal(got, want) {
		t.Errorf("a chart on the sets page counts %v, want %v", got, want)
	}
	for _, page := range []string{"search", "sealed"} {
		if got := searchLandingFacts(page, "name", ""); len(got) != 0 {
			t.Errorf("the %s landing page sorted by name counts %v", page, got)
		}
	}
}

func TestSearchSortFrom(t *testing.T) {
	for _, c := range []struct {
		desc, operator, param, cookie string
		velocity                      bool
		sort, from                    string
	}{
		{"nothing asked", "", "", "", false, "", "default"},
		{"the saved default", "", "", "hybrid", false, "hybrid", "cookie"},
		{"the parameter over the cookie", "", "retail", "buylist", false, "retail", "param"},
		{"the operator over both", "alpha", "retail", "buylist", false, "alpha", "operator"},
		{"a locked velocity falls to the cookie", "", "velocity", "alpha", false, "alpha", "cookie"},
		{"a locked velocity with nothing behind it", "", "velocity", "", false, "", "default"},
		{"a locked velocity operator falls to the parameter", "velocity", "retail", "", false, "retail", "param"},
		{"velocity for a reader who may", "", "velocity", "alpha", true, "velocity", "param"},
		{"an unknown parameter still wins", "", "<script>", "alpha", false, "<script>", "param"},
	} {
		target := "/search?q=x"
		if c.param != "" {
			target += "&sort=" + url.QueryEscape(c.param)
		}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: c.cookie})
		}
		config := SearchConfig{SortMode: c.operator, VelocitySort: c.velocity}
		sort, from := searchSortFrom(r, config)
		if sort != c.sort || from != c.from {
			t.Errorf("%s: (%q, %q), want (%q, %q)", c.desc, sort, from, c.sort, c.from)
		}
		if got := readSearchSort(r, config); got != c.sort {
			t.Errorf("%s: readSearchSort = %q, want %q", c.desc, got, c.sort)
		}
	}
}

func TestSearchSource(t *testing.T) {
	for _, c := range []struct {
		utm, referer string
		charting     bool
		want         string
	}{
		{"banbot", "https://example.com/", true, "banbot"},
		{"autocard", "", false, "autocard"},
		{"", "https://mtgban.com/newspaper", true, "chart"},
		{"", "", false, "direct"},
		{"", "https://mtgban.com/search/shared?id=abc", false, "own_site"},
		{"", "https://example.com/deck?id=abc", false, "other_site"},
		{"", "https://mtgban.com,evil.example/x", false, "other_site"},
		{"", "://not a url", false, "other_site"},
		{"somethingelse", "", false, "direct"},
	} {
		if got := searchSource(c.utm, c.referer, c.charting); got != c.want {
			t.Errorf("searchSource(%q, %q, %v) = %q, want %q", c.utm, c.referer, c.charting, got, c.want)
		}
	}
}

func TestSearchPageNameAndChartKind(t *testing.T) {
	for path, want := range map[string]string{"/search": "search", "/sealed": "sealed", "/sets": "sets", "/anything": "search"} {
		if got := searchPageName(path); got != want {
			t.Errorf("searchPageName(%q) = %q, want %q", path, got, want)
		}
	}
	for _, c := range []struct {
		roster chartRoster
		want   string
	}{
		{chartRoster{}, ""},
		{chartRoster{id: "a", ids: []string{"a"}}, "single"},
		{chartRoster{id: "a", ids: []string{"a", "b"}}, "multi"},
		{chartRoster{modal: true, ids: []string{"a", "b"}}, "modal"},
	} {
		if got := searchChartKind(c.roster); got != c.want {
			t.Errorf("searchChartKind(%+v) = %q, want %q", c.roster, got, c.want)
		}
	}
}

func TestReadSearchRun(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/sealed?q=x&p=3&ps=25&reverse=true&sort=retail&utm_source=banbot", nil)
	for name, value := range map[string]string{
		"SearchDefaultTab": "buyers", "SearchListingPriority": "market",
		"SearchMiscOpts": "noSussy,hidePromos,", storeFactorsCookie: "CK:10:85",
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	run := readSearchRun(r, b, SearchConfig{}, []string{"s:fixturea"}, "s:fixturea", false, true, chartRoster{}, nil)

	if run.Page != "sealed" || run.Scope != "set" || run.Sort != "retail" || run.SortFrom != "param" ||
		!run.Reverse || run.PageIndex != 3 || run.PageSize != 25 || run.Source != "banbot" || run.Chart != "" {
		t.Errorf("run = %+v", run)
	}
	if !run.Factors || run.Custom {
		t.Errorf("factors %v custom %v, want true false", run.Factors, run.Custom)
	}
	if run.Views["SearchDefaultTab"] != "buyers" {
		t.Errorf("views = %v", run.Views)
	}
	if _, found := run.Views["SearchListingPriority"]; found {
		t.Error("a locked listing still reports the listing cookie")
	}
	if !slices.Contains(run.Misc, "noSussy") || !slices.Equal(run.PromoTypes, []string{"fixturea"}) || !slices.Equal(run.Pinned, []string{"s:fixturea"}) {
		t.Errorf("misc %v promo types %v pinned %v", run.Misc, run.PromoTypes, run.Pinned)
	}
	for scope, want := range map[string]string{"": "none", "garbage": "ignored"} {
		got := readSearchRun(r, b, SearchConfig{}, nil, scope, scope != "", false, chartRoster{}, nil).Scope
		if got != want {
			t.Errorf("scope %q reads %q, want %q", scope, got, want)
		}
	}
	if got := readSearchRun(r, b, SearchConfig{}, nil, "", false, false, chartRoster{}, nil).Views["SearchListingPriority"]; got != "market" {
		t.Errorf("an open listing reports %q, want market", got)
	}

	// The custom buylist counts only where the search appends it.
	custom := httptest.NewRequest(http.MethodGet, "/search?q=x", nil)
	custom.AddCookie(&http.Cookie{Name: "UploadCustomOpts", Value: "enabled"})
	custom.AddCookie(&http.Cookie{Name: "UploadCustomRate", Value: "50"})
	for _, c := range []struct {
		config SearchConfig
		want   bool
	}{
		{SearchConfig{CustomBuylist: true}, true},
		{SearchConfig{CustomBuylist: true, SkipBuylist: true}, false},
		{SearchConfig{}, false},
	} {
		if got := readSearchRun(custom, b, c.config, nil, "", false, false, chartRoster{}, nil).Custom; got != c.want {
			t.Errorf("custom %+v reads %v, want %v", c.config, got, c.want)
		}
	}
}

func TestSearchCountsWhatItRanWith(t *testing.T) {
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{
		{"Fixture Card Alpha", "1"}, {"Fixture Card Beta", "2"},
	})
	s := fixtureSite(t, b, nil, nil)

	search := func(target, dest string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Sec-Fetch-Dest", dest)
		rec := httptest.NewRecorder()
		s.Search(rec, req)
		return rec
	}
	get := func(t *testing.T, target, dest string) []observability.Row {
		rows := withFeatureCounter(t)
		search(target, dest)
		return rows.rows()
	}
	value := func(t *testing.T, rows []observability.Row, name string) string {
		t.Helper()
		found := find(rows, name)
		if len(found) != 1 || found[0].N != 1 || found[0].Scope != "search" {
			t.Fatalf("%s rows = %+v, want one row counted once under scope search", name, found)
		}
		return found[0].Value
	}
	countsNoSearch := func(t *testing.T, rows []observability.Row) {
		t.Helper()
		for _, row := range rows {
			if strings.HasPrefix(row.Name, "search.") || row.Name == "sets.sort" {
				t.Errorf("counted %s:%s", row.Name, row.Value)
			}
		}
	}

	t.Run("a search that finds one card", func(t *testing.T) {
		rows := get(t, "/search?q="+url.QueryEscape("Fixture Card Alpha s:FIXTUREA")+"&sort=retail", "document")
		for name, want := range map[string]string{
			"search.mode": "default", "search.sort": "retail", "search.sort_from": "param",
			"search.filter": "s", "search.filter_count": "1", "search.scope": "none",
			"search.page": "1", "search.page_size": "100", "search.source": "direct",
			"search.result": "single", "search.results": "1-9",
		} {
			if got := value(t, rows, name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		if len(find(rows, "search.duration")) != 1 {
			t.Error("no search.duration row")
		}
		if len(find(rows, "metrics.rejected")) != 0 {
			t.Errorf("a search rejected facts: %+v", find(rows, "metrics.rejected"))
		}
	})

	t.Run("a search that finds nothing is counted once", func(t *testing.T) {
		rows := get(t, "/search?q=zzzqx&scope="+url.QueryEscape("s:FIXTUREA"), "document")
		if got := value(t, rows, "search.result"); got != "empty" {
			t.Errorf("search.result = %q, want empty", got)
		}
		if got := value(t, rows, "search.scope"); got != "set" {
			t.Errorf("search.scope = %q, want set", got)
		}
		if got := value(t, rows, "search.filter"); got != "s" {
			t.Errorf("search.filter = %q, want the pinned s", got)
		}
		shown := find(rows, "search.suggestion_shown")
		if !slices.ContainsFunc(shown, func(r observability.Row) bool { return r.Value == "unpin_scope" }) {
			t.Errorf("suggestions shown = %+v, want unpin_scope among them", shown)
		}
		if len(find(rows, "metrics.rejected")) != 0 {
			t.Errorf("an empty search rejected facts: %+v", find(rows, "metrics.rejected"))
		}
	})

	t.Run("the page's own fetch counts nothing", func(t *testing.T) {
		countsNoSearch(t, get(t, "/search?q="+url.QueryEscape("Fixture Card Alpha"), "empty"))
		countsNoSearch(t, get(t, "/sets?sort=size", "empty"))
	})

	t.Run("the sets tree counts its order", func(t *testing.T) {
		rows := get(t, "/sets?sort=size", "document")
		found := find(rows, "sets.sort")
		if len(found) != 1 || found[0].Value != "size" || found[0].Scope != "" {
			t.Errorf("sets.sort rows = %+v, want one row, value size", found)
		}
		if len(find(rows, "search.result")) != 0 {
			t.Error("a landing page counted a search")
		}
	})

	t.Run("a query too long to run counts nothing", func(t *testing.T) {
		countsNoSearch(t, get(t, "/search?q="+strings.Repeat("a", MaxSearchQueryLen+1), "document"))
	})

	t.Run("the settings redirect counts nothing", func(t *testing.T) {
		countsNoSearch(t, get(t, "/search?q=x&page=options", "document"))
	})

	t.Run("a search nothing will count reads no run", func(t *testing.T) {
		reads := 0
		prev := buildSearchRun
		buildSearchRun = func(r *http.Request, b *matcher.Backend, config SearchConfig, pinned []string,
			scope string, scopeIgnored, listingLocked bool, roster chartRoster, packs map[string]map[string]bool) searchRun {
			reads++
			return prev(r, b, config, pinned, scope, scopeIgnored, listingLocked, roster, packs)
		}
		t.Cleanup(func() { buildSearchRun = prev })
		target := "/search?q=" + url.QueryEscape("Fixture Card Alpha")
		renders := func(desc string, rec *httptest.ResponseRecorder) {
			t.Helper()
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Fixture Card Alpha") {
				t.Errorf("%s answered %d without the card", desc, rec.Code)
			}
		}

		rows := withFeatureCounter(t)
		renders("a counted view", search(target, "document"))
		if reads != 1 {
			t.Fatalf("a counted view read its run %d times, want 1", reads)
		}
		renders("a fetch", search(target, "empty"))
		FeatureCounter = nil // withFeatureCounter restores it
		renders("a view with no counter", search(target, "document"))
		if reads != 1 {
			t.Errorf("searches nothing counts read their run %d more times", reads-1)
		}
		rows.rows() // closes the counter
	})
}

func TestExportKind(t *testing.T) {
	for _, c := range []struct {
		retail, buylist, sealed bool
		kind, scope             string
	}{
		{true, false, false, "retail", "singles"},
		{false, true, false, "buylist", "singles"},
		{false, false, false, "list", "singles"},
		{true, false, true, "retail", "sealed"},
		{false, true, true, "buylist", "sealed"},
		{false, false, true, "list", "sealed"},
	} {
		kind, scope := exportKind(c.retail, c.buylist, c.sealed)
		if kind != c.kind || scope != c.scope {
			t.Errorf("exportKind(%v, %v, %v) = (%q, %q), want (%q, %q)", c.retail, c.buylist, c.sealed, kind, scope, c.kind, c.scope)
		}
	}
}

func TestSearchExportIsCounted(t *testing.T) {
	withSigMode(t, true, false) // a sigless dev build may download
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	// A seller and a vendor, so the price API answers rather than 503s.
	retail := mtgban.InventoryRecord{}
	retail.Add("FIXTUREA-1", &mtgban.InventoryEntry{Price: 2, Quantity: 1, Conditions: "NM"})
	buylist := mtgban.BuylistRecord{}
	buylist.Add("FIXTUREA-1", &mtgban.BuylistEntry{BuyPrice: 1, Conditions: "NM"})
	s := fixtureSite(t, b, []mtgban.Seller{
		mtgban.NewSellerFromInventory(retail, mtgban.ScraperInfo{Shorthand: "ZZA", Name: "Alpha"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: "ZZB", Name: "Beta"}),
	})

	for _, c := range []struct{ path, kind, scope string }{
		{"/search/export/list/Fixture%20Card%20Alpha.csv", "list", "singles"},
		{"/search/export/whatever/Fixture%20Card%20Alpha.csv", "list", "singles"},
		{"/search/export/retail/Fixture%20Card%20Alpha.csv", "retail", "singles"},
		{"/search/export/buylist/sealed/Fixture%20Card%20Alpha.csv", "buylist", "sealed"},
	} {
		rows := withFeatureCounter(t)
		rec := httptest.NewRecorder()
		s.SearchExport(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		got := find(rows.rows(), "export.search")
		if rec.Code != http.StatusOK || len(got) != 1 || got[0].Value != c.kind || got[0].Scope != c.scope || got[0].N != 1 {
			t.Errorf("%s: answered %d, export.search rows = %+v, want one %s download of %s", c.path, rec.Code, got, c.kind, c.scope)
		}
	}

	t.Run("a 404 counts nothing", func(t *testing.T) {
		rows := withFeatureCounter(t)
		s.SearchExport(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search/export/list/Fixture%20Card%20Alpha.json", nil))
		if got := find(rows.rows(), "export.search"); len(got) != 0 {
			t.Errorf("a 404 counted export.search: %+v", got)
		}
	})

	t.Run("a write that fails counts nothing", func(t *testing.T) {
		prev := log.Writer()
		log.SetOutput(io.Discard) // the error page cannot be written either
		t.Cleanup(func() { log.SetOutput(prev) })
		rows := withFeatureCounter(t)
		s.SearchExport(failingResponse{httptest.NewRecorder()}, httptest.NewRequest(http.MethodGet, "/search/export/list/Fixture%20Card%20Alpha.csv", nil))
		if got := find(rows.rows(), "export.search"); len(got) != 0 {
			t.Errorf("a failed download counted export.search: %+v", got)
		}
	})

	t.Run("a refused reader counts nothing", func(t *testing.T) {
		withSigMode(t, false, true)
		cache, err := buildTemplateCache()
		if err != nil {
			t.Fatalf("templates failed to parse: %v", err)
		}
		prevCache := TemplateCache
		TemplateCache = cache
		t.Cleanup(func() { TemplateCache = prevCache })
		rows := withFeatureCounter(t)
		s.SearchExport(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search/export/list/Fixture%20Card%20Alpha.csv", nil))
		if got := find(rows.rows(), "export.search"); len(got) != 0 {
			t.Errorf("a refused download counted export.search: %+v", got)
		}
	})

	t.Run("the price API counts nothing", func(t *testing.T) {
		rows := withFeatureCounter(t)
		rec := httptest.NewRecorder()
		s.SearchAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgban/search/retail/Fixture%20Card%20Alpha.csv", nil))
		if rec.Code == http.StatusServiceUnavailable {
			t.Fatal("the API answered 503 before reaching its CSV")
		}
		if got := find(rows.rows(), "export.search"); len(got) != 0 {
			t.Errorf("an API call counted export.search: %+v", got)
		}
	})
}

// failingResponse is a client gone away: every write fails.
type failingResponse struct{ *httptest.ResponseRecorder }

func (failingResponse) Write([]byte) (int, error) { return 0, errors.New("client went away") }

func TestRawRecordIsCountedForAdminsOnly(t *testing.T) {
	withSigMode(t, false, true)
	rows := withFeatureCounter(t)
	testSite.RawCardAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search/raw/whatever", nil))
	if got := find(rows.rows(), "export.raw"); len(got) != 0 {
		t.Errorf("a refused request counted export.raw: %+v", got)
	}

	withSigMode(t, true, false)
	rows = withFeatureCounter(t)
	testSite.RawCardAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search/raw/whatever", nil))
	if got := find(rows.rows(), "export.raw"); len(got) != 1 || got[0].Value != "" {
		t.Errorf("export.raw rows = %+v, want one", got)
	}
}

func TestOEmbedAnswersAreCounted(t *testing.T) {
	withSigMode(t, true, false)
	openSearch(t) // oembed_test.go
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	s := fixtureSite(t, b, nil, nil)
	page := func(q string) string { return url.QueryEscape("https://mtgban.com/search?q=" + url.QueryEscape(q)) }

	for _, c := range []struct{ desc, target, want string }{
		{"a format we do not serve", "/search/oembed?format=xml&url=" + page("Fixture Card Alpha"), "unsupported"},
		{"a page that is not ours", "/search/oembed?format=json&url=" + url.QueryEscape("https://example.com/search?q=x"), "not_found"},
		{"a page Search does not draw", "/search/oembed?format=json&url=" + url.QueryEscape("https://mtgban.com/upload?q=x"), "not_found"},
		{"a page with no query", "/search/oembed?format=json&url=" + page(""), "not_found"},
		{"a search with no cards", "/search/oembed?format=json&url=" + page("zzzqx"), "not_found"},
		{"a card we carry", "/search/oembed?format=json&url=" + page("Fixture Card Alpha"), "json"},
	} {
		rows := withFeatureCounter(t)
		s.SearchOEmbed(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, c.target, nil))
		got := find(rows.rows(), "search.oembed")
		if len(got) != 1 || got[0].Value != c.want {
			t.Errorf("%s: search.oembed rows = %+v, want %s", c.desc, got, c.want)
		}
	}
}

// A decklist needs a sealed product that has one, which no fixture holds.
// It swaps the global counter, so it does not run in parallel.
func TestDecklistDownloadsAreCounted(t *testing.T) {
	skipWithoutDatastore(t)
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("no sealed product with a decklist in this datastore")
	}
	// Two sites over the loaded cards: the TCGplayer export fails without a
	// TCGplayer seller, the seam TestFailedExportIsNotADownload uses.
	site := func(sellers []mtgban.Seller) *site {
		s := newSite()
		s.ds.Store(testSite.datastore())
		sitePrices(t, s, sellers, nil)
		return s
	}
	withTCG := site([]mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "TCGPlayer", Name: "TCGplayer"}),
	})
	withoutTCG := site(nil)

	prev := log.Writer()
	log.SetOutput(io.Discard) // the unknown product logs its lookup error
	t.Cleanup(func() { log.SetOutput(prev) })
	for _, c := range []struct {
		desc    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		failing bool
		want    string
	}{
		{"a tcgplayer download", withTCG.TCGHandler, "/search/decklist/tcgplayer/" + co.UUID, false, "tcgplayer"},
		{"a cardmarket download", withTCG.MKMHandler, "/search/decklist/cardmarket/" + co.UUID, false, "cardmarket"},
		{"a tcgplayer export that fails", withoutTCG.TCGHandler, "/search/decklist/tcgplayer/" + co.UUID, false, ""},
		{"an unknown product", withTCG.TCGHandler, "/search/decklist/tcgplayer/nope", false, ""},
		{"a tcgplayer write that fails", withTCG.TCGHandler, "/search/decklist/tcgplayer/" + co.UUID, true, ""},
		{"a cardmarket write that fails", withTCG.MKMHandler, "/search/decklist/cardmarket/" + co.UUID, true, ""},
	} {
		rows := withFeatureCounter(t)
		rec := httptest.NewRecorder()
		var w http.ResponseWriter = rec
		if c.failing {
			w = failingResponse{rec}
		}
		c.handler(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		got := find(rows.rows(), "export.decklist")
		if c.failing {
			if len(got) != 0 {
				t.Errorf("%s: export.decklist rows = %+v, want none", c.desc, got)
			}
			continue
		}
		if c.want == "" {
			if rec.Code == http.StatusOK || len(got) != 0 {
				t.Errorf("%s: answered %d, export.decklist rows = %+v, want a refusal and none", c.desc, rec.Code, got)
			}
			continue
		}
		if rec.Code != http.StatusOK || len(got) != 1 || got[0].Value != c.want {
			t.Errorf("%s: answered %d, export.decklist rows = %+v, want one %s", c.desc, rec.Code, got, c.want)
		}
	}
}
