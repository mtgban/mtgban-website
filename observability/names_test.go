package observability

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	if _, ok := Lookup("http.status"); !ok {
		t.Fatal("http.status is registered")
	}
	for _, name := range []string{
		"search.mode", "search.sort", "search.sort_from", "search.reverse", "search.filter",
		"search.is", "search.on", "search.region", "search.pool", "search.finish_suffix",
		"search.syntax", "search.filter_count", "search.scope", "search.page", "search.page_size",
		"search.source", "search.chart", "search.view", "search.misc", "search.store_factors",
		"search.custom_buylist", "search.result", "search.results", "search.suggestion_shown",
		"search.duration", "sets.sort", "search.oembed", "export.search", "export.decklist", "export.raw",
		"data.chart", "data.chart_ids", "data.prices", "suggest.fetch", "palette.list", "palette.chip_fetch",
		"settings.modal_fetch", "settings.values_fetch", "opensearch.fetch",
	} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("%s is registered", name)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("an unknown name is not found")
	}
}

// A search candidate's rate is a share of the searches that ran; the rest count page loads.
func TestSearchDenominators(t *testing.T) {
	want := []string{
		"search.mode", "search.sort", "search.reverse", "search.filter", "search.is", "search.on",
		"search.region", "search.pool", "search.finish_suffix", "search.syntax", "search.view",
		"search.misc", "search.store_factors", "search.custom_buylist",
	}
	var got []string
	for _, n := range All() {
		if n.Denom == "search.result" {
			got = append(got, n.Name)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("names with the search.result denominator = %v, want %v", got, want)
	}
	for name, page := range map[string]string{"search.chart": "search,sealed,sets", "sets.sort": "sets", "export.search": "search,sealed", "export.decklist": "search,sealed"} {
		if n, _ := Lookup(name); n.Page != page || n.Denom != "" {
			t.Errorf("%s: Page %q Denom %q, want Page %q and no Denom", name, n.Page, n.Denom, page)
		}
	}
}

func TestCheck(t *testing.T) {
	v := Validators{
		Store:   func(s string) bool { return s == "CK" || s == "A B" || strings.HasPrefix(s, "TCGSI") || len(s) > 40 },
		Page:    func(s string) bool { return s == "search" },
		Route:   func(s string) bool { return s == "search" },
		Setting: func(s string) bool { return s == "SearchSort" },
		SettingValue: func(setting, value string) bool {
			return setting == "SearchSort" && (value == "alpha" || value == "set")
		},
		Origin: func(s string) bool { return s == "moxfield.com" },
	}
	enum := Name{Name: "x", Values: ValueEnum, Enum: []string{"a", "b"}}
	bucket := Name{Name: "b", Values: ValueBucket, Enum: []string{"0", "1", "2+"}}
	flag := Name{Name: "f", Values: ValueFlag}
	store := Name{Name: "y", Values: ValueStore, Scope: ScopeEnum, Scopes: []string{"seller", "buyer"}}
	routed := Name{Name: "z", Values: ValueEnum, Enum: []string{"2xx"}, Scope: ScopeRoute}
	paged := Name{Name: "p", Scope: ScopePage}
	byStore := Name{Name: "s", Scope: ScopeStore}
	pageValue := Name{Name: "pv", Values: ValuePage}
	setting := Name{Name: "state.x", Values: ValueSetting, Scope: ScopeSetting}
	origin := Name{Name: "o", Values: ValueOrigin}
	none := Name{Name: "n"}

	cases := []struct {
		what         string
		n            Name
		scope, value string
		wantS, wantV string
		ok           bool
	}{
		{"an enum value", enum, "", "a", "", "a", true},
		{"a value not in the enum", enum, "", "c", "", "", false},
		{"an empty value on an enum", enum, "", "", "", "", false},
		{"a scope where the name has none", enum, "s", "a", "", "", false},
		{"a bucket value", bucket, "", "2+", "", "2+", true},
		{"a value that is no bucket", bucket, "", "7", "", "", false},
		{"a flag on", flag, "", "on", "", "on", true},
		{"a flag off", flag, "", "off", "", "off", true},
		{"a flag that is neither", flag, "", "true", "", "", false},
		{"a store value in an enum scope", store, "seller", "CK", "seller", "CK", true},
		{"an unknown store value folds", store, "seller", "Bob's Cards", "seller", "other", true},
		{"a known store value with a space folds", store, "seller", "A B", "seller", "other", true},
		{"a known store value over 40 bytes folds", store, "seller", strings.Repeat("Z", 41), "seller", "other", true},
		{"a seller inventory's shorthand", store, "seller", "TCGSI_a1b2,c3d4+direct", "seller", "TCGSI_a1b2,c3d4+direct", true},
		{"a scope not in the scope enum", store, "elsewhere", "CK", "", "", false},
		{"an empty scope on an enum-scoped name", store, "", "CK", "", "", false},
		{"a known route", routed, "search", "2xx", "search", "2xx", true},
		{"an unknown route folds", routed, "/debug/x", "2xx", "other", "2xx", true},
		{"an empty scope on a routed name", routed, "", "2xx", "", "", false},
		{"a known page scope", paged, "search", "", "search", "", true},
		{"an unknown page scope folds", paged, "wp-login.php", "", "other", "", true},
		{"an empty scope on a paged name", paged, "", "", "", "", false},
		{"a known store scope", byStore, "CK", "", "CK", "", true},
		{"an unknown store scope folds", byStore, "Bob's Cards", "", "other", "", true},
		{"a known store scope with a space folds", byStore, "A B", "", "other", "", true},
		{"a known store scope over 40 bytes folds", byStore, strings.Repeat("Z", 41), "", "other", "", true},
		{"an empty scope on a store-scoped name", byStore, "", "", "", "", false},
		{"a known page value", pageValue, "", "search", "", "search", true},
		{"an unknown page value folds", pageValue, "", "wp-login.php", "", "other", true},
		{"a setting and a value it allows", setting, "SearchSort", "alpha", "SearchSort", "alpha", true},
		{"a setting the validator refuses", setting, "NoSuchCookie", "alpha", "", "", false},
		{"a value the setting refuses", setting, "SearchSort", "free text", "", "", false},
		{"an empty scope on a setting", setting, "", "alpha", "", "", false},
		{"a configured origin", origin, "", "moxfield.com", "", "moxfield.com", true},
		{"an unknown origin folds", origin, "", "evil.example", "", "other", true},
		{"no scope, no value", none, "", "", "", "", true},
		{"a value where the name has none", none, "", "anything", "", "", false},
	}
	for _, c := range cases {
		s, val, ok := c.n.Check(c.scope, c.value, v)
		if ok != c.ok || s != c.wantS || val != c.wantV {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", c.what, s, val, ok, c.wantS, c.wantV, c.ok)
		}
	}
}

// With no validators a folding kind folds and a rejecting kind rejects.
func TestCheckWithNoValidators(t *testing.T) {
	var none Validators
	if s, _, ok := (Name{Name: "z", Scope: ScopeRoute}).Check("search", "", none); !ok || s != "other" {
		t.Errorf("a route with no validator folds: got (%q, %v)", s, ok)
	}
	if _, v, ok := (Name{Name: "y", Values: ValueStore}).Check("", "CK", none); !ok || v != "other" {
		t.Errorf("a store with no validator folds: got (%q, %v)", v, ok)
	}
	if _, v, ok := (Name{Name: "o", Values: ValueOrigin}).Check("", "moxfield.com", none); !ok || v != "other" {
		t.Errorf("an origin with no validator folds: got (%q, %v)", v, ok)
	}
	if s, _, ok := (Name{Name: "s", Scope: ScopeStore}).Check("CK", "", none); !ok || s != "other" {
		t.Errorf("a store scope with no validator folds: got (%q, %v)", s, ok)
	}
	if _, v, ok := (Name{Name: "pv", Values: ValuePage}).Check("", "search", none); !ok || v != "other" {
		t.Errorf("a page value with no validator folds: got (%q, %v)", v, ok)
	}
	set := Name{Name: "state.x", Values: ValueSetting, Scope: ScopeSetting}
	if _, _, ok := set.Check("SearchSort", "alpha", none); ok {
		t.Error("a setting with no validator rejects")
	}
	scopeOnly := Validators{Setting: func(string) bool { return true }}
	if _, _, ok := set.Check("SearchSort", "alpha", scopeOnly); ok {
		t.Error("a setting value with no SettingValue validator rejects")
	}
	if _, _, ok := (Name{Name: "f", Values: ValueFlag}).Check("", "", none); ok {
		t.Error("an empty flag value rejects")
	}
	if _, _, ok := (Name{Name: "b", Values: ValueBucket, Enum: []string{"0", "1+"}}).Check("", "", none); ok {
		t.Error("an empty bucket value rejects")
	}
}

func TestBucket(t *testing.T) {
	edges := []int64{1, 10, 100, 1000}
	for n, want := range map[int64]string{-3: "0", 0: "0", 1: "1-9", 9: "1-9", 10: "10-99", 999: "100-999", 1000: "1000+", 50000: "1000+"} {
		if got := Bucket(edges, n); got != want {
			t.Errorf("Bucket(%d) = %q, want %q", n, got, want)
		}
	}
	// A bucket one number wide prints as that number.
	narrow := []int64{1, 2, 3, 6}
	for n, want := range map[int64]string{0: "0", 1: "1", 2: "2", 3: "3-5", 5: "3-5", 6: "6+"} {
		if got := Bucket(narrow, n); got != want {
			t.Errorf("Bucket(narrow, %d) = %q, want %q", n, got, want)
		}
	}
}

// No registry string outgrows the columns' budget.
func TestRegistryStringsAreShort(t *testing.T) {
	const limit = 40
	for _, n := range All() {
		if len(n.Name) > limit {
			t.Errorf("name %q is over %d characters", n.Name, limit)
		}
		for _, s := range n.Scopes {
			if len(s) > limit {
				t.Errorf("%s: scope %q is over %d characters", n.Name, s, limit)
			}
		}
		for _, v := range n.Enum {
			if len(v) > limit {
				t.Errorf("%s: value %q is over %d characters", n.Name, v, limit)
			}
		}
		// The beacon drops anything else, so such an entry could never arrive.
		for _, s := range slices.Concat([]string{n.Name}, n.Enum, n.Scopes) {
			if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				t.Errorf("%s: %q is not printable ASCII", n.Name, s)
			}
		}
	}
}

func TestClientBeaconNames(t *testing.T) {
	load, ok := Lookup("ui.load")
	if !ok || load.Family != FamilyUI || load.Scope != ScopePage || load.Values != ValueNone || load.Report != ReportInternal {
		t.Fatalf("ui.load = %+v, %v", load, ok)
	}
	v := Validators{Page: func(s string) bool { return s == "search" }}
	if s, val, ok := load.Check("search", "", v); !ok || s != "search" || val != "" {
		t.Errorf("ui.load for a known page = (%q, %q, %v)", s, val, ok)
	}
	if s, _, ok := load.Check("/wp-login.php", "", v); !ok || s != "other" {
		t.Errorf("ui.load for an unknown page = (%q, %v), want it folded to other", s, ok)
	}
	if _, _, ok := load.Check("search", "x", v); ok {
		t.Error("ui.load takes no value")
	}
	if _, _, ok := load.Check("", "", v); ok {
		t.Error("ui.load with no scope is refused: a scoped name always carries one")
	}
}

func TestBeaconReasonNames(t *testing.T) {
	for name, values := range map[string][]string{
		"metrics.beacon": {"ok", "bad_body", "too_many"},
		"metrics.client": {"accepted", "unknown", "family", "value", "count"},
	} {
		n, ok := Lookup(name)
		if !ok || n.Family != FamilyServer || n.Values != ValueEnum || n.Scope != ScopeNone || !slices.Equal(n.Enum, values) {
			t.Errorf("%s = %+v, %v", name, n, ok)
		}
	}
}

func TestRateLimitRejectValues(t *testing.T) {
	n, _ := Lookup("ratelimit.reject")
	for _, v := range []string{"page", "api", "vote", "upload_share", "favorites_share", "userstate", "alerts", "alerts_confirm", "metrics"} {
		if !slices.Contains(n.Enum, v) {
			t.Errorf("ratelimit.reject lacks the value %q", v)
		}
	}
}

// Every entry is well formed: unique, lowercase dotted, and consistent.
func TestRegistryIsWellFormed(t *testing.T) {
	dotted := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)
	seen := map[string]bool{}
	for _, n := range All() {
		if !dotted.MatchString(n.Name) {
			t.Errorf("%q is not lowercase dotted", n.Name)
		}
		if seen[n.Name] {
			t.Errorf("%s registered twice", n.Name)
		}
		seen[n.Name] = true
		if n.Help == "" {
			t.Errorf("%s has no help line", n.Name)
		}
		if (n.Values == ValueEnum || n.Values == ValueBucket) && len(n.Enum) == 0 {
			t.Errorf("%s is an enum with no values", n.Name)
		}
		if n.Scope == ScopeEnum && len(n.Scopes) == 0 {
			t.Errorf("%s has an enum scope with no values", n.Name)
		}
		if strings.HasPrefix(n.Name, "ui.") != (n.Family == FamilyUI) {
			t.Errorf("%s: the ui. prefix and the UI family go together", n.Name)
		}
		if strings.HasPrefix(n.Name, "state.") != (n.Family == FamilyState) {
			t.Errorf("%s: the state. prefix and the State family go together", n.Name)
		}
		if n.Report == ReportCandidate && n.Kind == "" {
			t.Errorf("%s is a candidate with no kind", n.Name)
		}
		if n.Denom != "" {
			if _, ok := Lookup(n.Denom); !ok {
				t.Errorf("%s: its denominator %q is not registered", n.Name, n.Denom)
			}
		}
		if n.Page != "" && n.Page != "*" {
			for _, p := range strings.Split(n.Page, ",") {
				if p == "" || strings.TrimSpace(p) != p {
					t.Errorf("%s: Page %q is a comma-separated list with no spaces or gaps", n.Name, n.Page)
				}
			}
		}
		if n.Values == ValueSetting && n.Scope != ScopeSetting {
			t.Errorf("%s: a setting value needs the setting as its scope", n.Name)
		}
	}
}

// Each case is one (name, scope, value) a server emitter sends.
func TestServerNamesAccept(t *testing.T) {
	v := Validators{
		Store:  func(s string) bool { return s == "CK" },
		Page:   func(s string) bool { return s == "search" },
		Route:  func(s string) bool { return s == "api.v2" },
		Origin: func(s string) bool { return s == "www.cardmarket.com" },
	}
	for _, c := range []struct{ name, scope, value string }{
		{"upload.source", "", "handoff"}, {"upload.url_host", "", "gdocs"},
		{"upload.handoff_origin", "", "www.cardmarket.com"}, {"upload.from", "", "unknown"},
		{"upload.mode", "", "buylist"}, {"upload.rows", "", "1000+"}, {"upload.sealed", "", "some"},
		{"upload.option", "", "customperc"}, {"upload.value_set", "", "maxqty"},
		{"upload.sorting", "", "setchrono"}, {"upload.price_source", "", "marketCredit"},
		{"upload.custom_buylist", "", ""}, {"upload.stores", "", "20+"}, {"upload.index_pref", "", ""},
		{"upload.unpack", "", ""}, {"upload.publish", "", ""},
		{"upload.parse_error", "file_xls", "load_error"}, {"upload.duration", "", "5s+"},
		{"upload_share.open", "", "gone"},
		{"upload.export", "singles", "download"}, {"upload.tag", "TCG", "tcg_remove"},
		{"upload.handoff_page", "", "locked"}, {"upload_share.create", "", "retail"},
		{"arbit.view", "global", "landing"}, {"arbit.source", "global", "CK"}, {"arbit.apply", "global", "reset"},
		{"arbit.bound", "global", "minprof"}, {"arbit.pick", "global", "rarity"}, {"arbit.toggle", "global", "legit"},
		{"arbit.sort", "global", "sell_price"}, {"arbit.excluded_vendors", "global", "10+"},
		{"arbit.sections", "global", "20+"}, {"arbit.duration", "global", "<50ms"},
		{"news.report", "", "index"}, {"news.three_day", "", "on"}, {"news.sort", "desc", "sellers_d30"},
		{"news.filter", "", "edition"}, {"news.page", "", "6+"}, {"news.syp_csv", "", ""},
		{"news.syp_sort", "", "sell_price"}, {"news.editions_hidden", "", "20+"},
		{"sleepers.page", "", "velocity"}, {"sleepers.gap", "", "custom"}, {"sleepers.ref", "", "CK"},
		{"sleepers.target", "", "CK"}, {"sleepers.lists", "", "editions"}, {"sleepers.duration", "", "5s+"},
		{"screener.provider", "", "SealedEV"}, {"screener.window", "", "365"}, {"screener.kind", "", "both"},
		{"screener.move", "", "either"}, {"screener.filter", "", "edition"}, {"screener.size", "", "100"},
		{"screener.sort", "asc", "abs"}, {"screener.page", "", "6+"},
		{"alerts.create", "search", "retail"}, {"alerts.create_delivery", "", "email"},
		{"alerts.create_condition", "", "PO"}, {"alerts.create_threshold", "", "below_pct"},
		{"alerts.create_stores", "", "10+"}, {"alerts.edit", "", ""}, {"alerts.pause", "", ""},
		{"alerts.resume", "", ""}, {"alerts.delete", "", ""}, {"alerts.delete_all", "", ""},
		{"alerts.channel", "", "unsubscribe"}, {"alerts.fired", "", "buylist"},
		{"alerts.delivered", "email", "deferred"}, {"alerts.delivered", "discord", "refused"},
		{"alerts.mail_event", "", "hard_bounce"}, {"alerts.deep_link", "", "edit"},
		{"ratelimit.reject", "", "alerts"}, {"ratelimit.reject", "", "alerts_confirm"},
		{"auth.login", "", "fail_tier"}, {"auth.renew", "", "session_gone"}, {"auth.logout", "", "everywhere"},
		{"account.refresh", "", ""}, {"apiplans.view", "", "prefilled"},
		{"apiplans.handoff", "start", "trial"}, {"apiplans.handoff", "refused", "unknown"},
		{"userstate.get", "", ""}, {"userstate.put", "", ""}, {"userstate.patch", "", "backpack"},
		{"userstate.conflict", "", ""}, {"ratelimit.reject", "", "userstate"},
		{"favshare.create", "", ""}, {"favshare.stop", "", ""},
		{"favshare.view", "", ""}, {"favshare.view_gone", "", ""},
		{"patreon.webhook", "", "pledge_delete"}, {"patreon.webhook", "", "bad_signature"},
		{"patreon.webhook", "", "no_email"},
		{"go.click", "CK", "b"}, {"go.click", "Some Store Name", "r"}, {"go.click", "CK", "i"},
		{"redirect.random", "", "chart_modal"}, {"redirect.card", "", ""}, {"redirect.sealed", "", ""},
		{"redirect.discord", "", ""}, {"redirect.partner", "", ""}, {"view.toggle", "", "to_desktop"},
		{"api.call", "api.v2", "csv"}, {"api.option", "", "conditions"}, {"api.refuse", "api.v2", "plan"},
		{"offlineapi.fetch", "", "bucket_auth"},
		{"discord.message", "", "gatherer_link"}, {"discord.store_link", "", "amzn"}, {"discord.guild_join", "", ""},
	} {
		n, ok := Lookup(c.name)
		if !ok {
			t.Errorf("%s is not registered", c.name)
			continue
		}
		if _, _, ok := n.Check(c.scope, c.value, v); !ok {
			t.Errorf("%s refuses scope %q value %q", c.name, c.scope, c.value)
		}
	}
	if n, ok := Lookup("go.click"); ok {
		if scope, _, _ := n.Check("Some Store Name", "r", v); scope != "other" {
			t.Errorf("go.click stores an unknown store as %q, want other", scope)
		}
	}
}
