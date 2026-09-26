package apiproductlist

import (
	"slices"
	"strings"
	"testing"
)

func TestEmbeddedListMatchesIssue230(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Currency != "usd" {
		t.Errorf("currency %q", c.Currency)
	}
	if len(c.Packages) != 3 || c.Packages[0].Key != "starter" || c.Packages[1].Key != "all_stores" || c.Packages[2].Key != "all_data" {
		t.Errorf("packages %+v", c.Packages)
	}
	if c.Packages[0].Monthly != 20000 || c.Packages[1].Monthly != 50000 || c.Packages[2].Monthly != 80000 {
		t.Errorf("amounts %+v", c.Packages)
	}
	if c.Packages[0].StoreScope != StoreScopeExplicit || c.Packages[0].IncludedStores != 1 {
		t.Errorf("starter %+v", c.Packages[0])
	}
	// The 500 tier is BASE_ACCESS per issue 230; the 800 tier adds sealed and every region.
	if c.Packages[1].StoreScope != StoreScopeBase || c.Packages[2].StoreScope != StoreScopeAll {
		t.Errorf("scopes %+v", c.Packages)
	}
	if !slices.Equal(c.Packages[1].Modes, []string{"retail", "buylist"}) || !slices.Equal(c.Packages[2].Modes, Modes) {
		t.Errorf("modes %+v", c.Packages)
	}
	if len(c.Addons) != 2 || c.Addons[0].Key != "extra_store" || c.Addons[1].Key != "extra_game" {
		t.Errorf("addons %+v", c.Addons)
	}
	if len(c.Intervals) != 2 || !c.Intervals[0].Public || c.Intervals[1].Public || c.Intervals[1].Count != 3 {
		t.Errorf("intervals %+v", c.Intervals)
	}
	if c.IncludedGames != 1 {
		t.Errorf("included games %v", c.IncludedGames)
	}
	if c.Implied.Key != "tcg" || c.Implied.Name != "TCGplayer" {
		t.Errorf("implied %+v", c.Implied)
	}
}

func TestMustLoadDoesNotPanic(t *testing.T) {
	if MustLoad() == nil {
		t.Fatal("nil list")
	}
}

const minimal = `{
  "currency": "usd",
  "packages": [{"key": "p", "name": "P", "monthly": 100, "store_scope": "ALL_ACCESS", "modes": ["retail"], "icon": "globe", "subtitle": "S", "bullets": ["B"]}],
  "addons": [],
  "intervals": [{"key": "monthly", "interval": "month", "count": 1, "public": true}],
  "included_games": 1
}`

// explicit is minimal with a store-picking package, which needs an implied store.
const explicit = `{
  "currency": "usd",
  "packages": [{"key": "p", "name": "P", "monthly": 100, "store_scope": "explicit", "included_stores": 1, "modes": ["retail"], "icon": "globe", "subtitle": "S", "bullets": ["B"]}],
  "addons": [],
  "intervals": [{"key": "monthly", "interval": "month", "count": 1, "public": true}],
  "included_games": 1,
  "implied": {"key": "tcg", "name": "TCGplayer"}
}`

func TestParseMinimal(t *testing.T) {
	for _, doc := range []string{minimal, explicit} {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Fatal(err)
		}
	}
}

// rep is strings.Replace of the first occurrence, for readable table rows.
func rep(doc, old, with string) string {
	return strings.Replace(doc, old, with, 1)
}

func TestValidateRejects(t *testing.T) {
	const pkg = `"packages": [{"key": "p", "name": "P", "monthly": 100, "store_scope": "ALL_ACCESS", "modes": ["retail"], "icon": "globe", "subtitle": "S", "bullets": ["B"]}]`
	const ivs = `"intervals": [{"key": "monthly", "interval": "month", "count": 1, "public": true}]`
	cases := []struct {
		name string
		json string
		want string
	}{
		{"no currency", rep(minimal, `"usd"`, `""`), "currency must be one of [usd]"},
		{"unsupported currency", rep(minimal, `"usd"`, `"eur"`), "currency must be one of [usd]"},
		{"no packages", rep(minimal, pkg, `"packages": []`), "at least one package is required"},
		{"bad key", rep(minimal, `"key": "p"`, `"key": "P-1"`), `key "P-1" must match`},
		{"package key taken by an interval", rep(minimal, `"key": "p"`, `"key": "monthly"`), `duplicate key "monthly"`},
		{"empty package name", rep(minimal, `"name": "P"`, `"name": ""`), "package p: name is empty"},
		{"no icon", rep(minimal, `, "icon": "globe"`, ``), "package p: icon is empty"},
		{"no subtitle", rep(minimal, `, "subtitle": "S"`, ``), "package p: subtitle is empty"},
		{"no bullets", rep(minimal, `"bullets": ["B"]`, `"bullets": []`), "package p: at least one bullet is required"},
		{"zero amount", rep(minimal, `"monthly": 100`, `"monthly": 0`), "package p: monthly must be positive"},
		{"negative amount", rep(minimal, `"monthly": 100`, `"monthly": -5`), "package p: monthly must be positive"},
		{"unknown scope", rep(minimal, `"ALL_ACCESS"`, `"DEV_ACCESS"`), "package p: store_scope must be one of"},
		{"explicit without stores", rep(minimal, `"store_scope": "ALL_ACCESS"`, `"store_scope": "explicit"`), "included_stores must be at least 1"},
		{"preset with stores", rep(minimal, `"store_scope": "ALL_ACCESS"`, `"store_scope": "ALL_ACCESS", "included_stores": 1`), "included_stores applies to an explicit scope only"},
		{"bad mode", rep(minimal, `["retail"]`, `["all"]`), `package p modes: "all" must be one of`},
		{"duplicate mode", rep(minimal, `["retail"]`, `["retail", "retail"]`), `package p modes: duplicate "retail"`},
		{"modes out of order", rep(minimal, `["retail"]`, `["buylist", "retail"]`), "package p modes: must be listed in the order"},
		{"no modes", rep(minimal, `["retail"]`, `[]`), "package p modes is empty"},
		{"addon empty name", rep(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "", "monthly": 1, "applies_to": ["p"]}]`), "addon x: name is empty"},
		{"addon zero amount", rep(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 0, "applies_to": ["p"]}]`), "addon x: monthly must be positive"},
		{"addon unknown package", rep(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 1, "applies_to": ["nope"]}]`), `addon x applies_to: "nope" must be a known package`},
		{"addon no packages", rep(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 1, "applies_to": []}]`), "addon x applies_to is empty"},
		{"addon duplicate package", rep(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 1, "applies_to": ["p", "p"]}]`), `addon x applies_to: duplicate "p"`},
		{"duplicate key across kinds", rep(minimal, `"addons": []`, `"addons": [{"key": "p", "name": "X", "monthly": 1, "applies_to": ["p"]}]`), `duplicate key "p"`},
		{"no intervals", rep(minimal, ivs, `"intervals": []`), "at least one interval is required"},
		{"no public interval", rep(minimal, `"public": true`, `"public": false`), "at least one interval must be public"},
		{"bad interval unit", rep(minimal, `"interval": "month"`, `"interval": "fortnight"`), "interval monthly: interval must be one of [month]"},
		{"week interval", rep(minimal, `"interval": "month"`, `"interval": "week"`), "interval monthly: interval must be one of [month]"},
		{"year interval", rep(minimal, `"interval": "month"`, `"interval": "year"`), "interval monthly: interval must be one of [month]"},
		{"zero count", rep(minimal, `"count": 1`, `"count": 0`), "interval monthly: count must be at least 1"},
		{"zero included games", rep(minimal, `"included_games": 1`, `"included_games": 0`), "included_games must be at least 1"},
		{"explicit without implied store", rep(explicit, `,
  "implied": {"key": "tcg", "name": "TCGplayer"}`, ``), "an explicit package needs an implied store"},
		{"explicit with empty implied key", rep(explicit, `"key": "tcg"`, `"key": ""`), "an explicit package needs an implied store"},
		{"uppercase implied key", rep(explicit, `"key": "tcg"`, `"key": "TCG"`), `implied key "TCG" must be lowercase letters and digits`},
		{"implied key with underscore", rep(explicit, `"key": "tcg"`, `"key": "tcg_index"`), `implied key "tcg_index" must be lowercase letters and digits`},
		{"implied without name", rep(explicit, `"name": "TCGplayer"`, `"name": ""`), "implied tcg: name is empty"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.json))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want containing %q", c.name, err, c.want)
		}
	}
}

func TestValidateRejectsLookupKeyCollision(t *testing.T) {
	c := ProductList{
		Currency: "usd",
		Packages: []Package{
			{Key: "a_b", Name: "A B", Monthly: 100, StoreScope: StoreScopeAll, Modes: []string{"retail"}, Icon: "globe", Subtitle: "S", Bullets: []string{"B"}},
			{Key: "a", Name: "A", Monthly: 100, StoreScope: StoreScopeAll, Modes: []string{"retail"}, Icon: "globe", Subtitle: "S", Bullets: []string{"B"}},
		},
		Intervals: []Interval{
			{Key: "monthly", Interval: "month", Count: 1, Public: true},
			{Key: "b_monthly", Interval: "month", Count: 1},
		},
		IncludedGames: 1,
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), `lookup key "a_b_monthly" is produced by more than one`) {
		t.Errorf("collision: %v", err)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{")); err == nil {
		t.Error("expected error")
	}
}

func TestLookups(t *testing.T) {
	c := MustLoad()
	if p, ok := c.Package("all_data"); !ok || p.Monthly != 80000 {
		t.Errorf("package lookup %+v %v", p, ok)
	}
	if _, ok := c.Package("nope"); ok {
		t.Error("unknown package found")
	}
	if a, ok := c.Addon("extra_game"); !ok || !a.Applies("all_stores") || a.Applies("nope") {
		t.Errorf("addon lookup %+v %v", a, ok)
	}
	if a, _ := c.Addon("extra_store"); a.Applies("all_data") {
		t.Error("extra_store applies to all_data")
	}
	if _, ok := c.Addon("nope"); ok {
		t.Error("unknown addon found")
	}
	if iv, ok := c.Interval("quarterly"); !ok || iv.Count != 3 || iv.Public {
		t.Errorf("interval lookup %+v %v", iv, ok)
	}
	if _, ok := c.Interval("nope"); ok {
		t.Error("unknown interval found")
	}
	if pub := c.PublicIntervals(); len(pub) != 1 || pub[0].Key != "monthly" {
		t.Errorf("public intervals %+v", pub)
	}
}

func TestLookupKey(t *testing.T) {
	if got := LookupKey("starter", "monthly"); got != "starter_monthly" {
		t.Errorf("got %q", got)
	}
	if got := LookupKey("extra_game", "quarterly"); got != "extra_game_quarterly" {
		t.Errorf("got %q", got)
	}
}

func TestIntervalAmount(t *testing.T) {
	cases := []struct {
		iv      Interval
		monthly int64
		want    int64
	}{
		{Interval{Interval: "month", Count: 1}, 20000, 20000},
		{Interval{Interval: "month", Count: 3}, 20000, 60000},
	}
	for _, c := range cases {
		got, err := c.iv.Amount(c.monthly)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %d %v want %d", c.iv, got, err, c.want)
		}
	}
	for _, unit := range []string{"year", "week", ""} {
		if got, err := (Interval{Key: "x", Interval: unit, Count: 1}).Amount(20000); err == nil || got != 0 {
			t.Errorf("%q: got %d %v, want an error", unit, got, err)
		}
	}
}
