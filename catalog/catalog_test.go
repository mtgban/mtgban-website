package catalog

import (
	"strings"
	"testing"
)

func TestEmbeddedCatalogMatchesSpec(t *testing.T) {
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
	if c.Packages[1].StoreScope != "BASE_ACCESS" || c.Packages[2].StoreScope != "ALL_ACCESS" {
		t.Errorf("scopes %+v", c.Packages)
	}
	if len(c.Packages[2].Modes) != 3 || len(c.Packages[1].Modes) != 2 {
		t.Errorf("modes %+v", c.Packages)
	}
	if len(c.Addons) != 2 || c.Addons[0].Key != "extra_store" || c.Addons[1].Key != "extra_game" {
		t.Errorf("addons %+v", c.Addons)
	}
	if len(c.Intervals) != 2 || !c.Intervals[0].Public || c.Intervals[1].Public || c.Intervals[1].Count != 3 {
		t.Errorf("intervals %+v", c.Intervals)
	}
	if len(c.IncludedGames) != 1 || c.IncludedGames[0] != "magic" {
		t.Errorf("included games %v", c.IncludedGames)
	}
	for _, s := range c.SelectableStores {
		if s == "TCG" {
			t.Error("TCG is implied and must not be selectable")
		}
	}
}

func TestMustLoadDoesNotPanic(t *testing.T) {
	if MustLoad() == nil {
		t.Fatal("nil catalog")
	}
}

const minimal = `{
  "currency": "usd",
  "packages": [{"key": "p", "name": "P", "monthly": 100, "store_scope": "ALL_ACCESS", "modes": ["retail"]}],
  "addons": [],
  "intervals": [{"key": "monthly", "interval": "month", "count": 1, "public": true}],
  "included_games": ["magic"],
  "selectable_stores": ["CK"]
}`

func TestParseMinimal(t *testing.T) {
	if _, err := Parse([]byte(minimal)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"no currency", strings.Replace(minimal, `"usd"`, `""`, 1), "currency"},
		{"no packages", strings.Replace(minimal, `"packages": [{"key": "p", "name": "P", "monthly": 100, "store_scope": "ALL_ACCESS", "modes": ["retail"]}]`, `"packages": []`, 1), "at least one package"},
		{"bad key", strings.Replace(minimal, `"key": "p"`, `"key": "P-1"`, 1), `key "P-1"`},
		{"zero amount", strings.Replace(minimal, `"monthly": 100`, `"monthly": 0`, 1), "monthly"},
		{"unknown scope", strings.Replace(minimal, `"ALL_ACCESS"`, `"DEV_ACCESS"`, 1), "store_scope"},
		{"explicit without stores", strings.Replace(minimal, `"store_scope": "ALL_ACCESS"`, `"store_scope": "explicit"`, 1), "included_stores"},
		{"preset with stores", strings.Replace(minimal, `"store_scope": "ALL_ACCESS"`, `"store_scope": "ALL_ACCESS", "included_stores": 1`, 1), "included_stores"},
		{"bad mode", strings.Replace(minimal, `["retail"]`, `["all"]`, 1), "mode"},
		{"duplicate mode", strings.Replace(minimal, `["retail"]`, `["retail", "retail"]`, 1), "mode"},
		{"no modes", strings.Replace(minimal, `["retail"]`, `[]`, 1), "mode"},
		{"addon unknown package", strings.Replace(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 1, "applies_to": ["nope"]}]`, 1), "applies_to"},
		{"addon no packages", strings.Replace(minimal, `"addons": []`, `"addons": [{"key": "x", "name": "X", "monthly": 1, "applies_to": []}]`, 1), "applies_to"},
		{"duplicate key across kinds", strings.Replace(minimal, `"addons": []`, `"addons": [{"key": "p", "name": "X", "monthly": 1, "applies_to": ["p"]}]`, 1), `duplicate key "p"`},
		{"no intervals", strings.Replace(minimal, `"intervals": [{"key": "monthly", "interval": "month", "count": 1, "public": true}]`, `"intervals": []`, 1), "interval"},
		{"no public interval", strings.Replace(minimal, `"public": true`, `"public": false`, 1), "public"},
		{"bad interval unit", strings.Replace(minimal, `"interval": "month"`, `"interval": "fortnight"`, 1), "interval"},
		{"zero count", strings.Replace(minimal, `"count": 1`, `"count": 0`, 1), "count"},
		{"no included games", strings.Replace(minimal, `["magic"]`, `[]`, 1), "included_games"},
		{"no selectable stores", strings.Replace(minimal, `["CK"]`, `[]`, 1), "selectable_stores"},
		{"lowercase store", strings.Replace(minimal, `["CK"]`, `["ck"]`, 1), "selectable_stores"},
		{"duplicate store", strings.Replace(minimal, `["CK"]`, `["CK", "CK"]`, 1), "selectable_stores"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.json))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want containing %q", c.name, err, c.want)
		}
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
		{Interval{Interval: "year", Count: 1}, 20000, 240000},
		{Interval{Interval: "week", Count: 1}, 20000, 0},
		{Interval{Interval: "day", Count: 30}, 20000, 0},
	}
	for _, c := range cases {
		if got := c.iv.Amount(c.monthly); got != c.want {
			t.Errorf("%+v: got %d want %d", c.iv, got, c.want)
		}
	}
}
