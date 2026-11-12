package observability

import (
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The type is the roadmap's; every entry has a name.
func TestSettingHasTheRoadmapsFields(t *testing.T) {
	s := Setting{Name: "UploadSorting", Storage: "cookie", Mirror: "", Path: "upload", Kind: "enum", Enum: []string{"a"},
		Default: "a", Class: "preference", Area: "upload", Fact: "upload.sorting", FactScope: "", FactValue: ""}
	if s.Name == "" || s.Fact == "" {
		t.Fatal("a setting keeps what it is given")
	}
	for _, e := range Settings() {
		if e.Name == "" {
			t.Error("a setting with no name")
		}
	}
}

func TestSettingsAreWellFormed(t *testing.T) {
	kinds := []string{"flag", "enum", "number", "list", "blob", "query"}
	printable := regexp.MustCompile(`^[\x21-\x7e]+$`)
	seen := map[string]bool{}
	for _, s := range Settings() {
		if seen[s.Name] {
			t.Errorf("%s registered twice", s.Name)
		}
		seen[s.Name] = true
		// A name travels as a scope and an enum value as a value: 40 characters, printable.
		for _, text := range append([]string{s.Name}, s.Enum...) {
			if len(text) > 40 || !printable.MatchString(text) {
				t.Errorf("%s: %q is over 40 characters or not printable ASCII", s.Name, text)
			}
		}
		if !slices.Contains([]string{"cookie", "local", "both"}, s.Storage) {
			t.Errorf("%s: storage %q", s.Name, s.Storage)
		}
		if !slices.Contains(SettingPaths, s.Path) {
			t.Errorf("%s: path %q", s.Name, s.Path)
		}
		if !slices.Contains(kinds, s.Kind) {
			t.Errorf("%s: kind %q", s.Name, s.Kind)
		}
		if !slices.Contains([]string{"preference", "transient", "admin"}, s.Class) {
			t.Errorf("%s: class %q", s.Name, s.Class)
		}
		if s.Storage == "local" && s.Path != "root" {
			t.Errorf("%s: localStorage is readable everywhere, so its path is root", s.Name)
		}
		if (s.Kind == "enum") != (len(s.Enum) > 0) {
			t.Errorf("%s: an enum, and only an enum, lists its values", s.Name)
		}
		if s.Kind == "enum" && s.Default != "" && !slices.Contains(s.Enum, s.Default) {
			t.Errorf("%s: default %q is not one of its values", s.Name, s.Default)
		}
		if s.Mirror != "" && s.Storage != "both" {
			t.Errorf("%s: only a both entry has a mirror", s.Name)
		}
		if strings.Contains(s.Name, ".") && (s.Kind != "flag" || s.Storage != "cookie") {
			t.Errorf("%s: a dotted name is a flag packed in a cookie", s.Name)
		}
		if s.Class != "preference" {
			continue
		}
		if s.Area == "" {
			t.Errorf("%s has no area", s.Name)
		}
		if s.Kind == "flag" && s.Default != "on" && s.Default != "off" {
			t.Errorf("%s: a flag defaults to on or off, got %q", s.Name, s.Default)
		}
		if s.Kind == "number" {
			if _, err := strconv.ParseFloat(s.Default, 64); err != nil {
				t.Errorf("%s: a number needs a numeric default, got %q", s.Name, s.Default)
			}
		}
	}
}

func TestSettingsCounts(t *testing.T) {
	byClass, byPath := map[string]int{}, map[string]int{}
	for _, s := range Settings() {
		byClass[s.Class]++
		if s.Class == "preference" {
			byPath[s.Path]++
		}
	}
	if byClass["preference"] != 90 || byClass["transient"] != 17 || byClass["admin"] != 1 {
		t.Errorf("classes = %v, want 90 preference, 17 transient, 1 admin", byClass)
	}
	want := map[string]int{"root": 59, "upload": 23, "arbit": 1, "reverse": 1, "global": 1, "sleepers": 3, "newspaper": 2}
	if !maps.Equal(byPath, want) {
		t.Errorf("preference entries by path = %v, want %v", byPath, want)
	}
}

// One page's snapshot is root plus that page's scope plus a reader row each.
// The script sends 50 entries a post, so under 90 keeps a snapshot to two
// posts with room for the load's first clicks.
func TestSnapshotStaysUnderNinety(t *testing.T) {
	n := map[string]int{}
	for _, s := range Settings() {
		if s.Class == "preference" {
			n[s.Path]++
		}
	}
	for _, p := range SettingPaths[1:] {
		if total := n["root"] + n[p] + 2; total > 90 {
			t.Errorf("a snapshot on %s can reach %d entries, over 90", p, total)
		}
	}
}

func TestSettingEntries(t *testing.T) {
	for _, c := range []struct{ name, storage, path, kind, def, class, mirror string }{
		{"SearchDefaultSort", "cookie", "root", "enum", "chrono", "preference", ""},
		{"SearchListingPriority", "cookie", "root", "enum", "prices", "preference", ""},
		{"SearchMiscOpts.noSussy", "cookie", "root", "flag", "off", "preference", ""},
		{"UploadOptimizerOpts.lowval", "cookie", "upload", "flag", "on", "preference", ""},
		{"UploadOptimizerOpts.highval", "cookie", "upload", "flag", "off", "preference", ""},
		{"UploadCustomPercMax", "cookie", "root", "number", "100", "preference", ""},
		{"UploadMargin", "cookie", "upload", "number", "10", "preference", ""},
		{"chartDateRange", "both", "root", "number", "180", "preference", "SearchChartRange"},
		{"chartMultiDateRange", "both", "root", "number", "0", "preference", "SearchChartMultiRange"},
		{"MobileSearchLayout", "both", "root", "enum", "expanded", "preference", "mtgban_search_layout"},
		{"ArbitFilters", "both", "root", "query", "", "preference", "mtgban_arbit_filters"},
		{"uploadMode", "both", "upload", "flag", "off", "preference", ""},
		{"gdocURL", "cookie", "upload", "blob", "", "transient", ""},
		{"BanNewspaperPref", "cookie", "newspaper", "flag", "off", "preference", ""},
		{"offline_live_search", "local", "root", "enum", "", "preference", ""},
		{"chartSpanGaps", "local", "root", "flag", "on", "preference", ""},
		{"ArbitFiltersOpen", "cookie", "root", "flag", "", "transient", ""},
		{"mtgban_metrics_queue", "local", "root", "blob", "", "transient", ""},
		{"mtgban_metrics_snap", "local", "root", "blob", "", "transient", ""},
		{"adminFixMode", "local", "root", "flag", "", "admin", ""},
	} {
		s, ok := LookupSetting(c.name)
		if !ok {
			t.Errorf("%s is not registered", c.name)
			continue
		}
		if s.Storage != c.storage || s.Path != c.path || s.Kind != c.kind || s.Default != c.def || s.Class != c.class || s.Mirror != c.mirror {
			t.Errorf("%s = %+v", c.name, s)
		}
	}
	sort, _ := LookupSetting("SearchDefaultSort")
	if !slices.Equal(sort.Enum, []string{"chrono", "hybrid", "alpha", "number", "retail", "buylist"}) {
		t.Errorf("SearchDefaultSort values = %v", sort.Enum)
	}
	for _, s := range Settings() {
		if slices.Contains(NotSettings(), s.Name) {
			t.Errorf("%s is both a setting and listed as not one", s.Name)
		}
	}
}

// The 54 settings the modal and the mobile drawer can change (phase 2d's
// ui.settings.change scopes) are preference entries under exactly these names.
func TestSettingsCoverTheModal(t *testing.T) {
	names := []string{
		"SearchSellersList", "SearchVendorsList", "SearchDefaultSort", "SearchListingPriority",
		"SearchSellersPriority", "SearchVendorsPriority", "SearchBuylistSecondary", "SearchSealedContents",
		"SearchStoreFactors", "SearchDefaultTab", "SearchDefaultView", "MobileSearchLayout",
		"UploadCustomOpts.enabled",
		"UploadPercSpread", "UploadPercSpreadMax", "UploadMinVal", "UploadMaxVal", "UploadMargin",
		"UploadCustomPercMax", "UploadMultiplier", "UploadMaxQty", "UploadSorting", "UploadPriceSource", "UploadTiebreak", "UploadTiebreakOrder",
		"UploadAltPrice", "UploadCustomBuyer", "UploadCustomSealedBuyer", "UploadCustomSinglesFallback",
		"UploadCustomSealedFallback", "UploadCustomMinPrice", "UploadCustomRate",
		"ArbitVendorsList", "GlobalVendorsList", "ReverseVendorsList",
		"SleepersSellersList", "SleepersVendorsList", "SleepersEditionList", "NewspaperList",
	}
	for _, f := range []string{"noSussy", "hidePrelPack", "hidePromos", "preferFlavor", "hideBLconds", "skipEmpty", "noUpsell"} {
		names = append(names, "SearchMiscOpts."+f)
	}
	for _, f := range []string{"lowval", "highval", "lowvalabs", "highvalabs", "minmargin", "unpack", "nocond", "noprice", "customperc", "noresults"} {
		names = append(names, "UploadOptimizerOpts."+f)
	}
	if len(names) != 56 {
		t.Fatalf("%d names, want 56", len(names))
	}
	for _, n := range names {
		if !IsSetting(n) {
			t.Errorf("%s is not a preference entry", n)
		}
	}
}

func TestSettingValue(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"UploadSorting", "highprice", true},
		{"UploadSorting", "set", false},
		{"UploadSorting", "NM", false},
		{"SearchMiscOpts.noSussy", "on", true},
		{"UploadOptimizerOpts.lowval", "off", true},
		{"SearchMiscOpts.noSussy", "set", false},
		{"SearchSellersPriority", "set", true},
		{"gdocURL", "set", false}, // the server writes it on every upload
		{"gdocURL", "https://docs.google.com/spreadsheets/d/abc", false},
		{"UploadMaxQty", "4", false},
		{"ArbitFilters", "set", true},
		{"UploadSorting", "", false},          // a value is required
		{"uploadTab", "set", false},           // transient
		{"mtgban_metrics_snap", "set", false}, // the script's own mark is transient
		{"adminFixMode", "on", false},         // admin
		{"NoSuchSetting", "on", false},
		{"SearchMiscOpts", "on", false}, // the cookie is not an entry, its flags are
		{"chartSpanGaps", "on", false},  // a default is not a snapshot value
		{"chartSpanGaps", "off", true},
		{"SearchMiscOpts.noSussy", "off", false},
		{"SearchDefaultSort", "chrono", false},
		{"SearchDefaultSort", "alpha", true},
		{"MobileView", "true", true}, // no default
	} {
		if got := SettingValue(c.name, c.value); got != c.want {
			t.Errorf("SettingValue(%q, %q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
	if IsSetting("uploadTab") || !IsSetting("UploadSorting") {
		t.Error("IsSetting is true for preference entries only")
	}
}

// The upload writes these on every run, so they are registered but never snapshotted.
func TestServerWrittenUploadCookiesAreNotSnapshotted(t *testing.T) {
	raw := string(SettingsJSON())
	for _, name := range []string{"enabledSellers", "enabledVendors", "enabledSealedSellers", "enabledSealedVendors", "enabledIndexes", "enabledSealedIndexes", "gdocURL"} {
		if _, ok := LookupSetting(name); !ok {
			t.Errorf("%s is not registered", name)
		}
		if IsSetting(name) {
			t.Errorf("%s is a preference entry", name)
		}
		if strings.Contains(raw, `"name":"`+name+`"`) {
			t.Errorf("the served registry carries %s", name)
		}
	}
}

func TestSettingsJSONServesPreferencesOnly(t *testing.T) {
	var got struct {
		Settings []struct {
			Name, Storage, Path, Kind, Default string
			Enum                               []string
		}
	}
	if err := json.Unmarshal(SettingsJSON(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Settings) != 90 {
		t.Fatalf("served %d entries, want 90", len(got.Settings))
	}
	raw := string(SettingsJSON())
	for _, leak := range []string{"uploadTab", "adminFixMode", "mtgban_metrics_snap", "mtgban_metrics_queue", "mtgban_search_layout", "upload.value_set", "\"class\"", "\"area\""} {
		if strings.Contains(raw, leak) {
			t.Errorf("the served registry carries %s", leak)
		}
	}
}

// The bun drift test reads this file with the same expression.
func TestSettingsSourceIsParseable(t *testing.T) {
	src, err := os.ReadFile("settings.go")
	if err != nil {
		t.Fatal(err)
	}
	entries := regexp.MustCompile(`(?m)^\s*\{Name: "([^"]+)"`).FindAllSubmatch(src, -1)
	if len(entries) != len(Settings()) {
		t.Errorf("%d entries match the one-line form, the registry has %d", len(entries), len(Settings()))
	}
	block := regexp.MustCompile(`(?s)var notSettings = \[\]string\{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("notSettings is not a one-per-line string slice")
	}
	if n := len(regexp.MustCompile(`"([^"]+)"`).FindAll(block[1], -1)); n != len(NotSettings()) {
		t.Errorf("%d strings in the notSettings literal, %d in NotSettings()", n, len(NotSettings()))
	}
}

// A setting's review is filed under its Area, so each is an area some name has.
func TestSettingAreasAreRegistryAreas(t *testing.T) {
	areas := map[string]bool{}
	for _, n := range All() {
		areas[n.Area] = true
	}
	for _, s := range Settings() {
		if s.Area != "" && !areas[s.Area] {
			t.Errorf("%s: area %q is no registry name's area", s.Name, s.Area)
		}
	}
}
