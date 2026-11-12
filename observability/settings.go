package observability

import (
	"encoding/json"
	"slices"
	"sync"
)

// Setting is one stored reader setting the reports read.
type Setting struct {
	Name      string   // cookie or localStorage key; "Cookie.flag" for a packed flag
	Storage   string   // cookie, local, both
	Mirror    string   // for "both": the other copy's key, so a pair is one entry
	Path      string   // root, upload, arbit, reverse, global, sleepers, newspaper
	Kind      string   // flag, enum, number, list, blob, query
	Enum      []string // the values an enum setting takes
	Default   string   // the value a reader has before changing it
	Class     string   // preference, transient, admin
	Area      string   // the registry area it belongs to
	Fact      string   // the server name behind "requests that ran with it"
	FactScope string   // that name's scope, when it has one
	FactValue string   // that name's value, when it has one
}

// SettingPaths are the path scopes a setting can be read at, root first.
var SettingPaths = []string{"root", "upload", "arbit", "reverse", "global", "sleepers", "newspaper"}

// Each entry stays on one line: tests/settings-registry.test.js reads them with a regexp.
var settings = []Setting{
	// Root, preference.
	{Name: "SearchSellersList", Storage: "cookie", Path: "root", Kind: "list", Class: "preference", Area: "search"},
	{Name: "SearchVendorsList", Storage: "cookie", Path: "root", Kind: "list", Class: "preference", Area: "search"},
	{Name: "SearchDefaultSort", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"chrono", "hybrid", "alpha", "number", "retail", "buylist"}, Default: "chrono", Class: "preference", Area: "search", Fact: "search.sort_from", FactValue: "cookie"},
	{Name: "SearchListingPriority", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"stores", "prices", "credit", "market"}, Default: "prices", Class: "preference", Area: "search", Fact: "search.view", FactScope: "SearchListingPriority"},
	{Name: "SearchSellersPriority", Storage: "cookie", Path: "root", Kind: "blob", Class: "preference", Area: "search"},
	{Name: "SearchVendorsPriority", Storage: "cookie", Path: "root", Kind: "blob", Class: "preference", Area: "search"},
	{Name: "SearchBuylistSecondary", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"priceRatio", "creditPrice", "marketCredit"}, Default: "priceRatio", Class: "preference", Area: "search"},
	{Name: "SearchSealedContents", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"contents", "decklist", "variable"}, Default: "contents", Class: "preference", Area: "search", Fact: "search.view", FactScope: "SearchSealedContents"},
	{Name: "SearchMiscOpts.noSussy", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "noSussy"},
	{Name: "SearchMiscOpts.hidePrelPack", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "hidePrelPack"},
	{Name: "SearchMiscOpts.hidePromos", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "hidePromos"},
	{Name: "SearchMiscOpts.preferFlavor", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "preferFlavor"},
	{Name: "SearchMiscOpts.hideBLconds", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "hideBLconds"},
	{Name: "SearchMiscOpts.skipEmpty", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "skipEmpty"},
	{Name: "SearchMiscOpts.noUpsell", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "search", Fact: "search.misc", FactValue: "noUpsell"},
	{Name: "SearchDefaultTab", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"sellers", "buyers"}, Default: "sellers", Class: "preference", Area: "search", Fact: "search.view", FactScope: "SearchDefaultTab"},
	{Name: "SearchDefaultView", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"NM", "SP", "MP", "HP", "PO", "INDEX"}, Default: "NM", Class: "preference", Area: "search", Fact: "search.view", FactScope: "SearchDefaultView"},
	{Name: "MobileSearchLayout", Storage: "both", Mirror: "mtgban_search_layout", Path: "root", Kind: "enum", Enum: []string{"expanded", "compact"}, Default: "expanded", Class: "preference", Area: "search", Fact: "search.view", FactScope: "MobileSearchLayout"},
	{Name: "SearchStoreFactors", Storage: "both", Mirror: "mtgban_store_factors", Path: "root", Kind: "blob", Class: "preference", Area: "search", Fact: "search.store_factors"},
	{Name: "chartDateRange", Storage: "both", Mirror: "SearchChartRange", Path: "root", Kind: "number", Default: "180", Class: "preference", Area: "chart"},
	{Name: "chartMultiDateRange", Storage: "both", Mirror: "SearchChartMultiRange", Path: "root", Kind: "number", Default: "0", Class: "preference", Area: "chart"},
	{Name: "UploadCustomOpts.enabled", Storage: "cookie", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.custom_buylist"},
	{Name: "UploadCustomBuyer", Storage: "cookie", Path: "root", Kind: "blob", Default: "TCGLow", Class: "preference", Area: "upload"},
	{Name: "UploadCustomSealedBuyer", Storage: "cookie", Path: "root", Kind: "blob", Default: "TCGSealed", Class: "preference", Area: "upload"},
	{Name: "UploadCustomSinglesFallback", Storage: "cookie", Path: "root", Kind: "blob", Class: "preference", Area: "upload"},
	{Name: "UploadCustomSealedFallback", Storage: "cookie", Path: "root", Kind: "blob", Class: "preference", Area: "upload"},
	{Name: "UploadCustomMinPrice", Storage: "cookie", Path: "root", Kind: "number", Default: "7", Class: "preference", Area: "upload"},
	{Name: "UploadCustomRate", Storage: "cookie", Path: "root", Kind: "number", Default: "0.8", Class: "preference", Area: "upload"},
	{Name: "UploadCustomPercMax", Storage: "cookie", Path: "root", Kind: "number", Default: "100", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "custompercmax"},
	{Name: "ArbitFilters", Storage: "both", Mirror: "mtgban_arbit_filters", Path: "root", Kind: "query", Class: "preference", Area: "arbit"},
	{Name: "GlobalFilters", Storage: "both", Mirror: "mtgban_arbit_filters", Path: "root", Kind: "query", Class: "preference", Area: "arbit"},
	{Name: "MobileView", Storage: "cookie", Path: "root", Kind: "enum", Enum: []string{"true", "false"}, Class: "preference", Area: "site"},
	{Name: "MobileChartHidden", Storage: "cookie", Path: "root", Kind: "list", Class: "preference", Area: "chart"},
	{Name: "theme", Storage: "local", Path: "root", Kind: "enum", Enum: []string{"light", "dark", "system"}, Default: "system", Class: "preference", Area: "nav"},
	{Name: "chartReleasesLongRange", Storage: "local", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "chart"},
	{Name: "chartCheckpointTypes", Storage: "local", Path: "root", Kind: "list", Default: "ban,release,reprint", Class: "preference", Area: "chart"},
	{Name: "mtgban_nav_layout_v1", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "nav"},
	{Name: "mtgban_fav_sort", Storage: "local", Path: "root", Kind: "enum", Enum: []string{"chrono", "alpha", "sell", "buy", "manual"}, Default: "chrono", Class: "preference", Area: "favorites"},
	{Name: "mtgban_fav_sort_dir", Storage: "local", Path: "root", Kind: "enum", Enum: []string{"asc", "desc"}, Default: "desc", Class: "preference", Area: "favorites"},
	{Name: "mtgban_backpack_sort", Storage: "local", Path: "root", Kind: "blob", Default: `{"by":"added","dir":"desc"}`, Class: "preference", Area: "backpack"},
	{Name: "mtgban_backpack_tabs", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "backpack"},
	{Name: "mtgban_upload_presets", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "upload"},
	{Name: "mtgban_upload_sort", Storage: "local", Path: "root", Kind: "blob", Default: `{"results":"","opt":""}`, Class: "preference", Area: "upload"},
	{Name: "mtgban_arbit_presets", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "arbit"},
	{Name: "mtgban_arbit_pins", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "arbit"},
	{Name: "mtgban_news_filters", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "news"},
	{Name: "offline_mode", Storage: "local", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "offline"},
	{Name: "offline_img_editions", Storage: "local", Path: "root", Kind: "list", Class: "preference", Area: "offline"},
	{Name: "offline_stores", Storage: "local", Path: "root", Kind: "list", Class: "preference", Area: "offline"},
	{Name: "offline_editions", Storage: "local", Path: "root", Kind: "list", Class: "preference", Area: "offline"},
	{Name: "offline_live_search", Storage: "local", Path: "root", Kind: "enum", Enum: []string{"true", "false"}, Class: "preference", Area: "offline"},
	{Name: "offline_prefer", Storage: "local", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "offline"},
	{Name: "chartSpanGaps", Storage: "local", Path: "root", Kind: "flag", Default: "on", Class: "preference", Area: "chart"},
	{Name: "chartMultiRef", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "chart"},
	{Name: "BANChart", Storage: "local", Path: "root", Kind: "list", Class: "preference", Area: "chart"},
	{Name: "BANChartSealed", Storage: "local", Path: "root", Kind: "list", Class: "preference", Area: "chart"},
	{Name: "mtgban_saved_commands", Storage: "local", Path: "root", Kind: "blob", Class: "preference", Area: "palette"},
	{Name: "alertsSort", Storage: "local", Path: "root", Kind: "enum", Enum: []string{"created:asc", "created:desc", "name:asc", "name:desc", "now:asc", "now:desc", "fired:asc", "fired:desc", "status:asc", "status:desc", "side:asc", "side:desc"}, Default: "created:desc", Class: "preference", Area: "alerts"},
	{Name: "mtgban_backpack_empty_after", Storage: "local", Path: "root", Kind: "flag", Default: "off", Class: "preference", Area: "backpack"},

	// Upload page, preference.
	{Name: "UploadOptimizerOpts.lowval", Storage: "cookie", Path: "upload", Kind: "flag", Default: "on", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "lowval"},
	{Name: "UploadOptimizerOpts.highval", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "highval"},
	{Name: "UploadOptimizerOpts.lowvalabs", Storage: "cookie", Path: "upload", Kind: "flag", Default: "on", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "lowvalabs"},
	{Name: "UploadOptimizerOpts.highvalabs", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "highvalabs"},
	{Name: "UploadOptimizerOpts.minmargin", Storage: "cookie", Path: "upload", Kind: "flag", Default: "on", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "minmargin"},
	{Name: "UploadOptimizerOpts.nocond", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "nocond"},
	{Name: "UploadOptimizerOpts.noprice", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "noprice"},
	{Name: "UploadOptimizerOpts.customperc", Storage: "cookie", Path: "upload", Kind: "flag", Default: "on", Class: "preference", Area: "upload", Fact: "upload.option", FactValue: "customperc"},
	{Name: "UploadOptimizerOpts.unpack", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.unpack"},
	{Name: "UploadOptimizerOpts.noresults", Storage: "cookie", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload"},
	{Name: "UploadPercSpread", Storage: "cookie", Path: "upload", Kind: "number", Default: "60", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "percspread"},
	{Name: "UploadPercSpreadMax", Storage: "cookie", Path: "upload", Kind: "number", Default: "0", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "percspreadmax"},
	{Name: "UploadMinVal", Storage: "cookie", Path: "upload", Kind: "number", Default: "1", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "minval"},
	{Name: "UploadMaxVal", Storage: "cookie", Path: "upload", Kind: "number", Default: "0", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "maxval"},
	{Name: "UploadMargin", Storage: "cookie", Path: "upload", Kind: "number", Default: "10", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "margin"},
	{Name: "UploadMultiplier", Storage: "cookie", Path: "upload", Kind: "number", Default: "1", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "multiplier"},
	{Name: "UploadMaxQty", Storage: "cookie", Path: "upload", Kind: "number", Default: "0", Class: "preference", Area: "upload", Fact: "upload.value_set", FactValue: "maxqty"},
	{Name: "UploadSorting", Storage: "cookie", Path: "upload", Kind: "enum", Enum: []string{"setchrono", "setalpha", "alphabetical", "highprice", "highspread", "profitability"}, Class: "preference", Area: "upload", Fact: "upload.sorting"},
	{Name: "UploadPriceSource", Storage: "cookie", Path: "upload", Kind: "enum", Enum: []string{"credit", "marketCredit"}, Class: "preference", Area: "upload", Fact: "upload.price_source"},
	{Name: "UploadAltPrice", Storage: "cookie", Path: "upload", Kind: "blob", Default: "TCGLow", Class: "preference", Area: "upload"},
	{Name: "UploadTiebreak", Storage: "cookie", Path: "upload", Kind: "enum", Enum: []string{"credit", "marketCredit", "consolidate", "custom"}, Class: "preference", Area: "upload"},
	{Name: "UploadTiebreakOrder", Storage: "cookie", Path: "upload", Kind: "list", Class: "preference", Area: "upload"},
	// The local copy shares the name; an absent cookie reads as retail even when it says buylist.
	{Name: "uploadMode", Storage: "both", Path: "upload", Kind: "flag", Default: "off", Class: "preference", Area: "upload", Fact: "upload.mode", FactValue: "buylist"},

	// Other pages, preference.
	{Name: "ArbitVendorsList", Storage: "cookie", Path: "arbit", Kind: "list", Class: "preference", Area: "arbit", Fact: "arbit.excluded_vendors", FactScope: "arbit"},
	{Name: "ReverseVendorsList", Storage: "cookie", Path: "reverse", Kind: "list", Class: "preference", Area: "arbit", Fact: "arbit.excluded_vendors", FactScope: "reverse"},
	{Name: "GlobalVendorsList", Storage: "cookie", Path: "global", Kind: "list", Class: "preference", Area: "arbit", Fact: "arbit.excluded_vendors", FactScope: "global"},
	{Name: "SleepersSellersList", Storage: "cookie", Path: "sleepers", Kind: "list", Class: "preference", Area: "sleepers", Fact: "sleepers.lists", FactValue: "sellers"},
	{Name: "SleepersVendorsList", Storage: "cookie", Path: "sleepers", Kind: "list", Class: "preference", Area: "sleepers", Fact: "sleepers.lists", FactValue: "vendors"},
	{Name: "SleepersEditionList", Storage: "cookie", Path: "sleepers", Kind: "list", Class: "preference", Area: "sleepers", Fact: "sleepers.lists", FactValue: "editions"},
	{Name: "NewspaperList", Storage: "cookie", Path: "newspaper", Kind: "list", Class: "preference", Area: "news", Fact: "news.editions_hidden"},
	{Name: "BanNewspaperPref", Storage: "cookie", Path: "newspaper", Kind: "flag", Default: "off", Class: "preference", Area: "news", Fact: "news.three_day", FactValue: "on"},

	// Transient and admin: never snapshotted, never served.
	{Name: "ArbitFiltersOpen", Storage: "cookie", Path: "root", Kind: "flag", Class: "transient"},
	{Name: "mtgban_popular_collapsed", Storage: "local", Path: "root", Kind: "flag", Class: "transient"},
	{Name: "cartPromptSkip", Storage: "local", Path: "root", Kind: "flag", Class: "transient"},
	{Name: "mtgban_nav_hint_dismissed", Storage: "local", Path: "root", Kind: "flag", Class: "transient"},
	{Name: "uploadTab", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	{Name: "uploadSourceMode", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	{Name: "setsExpanded", Storage: "local", Path: "root", Kind: "flag", Class: "transient"},
	{Name: "mtgban_backpack_active", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	{Name: "mtgban_metrics_queue", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	{Name: "mtgban_metrics_snap", Storage: "local", Path: "root", Kind: "blob", Class: "transient"},
	// Written on every upload, changed or not: a snapshot cannot tell them from their default.
	{Name: "enabledSellers", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "enabledVendors", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "enabledSealedSellers", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "enabledSealedVendors", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "enabledIndexes", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "enabledSealedIndexes", Storage: "cookie", Path: "upload", Kind: "list", Class: "transient"},
	{Name: "gdocURL", Storage: "cookie", Path: "upload", Kind: "blob", Class: "transient"},
	{Name: "adminFixMode", Storage: "local", Path: "root", Kind: "flag", Class: "admin"},
}

// Stored keys that hold data or bookkeeping, not a choice; one per line for the bun test.
var notSettings = []string{
	"mtgban_favorites",        // the reader's list
	"mtgban_recent_searches",  // the reader's list
	"mtgban_backpack",         // the reader's list
	"mtgban_userstate_dirty",  // sync bookkeeping flag
	"mtgban_userstate_synced", // sync bookkeeping time
	"mtgban_userstate_fp",     // sync bookkeeping fingerprint
	"mtgban_userstate_clock",  // sync bookkeeping clock
	"offline_available",       // server flag left
	"chartAddPending",         // chart modal handoff
	"uploadTextArea",          // unsent upload draft
	"manapool-cart",           // another site's cart
}

var settingByName = func() map[string]Setting {
	m := make(map[string]Setting, len(settings))
	for _, s := range settings {
		m[s.Name] = s
	}
	return m
}()

// Settings returns every registered setting, in table order.
func Settings() []Setting {
	return slices.Clone(settings)
}

// LookupSetting returns the registered setting.
func LookupSetting(name string) (Setting, bool) {
	s, ok := settingByName[name]
	return s, ok
}

// IsSetting reports whether name is a preference-class entry.
func IsSetting(name string) bool {
	s, ok := settingByName[name]
	return ok && s.Class == "preference"
}

// SettingValue reports whether a snapshot may say value about the setting.
func SettingValue(name, value string) bool {
	s, ok := settingByName[name]
	if !ok || s.Class != "preference" {
		return false
	}
	switch s.Kind {
	case "flag":
		return (value == "on" || value == "off") && value != s.Default
	case "enum":
		return value != s.Default && slices.Contains(s.Enum, value)
	}
	return value == "set"
}

// NotSettings returns the stored keys that are not settings.
func NotSettings() []string {
	return slices.Clone(notSettings)
}

type servedSetting struct {
	Name    string   `json:"name"`
	Storage string   `json:"storage"`
	Path    string   `json:"path"`
	Kind    string   `json:"kind"`
	Enum    []string `json:"enum,omitempty"`
	Default string   `json:"default"`
}

var settingsJSON = sync.OnceValue(func() []byte {
	out := struct {
		Settings []servedSetting `json:"settings"`
	}{}
	for _, s := range settings {
		if s.Class != "preference" {
			continue
		}
		out.Settings = append(out.Settings, servedSetting{Name: s.Name, Storage: s.Storage, Path: s.Path, Kind: s.Kind, Enum: s.Enum, Default: s.Default})
	}
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return b
})

// SettingsJSON returns the preference entries as the script reads them, marshalled once.
func SettingsJSON() []byte {
	return slices.Clone(settingsJSON())
}
