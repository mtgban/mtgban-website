package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// searchSettingsKeys lists every loaded seller and vendor the site shows,
// in display order.
func searchSettingsKeys(p *prices) (sellers, vendors []string) {
	shown := func(info mtgban.ScraperInfo) bool {
		return !Config().apiOnly(info.Shorthand)
	}
	return sortKeysByScraperName(p, p.filterSellers(shown)), sortKeysByScraperName(p, p.filterVendors(shown))
}

// arbitBlockedVendors is the reader's ArbitDisabledVendors grant; NONE, or
// no grant, blocks nothing. The stores only the price API serves are blocked
// whatever the grant says.
func arbitBlockedVendors(sig string) []string {
	var blocked []string
	blocklistVendorsOpt := GetParamFromSig(sig, "ArbitDisabledVendors")
	switch blocklistVendorsOpt {
	case "", "NONE":
	default:
		blocked = strings.Split(blocklistVendorsOpt, ",")
	}
	return append(blocked, Config().Stores.APIOnlyStores...)
}

// arbitVendorKeys is the Arbitrage or Reverse vendor grid, in display order.
// In reverse mode the vendor column is a seller; same blocklist.
func arbitVendorKeys(p *prices, blocklistVendors []string, reverse bool) []string {
	notBlocked := func(info mtgban.ScraperInfo) bool {
		return !slices.Contains(blocklistVendors, info.Shorthand)
	}
	if reverse {
		return sortKeysByScraperName(p, p.filterSellers(notBlocked))
	}
	return sortKeysByScraperName(p, p.filterVendors(notBlocked))
}

// globalProbeBlocklist is every seller outside the Global probe list, and
// every one only the price API serves.
func globalProbeBlocklist(p *prices) []string {
	return p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return !slices.Contains(Config().Stores.GlobalProbeList, info.Shorthand) ||
			Config().apiOnly(info.Shorthand)
	})
}

// globalVendorKeys is the Global vendor grid, in display order: the sellers
// Global compares against, which its GlobalVendorsList cookie hides, less
// the unactionable sealed ones it never compares against.
func globalVendorKeys(p *prices, blocklistVendors []string) []string {
	return sortKeysByScraperName(p, p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return comparableSeller(info) &&
			!slices.Contains(blocklistVendors, info.Shorthand) && !Config().apiOnly(info.Shorthand)
	}))
}

// sleepBlocklists is the default blocklist plus the Sleepers one.
func sleepBlocklists(sig string) (retail, buylist []string) {
	retail, buylist = getDefaultBlocklists(sig)
	if Config().Stores.SleepersBlockList != nil {
		retail = append(retail, Config().Stores.SleepersBlockList...)
		buylist = append(buylist, Config().Stores.SleepersBlockList...)
	}
	return retail, buylist
}

// sleepModalKeys is the Sleepers tab's store grids, before the reader's own
// hide cookie is applied, so a hidden store still shows, ticked.
func sleepModalKeys(p *prices, blocklistRetail, blocklistBuylist []string) (sellers, vendors []string) {
	sellers = p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return info.CountryFlag == "" && !info.SealedMode && !info.MetadataOnly &&
			!slices.Contains(blocklistRetail, info.Shorthand)
	})
	vendors = p.filterVendors(func(info mtgban.ScraperInfo) bool {
		return info.CountryFlag == "" && !info.SealedMode && !info.MetadataOnly &&
			!slices.Contains(blocklistBuylist, info.Shorthand)
	})
	return sellers, vendors
}

// uploadStoreLists is every store an upload may be priced against, by kind.
// Sellers skip MetadataOnly entries; vendors do not.
func uploadStoreLists(p *prices, sig string) (singlesSellers, sealedSellers, singlesVendors, sealedVendors []string) {
	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)
	singlesSellers = p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && !info.SealedMode &&
			!slices.Contains(blocklistRetail, info.Shorthand)
	})
	sealedSellers = p.filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && info.SealedMode &&
			!slices.Contains(Config().Stores.UploadSealedBlockList, info.Shorthand) &&
			!Config().apiOnly(info.Shorthand)
	})
	singlesVendors = p.filterVendors(func(info mtgban.ScraperInfo) bool {
		return !info.SealedMode &&
			!slices.Contains(blocklistBuylist, info.Shorthand)
	})
	sealedVendors = p.filterVendors(func(info mtgban.ScraperInfo) bool {
		return info.SealedMode &&
			!slices.Contains(Config().Stores.UploadSealedBlockList, info.Shorthand) &&
			!Config().apiOnly(info.Shorthand)
	})
	return singlesSellers, sealedSellers, singlesVendors, sealedVendors
}

// uploadModalKeys is what the Upload tab's selects list and whether the
// custom buylist rule is open to the reader.
type uploadModalKeys struct {
	AltKeys          []string
	SellerKeys       []string
	SealedSellerKeys []string
	CanUploadCustom  bool
	VendorKeys       []string
	SealedVendorKeys []string
}

// uploadSettingsKeys reads the Upload tab's data for a verified sig, with
// the custom buylist gate readUploadSettings applies.
func uploadSettingsKeys(p *prices, sig string) uploadModalKeys {
	canUploadCustom, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadCustom"))
	canUploadCustom = canUploadCustom || (DevMode && !SigCheck)
	singlesSellers, sealedSellers, singlesVendors, sealedVendors := uploadStoreLists(p, sig)
	return uploadModalKeys{
		AltKeys:          UploadIndexComparePriceList,
		SellerKeys:       singlesSellers,
		SealedSellerKeys: sealedSellers,
		CanUploadCustom:  canUploadCustom,
		VendorKeys:       singlesVendors,
		SealedVendorKeys: sealedVendors,
	}
}

var settingsTabNames = map[string]string{
	"search":  "Search",
	"upload":  "Upload",
	"arbit":   "Arbitrage",
	"global":  "Global",
	"reverse": "Reverse",
	"news":    "Newspaper",
	"sleep":   "Sleepers",
	"offline": "Offline",
}

// settingsTabs is the rail for a reader whose navbar is nav: one tab per
// SettingsTab it carries, in nav order, then Offline with the grant.
func settingsTabs(nav []NavElem, offlineAllowed bool) []string {
	var tabs []string
	for _, elem := range nav {
		if elem.SettingsTab != "" && !slices.Contains(tabs, elem.SettingsTab) {
			tabs = append(tabs, elem.SettingsTab)
		}
	}
	if offlineAllowed {
		tabs = append(tabs, "offline")
	}
	return tabs
}

// settingsTabPaths is the path of the page each tab's settings belong to,
// the first page in nav that opens the tab, for the cookies it keeps there.
func settingsTabPaths(nav []NavElem) map[string]string {
	paths := map[string]string{}
	for _, elem := range nav {
		if elem.SettingsTab != "" && paths[elem.SettingsTab] == "" {
			paths[elem.SettingsTab] = elem.Link
		}
	}
	return paths
}

// settingsModalVars is everything the modal body renders from.
type settingsModalVars struct {
	Hash     string
	Tabs     []string
	TabNames map[string]string
	TabPaths map[string]string

	// search
	SellerKeys []string
	VendorKeys []string
	// StoreNames names every store the tabs list by shorthand, and
	// StoreFactorOptions is the search tab's store-factor editor data
	StoreNames         map[string]string
	StoreFactorOptions string
	// Which of SellerKeys and VendorKeys trade sealed product
	SealedStores  map[string]bool
	ListingLocked bool

	// upload
	UploadAltKeys          []string
	UploadSellerKeys       []string
	UploadSealedSellerKeys []string
	CanUploadCustom        bool
	UploadVendorKeys       []string
	UploadSealedVendorKeys []string

	// arbit, global, reverse
	ArbitVendorKeys   []string
	GlobalVendorKeys  []string
	ReverseVendorKeys []string

	// sleep
	SleepSellerKeys []string
	SleepVendorKeys []string

	// news, sleep and offline images share one editions list
	EditionsCategories []string
	EditionsByCategory map[string][]EditionEntry
	OfflineModeAllowed bool
}

// settingsBodyKey is the body's entry in TemplateCache.
const settingsBodyKey = "settings/body.html"

// settingsBodyFiles is the body's template set: the rail, one file per
// tab, and the partials the tabs call.
func settingsBodyFiles() (baseName string, files []string) {
	return "body.html", []string{
		"templates/settings/body.html",
		"templates/settings/search.html",
		"templates/settings/upload.html",
		"templates/settings/arbit.html",
		"templates/settings/news.html",
		"templates/settings/sleep.html",
		"templates/settings/offline.html",
		"templates/partials/settings-stores-grouped.html",
		"templates/partials/editions-picker.html",
		"templates/partials/set-symbol.html",
	}
}

// settingsModalData builds the body for the reader behind r: the tabs
// their navbar earns, and each tab's lists from the code its page runs.
func settingsModalData(s *site, r *http.Request) settingsModalVars {
	ds := s.datastore()
	p := s.prices()
	// Behind noSigning, so only a sig this host wrote earns tabs
	sig := verifiedSignature(r)
	nav := genPageNav(s, r, "", sig).Nav
	_, offlineAllowed := offlineModeAllowed(r)

	v := settingsModalVars{
		Hash:               assetHash(),
		Tabs:               settingsTabs(nav, offlineAllowed),
		TabNames:           settingsTabNames,
		TabPaths:           settingsTabPaths(nav),
		ListingLocked:      sig == "" && SigCheck,
		OfflineModeAllowed: offlineAllowed,
		EditionsCategories: ds.editions.AllEditionsCategoriesSorted,
		EditionsByCategory: ds.editions.AllEditionsByCategory,
	}
	v.SellerKeys, v.VendorKeys = searchSettingsKeys(p)
	v.SealedStores = p.sealedStores()
	v.StoreNames = p.storeNames()
	v.StoreFactorOptions = storeFactorOptions(p, v.SellerKeys, v.VendorKeys)

	up := uploadSettingsKeys(p, sig)
	v.UploadAltKeys = up.AltKeys
	v.UploadSellerKeys = up.SellerKeys
	v.UploadSealedSellerKeys = up.SealedSellerKeys
	v.CanUploadCustom = up.CanUploadCustom
	v.UploadVendorKeys = up.VendorKeys
	v.UploadSealedVendorKeys = up.SealedVendorKeys

	v.ArbitVendorKeys = arbitVendorKeys(p, arbitBlockedVendors(sig), false)
	v.GlobalVendorKeys = globalVendorKeys(p, globalProbeBlocklist(p))
	v.ReverseVendorKeys = arbitVendorKeys(p, arbitBlockedVendors(sig), true)

	retail, buylist := sleepBlocklists(sig)
	v.SleepSellerKeys, v.SleepVendorKeys = sleepModalKeys(p, retail, buylist)

	return v
}

// SettingsModal serves the settings modal's body for the reader behind
// the request. The body varies by tier, so it is never cached.
func (s *site) SettingsModal(w http.ResponseWriter, r *http.Request) {
	v := settingsModalData(s, r)

	baseName, files := settingsBodyFiles()
	t := TemplateCache[settingsBodyKey]
	if DevMode || t == nil {
		var err error
		t, err = tmplparse.ParseFiles(baseName, files, funcMap)
		if err != nil {
			log.Print("settings body parsing error: ", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// Rendered whole first, so an error is a 500 and not half a body
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, baseName, v); err != nil {
		log.Print("settings body executing error: ", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Write(buf.Bytes())
}

// SettingsValues answers the settings modal, opened on another page, with
// the named cookies this page keeps at its own path: only a request under
// that path carries them. Root cookies, the signature among them, are left
// out, since every page reads those itself.
func SettingsValues(w http.ResponseWriter, r *http.Request) {
	values := map[string]string{}
	for _, name := range r.URL.Query()["name"] {
		if cookiePath(r, name) != "/" {
			values[name] = readCookie(r, name)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(values)
}
