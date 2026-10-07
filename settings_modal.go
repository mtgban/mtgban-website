package main

import (
	"bytes"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// searchSettingsKeys lists every loaded seller and vendor, in display order.
func searchSettingsKeys() (sellers, vendors []string) {
	for _, seller := range GetSellers() {
		sellers = append(sellers, seller.Info().Shorthand)
	}
	for _, vendor := range GetVendors() {
		vendors = append(vendors, vendor.Info().Shorthand)
	}
	return sortKeysByScraperName(sellers), sortKeysByScraperName(vendors)
}

// arbitBlockedVendors is the reader's ArbitDisabledVendors grant, or the
// config block list when the grant is absent; NONE clears it.
func arbitBlockedVendors(sig string) []string {
	blocklistVendorsOpt := GetParamFromSig(sig, "ArbitDisabledVendors")
	if blocklistVendorsOpt == "" {
		// Clipped: callers append the cookie's vendors to it
		return slices.Clip(Config().ArbitBlockVendors)
	}
	if blocklistVendorsOpt == "NONE" {
		return nil
	}
	return strings.Split(blocklistVendorsOpt, ",")
}

// arbitVendorKeys is the Arbitrage or Reverse vendor grid, in display order.
// In reverse mode the vendor column is a seller; same blocklist.
func arbitVendorKeys(blocklistVendors []string, reverse bool) []string {
	notBlocked := func(info mtgban.ScraperInfo) bool {
		return !slices.Contains(blocklistVendors, info.Shorthand)
	}
	if reverse {
		return sortKeysByScraperName(filterSellers(notBlocked))
	}
	return sortKeysByScraperName(filterVendors(notBlocked))
}

// globalProbeBlocklist is every seller outside the Global probe list.
func globalProbeBlocklist() []string {
	return filterSellers(func(info mtgban.ScraperInfo) bool {
		return !slices.Contains(Config().GlobalProbeList, info.Shorthand)
	})
}

// globalVendorKeys is the Global vendor grid, in display order.
func globalVendorKeys(blocklistVendors []string) []string {
	return sortKeysByScraperName(filterVendors(func(info mtgban.ScraperInfo) bool {
		return !slices.Contains(blocklistVendors, info.Shorthand)
	}))
}

// sleepBlocklists is the default blocklist plus the Sleepers one.
func sleepBlocklists(sig string) (retail, buylist []string) {
	retail, buylist = getDefaultBlocklists(sig)
	if Config().SleepersBlockList != nil {
		retail = append(retail, Config().SleepersBlockList...)
		buylist = append(buylist, Config().SleepersBlockList...)
	}
	return retail, buylist
}

// sleepModalKeys is the Sleepers tab's store grids, before the reader's own
// hide cookie is applied, so a hidden store still shows, ticked.
func sleepModalKeys(blocklistRetail, blocklistBuylist []string) (sellers, vendors []string) {
	sellers = filterSellers(func(info mtgban.ScraperInfo) bool {
		return info.CountryFlag == "" && !info.SealedMode && !info.MetadataOnly &&
			!slices.Contains(blocklistRetail, info.Shorthand)
	})
	vendors = filterVendors(func(info mtgban.ScraperInfo) bool {
		return info.CountryFlag == "" && !info.SealedMode && !info.MetadataOnly &&
			!slices.Contains(blocklistBuylist, info.Shorthand)
	})
	return sellers, vendors
}

// uploadStoreLists is every store an upload may be priced against, by kind.
// Sellers skip MetadataOnly entries; vendors do not.
func uploadStoreLists(sig string) (singlesSellers, sealedSellers, singlesVendors, sealedVendors []string) {
	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)
	singlesSellers = filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && !info.SealedMode &&
			!slices.Contains(blocklistRetail, info.Shorthand)
	})
	sealedSellers = filterSellers(func(info mtgban.ScraperInfo) bool {
		return !info.MetadataOnly && info.SealedMode &&
			!slices.Contains(Config().UploadSealedBlockList, info.Shorthand)
	})
	singlesVendors = filterVendors(func(info mtgban.ScraperInfo) bool {
		return !info.SealedMode &&
			!slices.Contains(blocklistBuylist, info.Shorthand)
	})
	sealedVendors = filterVendors(func(info mtgban.ScraperInfo) bool {
		return info.SealedMode &&
			!slices.Contains(Config().UploadSealedBlockList, info.Shorthand)
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
}

// uploadSettingsKeys reads the Upload tab's data for a verified sig, with
// the custom buylist gate readUploadSettings applies.
func uploadSettingsKeys(sig string) uploadModalKeys {
	canUploadCustom, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadCustom"))
	canUploadCustom = canUploadCustom || (DevMode && !SigCheck)
	singlesSellers, sealedSellers, _, _ := uploadStoreLists(sig)
	return uploadModalKeys{
		AltKeys:          UploadIndexComparePriceList,
		SellerKeys:       singlesSellers,
		SealedSellerKeys: sealedSellers,
		CanUploadCustom:  canUploadCustom,
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

// settingsModalVars is everything the modal body renders from.
type settingsModalVars struct {
	Hash     string
	Tabs     []string
	TabNames map[string]string

	// search
	SellerKeys    []string
	VendorKeys    []string
	ListingLocked bool

	// upload
	UploadAltKeys          []string
	UploadSellerKeys       []string
	UploadSealedSellerKeys []string
	CanUploadCustom        bool

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
	// Behind noSigning, so only a sig this host wrote earns tabs
	sig := verifiedSignature(r)
	nav := genPageNav(s, r, "", sig).Nav
	_, offlineAllowed := offlineModeAllowed(r)

	v := settingsModalVars{
		Hash:               BuildCommit,
		Tabs:               settingsTabs(nav, offlineAllowed),
		TabNames:           settingsTabNames,
		ListingLocked:      sig == "" && SigCheck,
		OfflineModeAllowed: offlineAllowed,
		EditionsCategories: ds.editions.AllEditionsCategoriesSorted,
		EditionsByCategory: ds.editions.AllEditionsByCategory,
	}
	v.SellerKeys, v.VendorKeys = searchSettingsKeys()

	up := uploadSettingsKeys(sig)
	v.UploadAltKeys = up.AltKeys
	v.UploadSellerKeys = up.SellerKeys
	v.UploadSealedSellerKeys = up.SealedSellerKeys
	v.CanUploadCustom = up.CanUploadCustom

	v.ArbitVendorKeys = arbitVendorKeys(arbitBlockedVendors(sig), false)
	v.GlobalVendorKeys = globalVendorKeys(globalProbeBlocklist())
	v.ReverseVendorKeys = arbitVendorKeys(arbitBlockedVendors(sig), true)

	retail, buylist := sleepBlocklists(sig)
	v.SleepSellerKeys, v.SleepVendorKeys = sleepModalKeys(retail, buylist)

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
