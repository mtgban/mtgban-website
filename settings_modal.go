package main

import (
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
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

// uploadSettingsKeys reads the Upload tab's data the way the Upload page
// does, without writing any cookie.
func uploadSettingsKeys(r *http.Request) uploadModalKeys {
	sig := getSignatureFromCookies(r)
	st := readUploadSettings(r, false)
	singlesSellers, sealedSellers, _, _ := uploadStoreLists(sig)
	return uploadModalKeys{
		AltKeys:          UploadIndexComparePriceList,
		SellerKeys:       singlesSellers,
		SealedSellerKeys: sealedSellers,
		CanUploadCustom:  st.canUploadCustom,
	}
}
