package main

import (
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

// Sessions tracks the scrapers an admin published from an upload, wired to
// this site's own scraper state: see internal/sessionstore for the store
// itself and the publish/remove logic. This file is only the wiring - how a
// session store reaches GetSellers/GetVendors, the scraper config, the
// served snapshot, and the notification channel. Tests rebuild it from
// sessionHooks() to get a private, empty registry bound to the same real
// hooks, rather than sharing this one across the whole test binary.
var Sessions = sessionstore.New(sessionHooks())

func sessionHooks() sessionstore.Hooks {
	return sessionstore.Hooks{
		Sellers:      GetSellers,
		Vendors:      GetVendors,
		IsConfigured: isConfiguredScraper,
		Install:      installSessionScraper,
		Drop:         dropSessionScraper,
		Notify:       func(kind, message string) { ServerNotify(kind, message) },
	}
}

// installSessionScraper publishes scraper as the served retail or buylist
// scraper for its shorthand, through the same install path (and the same
// freshness/shrink refusals) a bucket load uses.
func installSessionScraper(kind string, scraper mtgban.Scraper) error {
	if kind == sessionstore.Retail {
		return updateSellers(scraper)
	}
	return updateVendors(scraper)
}

// dropSessionScraper takes the scraper serving shorthand off the served
// snapshot, on the given side. Takes scrapersWriteMu, so per sessionstore's
// Hooks doc, nothing that holds scrapersWriteMu may call into Sessions.
func dropSessionScraper(kind, shorthand string) {
	scrapersWriteMu.Lock()
	defer scrapersWriteMu.Unlock()

	if kind == sessionstore.Retail {
		next := slices.DeleteFunc(slices.Clone(GetSellers()), func(seller mtgban.Seller) bool {
			return seller.Info().Shorthand == shorthand
		})
		sellersPtr.Store(&next)
		return
	}
	next := slices.DeleteFunc(slices.Clone(GetVendors()), func(vendor mtgban.Vendor) bool {
		return vendor.Info().Shorthand == shorthand
	})
	vendorsPtr.Store(&next)
}

// isConfiguredScraper reports whether any section of the scraper config
// names the shorthand, loaded or not, compared the way the site's own
// lookups are: case-insensitively.
func isConfiguredScraper(shorthand string) bool {
	for _, sections := range Config.ScraperConfig.Config {
		for _, list := range sections {
			if slices.ContainsFunc(list, func(configured string) bool {
				return strings.EqualFold(configured, shorthand)
			}) {
				return true
			}
		}
	}
	return false
}
