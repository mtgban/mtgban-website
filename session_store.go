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
// session store reaches the served stores, the scraper config, the
// served snapshot, and the notification channel. Tests rebuild it from
// sessionHooks(testSite) to get a private, empty registry bound to the same real
// hooks, rather than sharing this one across the whole test binary.
var Sessions *sessionstore.Registry

// sessionHooks binds the session store to the site whose snapshot it
// publishes into and reads.
func sessionHooks(s *site) sessionstore.Hooks {
	return sessionstore.Hooks{
		Sellers:      func() []mtgban.Seller { return s.prices().sellers },
		Vendors:      func() []mtgban.Vendor { return s.prices().vendors },
		IsConfigured: s.isConfiguredScraper,
		Install:      s.installSessionScraper,
		Drop:         s.dropSessionScraper,
		Notify:       func(kind, message string) { ServerNotify(kind, message) },
	}
}

// installSessionScraper publishes scraper as the served retail or buylist
// scraper for its shorthand, through the same install path (and the same
// freshness/shrink refusals) a bucket load uses.
func (s *site) installSessionScraper(kind string, scraper mtgban.Scraper) error {
	if kind == sessionstore.Retail {
		return s.updateSellers(scraper)
	}
	return s.updateVendors(scraper)
}

// dropSessionScraper takes the scraper serving shorthand off the served
// snapshot, on the given side. Takes scrapersMu, so per sessionstore's Hooks
// doc, nothing that holds scrapersMu may call into Sessions.
func (s *site) dropSessionScraper(kind, shorthand string) {
	s.scrapersMu.Lock()
	defer s.scrapersMu.Unlock()

	p := s.prices()
	if kind == sessionstore.Retail {
		next := slices.DeleteFunc(slices.Clone(p.sellers), func(seller mtgban.Seller) bool {
			return seller.Info().Shorthand == shorthand
		})
		s.pricesPtr.Store(newPrices(p, next, p.vendors, p.scrapers))
		return
	}
	next := slices.DeleteFunc(slices.Clone(p.vendors), func(vendor mtgban.Vendor) bool {
		return vendor.Info().Shorthand == shorthand
	})
	s.pricesPtr.Store(withVendors(p, next))
}

// isConfiguredScraper reports whether the dumps bucket's last listing named
// the shorthand under any store, loaded or not, compared the way the site's
// own lookups are: case-insensitively.
func (s *site) isConfiguredScraper(shorthand string) bool {
	for configured := range s.prices().scrapers.byShorthand {
		if strings.EqualFold(configured, shorthand) {
			return true
		}
	}
	return false
}
