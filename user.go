package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/userstate"
)

// TierSummary is one tier's pages and what each page unlocks.
type TierSummary struct {
	Name    string // "Everyone" for the Any entry
	Key     string // lowercased tier, "" for Everyone
	Current bool
	Pages   []TierPage
}

// TierPage is one page a tier grants, with the perks its flags add.
type TierPage struct {
	Name, Description string
	Perks             []string
}

// patreonTiers are the tiers a Patreon membership maps to, in order of
// price, as Auth names them. Staff tiers and retired ones are not described.
var patreonTiers = []string{"Pioneer", "Modern", "Legacy", "Vintage"}

// tierSummaries describes the Any entry and each Patreon tier the table
// has, with the pages s shows; current names the reader's tier, matched
// without case.
func tierSummaries(s *site, table access.Table, current string) []TierSummary {
	var out []TierSummary
	if pages := tierPages(s, table["Any"]); len(pages) > 0 {
		out = append(out, TierSummary{Name: "Everyone", Pages: pages})
	}
	for _, tier := range patreonTiers {
		entry, found := table[tier]
		if !found {
			continue
		}
		out = append(out, TierSummary{
			Name:    tier,
			Key:     strings.ToLower(tier),
			Current: strings.EqualFold(tier, current),
			Pages:   tierPages(s, entry),
		})
	}
	return out
}

// tierPages lists a tier entry's pages in nav order, each with the labels
// of the flags it sets; a key the registry lacks or s hides is skipped.
func tierPages(s *site, entry map[string]map[string]string) []TierPage {
	var pages []TierPage
	for _, key := range OrderNav {
		flags, found := entry[key]
		if !found {
			continue
		}
		nav, known := ExtraNavs[key]
		if !known || nav.hiddenOn(s) {
			continue
		}
		page := TierPage{Name: nav.Name, Description: nav.Description}
		for _, flag := range slices.Sorted(maps.Keys(flags)) {
			if label, ok := aclFlagLabel(flag, flags[flag]); ok {
				page.Perks = append(page.Perks, label)
			}
		}
		pages = append(pages, page)
	}
	return pages
}

// aclFlagLabel says what a signed ACL value gives the reader, in the
// words the pages use; false for a flag or value the page does not name.
func aclFlagLabel(flag, value string) (string, bool) {
	on := func(label string) (string, bool) {
		if set, _ := strconv.ParseBool(value); !set {
			return "", false
		}
		return label, true
	}
	count := func(singular, plural string) (string, bool) {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			return "", false
		}
		if n == 1 {
			return fmt.Sprintf(singular, n), true
		}
		return fmt.Sprintf(plural, n), true
	}
	switch flag {
	case "UploadBuylistEnabled":
		return on("Buylist prices")
	case "UploadChangeStoresEnabled":
		return on("Choose which stores to price")
	case "UploadOptimizer":
		return on("Sell-list optimizer")
	case "UploadNoLimit":
		return on("No limit on list size")
	case "UploadCustom":
		return on("Import custom searches")
	case "UploadPublish":
		return on("Publish an upload as a store")
	case "NewsEnabled":
		switch value {
		case "0day":
			return "Same-day data", true
		case "1day":
			return "Data one day behind", true
		case "3day":
			return "Data three days behind", true
		}
		return "", false
	case "NewsLarge":
		return on("50 rows per page")
	case "SearchDownloadCSV":
		return on("CSV download of results")
	case "SearchChartLoopback":
		return count("Price charts back %d day", "Price charts back %d days")
	case "SearchOfflineMode":
		return on("Offline mode")
	case "SearchDisabled":
		return listLabel(value, "Every retail store shown", "Some retail stores hidden")
	case "SearchBuylistDisabled":
		return listLabel(value, "Every buylist shown", "Some buylists hidden")
	case "ArbitEnabled":
		if value == "ALL" {
			return "Every store", true
		}
		if value == "" {
			return "", false
		}
		n := len(strings.Split(value, ","))
		if n == 1 {
			return "1 store", true
		}
		return fmt.Sprintf("%d stores", n), true
	case "ArbitDisabledVendors":
		if value == "" {
			return "", false
		}
		return "Some vendors excluded", true
	case "AnyEnabled":
		return on("Compare the full store list")
	case "AnyExperimentsEnabled":
		return on("Experimental stores included")
	case "AnySpread":
		return on("Spread view")
	case "SleepersCYOA":
		return on("Pick your own store pairing")
	case "AlertsMax":
		return count("Up to %d alert", "Up to %d alerts")
	case "AlertChannels":
		var names []string
		for _, kind := range strings.Split(value, ",") {
			switch strings.TrimSpace(kind) {
			case "discord":
				names = append(names, "Discord")
			case "email":
				names = append(names, "email")
			}
		}
		if len(names) == 0 {
			return "", false
		}
		return "Delivered by " + strings.Join(names, " and "), true
	case "APImode":
		if value == "" {
			return "", false
		}
		return "Price API modes: " + strings.Join(strings.Split(value, ","), ", "), true
	}
	return "", false
}

// listLabel reads a blocklist value: NONE clears it, a list hides some.
func listLabel(value, none, some string) (string, bool) {
	switch value {
	case "":
		return "", false
	case "NONE":
		return none, true
	}
	return some, true
}

// DiscordStatus is the Discord account Patreon reports as linked.
type DiscordStatus struct {
	// "linked", "unlinked", "pending" (no login row yet), "unavailable"
	// (no store or a failed read) or "unverified" (Patreon email unconfirmed)
	State  string
	Handle string // "@name" when the bot resolved it, else ""
}

// contactReader is the one Store read the Account page makes.
type contactReader interface {
	Contact(ctx context.Context, userHash string) (alerts.Contact, bool, error)
}

// discordStatus reads the reader's linked Discord account off the login
// record and names it through resolve; a failed name leaves it linked.
func discordStatus(ctx context.Context, rd contactReader, resolve func(context.Context, string) (string, error), userHash string) DiscordStatus {
	if rd == nil {
		return DiscordStatus{State: "unavailable"}
	}
	c, found, err := rd.Contact(ctx, userHash)
	if err != nil {
		return DiscordStatus{State: "unavailable"}
	}
	if !found {
		return DiscordStatus{State: "pending"}
	}
	if c.DiscordUserID == "" {
		return DiscordStatus{State: "unlinked"}
	}
	st := DiscordStatus{State: "linked"}
	if handle, err := resolve(ctx, c.DiscordUserID); err == nil {
		st.Handle = handle
	}
	return st
}

// UserVars is what the Account page shows: the reader, their features
// and the tier table.
type UserVars struct {
	SignedIn   bool
	Name       string
	Email      string
	Unverified bool   // UserEmailUnverified on the signature
	Tier       string // as signed, "Legacy"
	TierKey    string // lowercased, for data-tier styling
	Discord    DiscordStatus
	Features   []UserFeature
	Tiers      []TierSummary
}

// UserFeature is one personal feature the reader's tier grants.
type UserFeature struct {
	Name, Description, Link string
}

// discordLookupTimeout bounds the bot lookup so a slow Discord does not
// hold the page.
const discordLookupTimeout = 2 * time.Second

// User serves the Account page: the tier table for everyone, the reader's
// own account and features when signed in.
func (s *site) User(w http.ResponseWriter, r *http.Request) {
	sig := verifiedSignature(r)
	pageVars := genPageNav(s, r, "Account", sig)
	pageVars.User = &UserVars{}
	if pageVars.ErrorMessage == "" {
		pageVars.User = s.userVars(r.Context(), parseSig(sig), pageVars.IsMobile)
	}
	render(w, "user.html", pageVars)
}

// userVars reads the reader off the signed values and builds the page.
func (s *site) userVars(ctx context.Context, sigParams url.Values, isMobile bool) *UserVars {
	v := &UserVars{
		Name:       sigParams.Get("UserName"),
		Email:      sigParams.Get("UserEmail"),
		Unverified: sigParams.Get("UserEmailUnverified") == "true",
		Tier:       sigParams.Get("UserTier"),
	}
	v.SignedIn = v.Email != ""
	for _, tier := range patreonTiers {
		if strings.EqualFold(tier, v.Tier) {
			v.TierKey = strings.ToLower(tier)
		}
	}
	v.Tiers = tierSummaries(s, ACL(), v.Tier)
	if !v.SignedIn {
		return v
	}
	v.Features = userFeatures(s, sigParams, isMobile)
	if v.Unverified {
		v.Discord = DiscordStatus{State: "unverified"}
		return v
	}
	ctx, cancel := context.WithTimeout(ctx, discordLookupTimeout)
	defer cancel()
	v.Discord = discordStatus(ctx, s.contactReader(), discordHandle, userstate.HashEmail(v.Email))
	return v
}

// userFeatures lists the personal features the signed reader's tier
// grants, with the link each device lands on; nobody for an anonymous one.
func userFeatures(s *site, sigParams url.Values, isMobile bool) []UserFeature {
	if sigParams.Get("UserEmail") == "" {
		return nil
	}
	var out []UserFeature
	if navOffers(s, sigParams, "Search") {
		favorites, recents := "/search#desktop-favorites", "/search#desktop-recent-searches"
		if isMobile {
			favorites, recents = "/search#m-favorites", "/search#m-recent-searches"
		}
		out = append(out,
			UserFeature{Name: "Favorites", Description: "Cards you starred, with their best prices", Link: favorites},
			UserFeature{Name: "Recent searches", Description: "What you looked up lately, on every device you sign in on", Link: recents},
		)
	}
	// The settings modal is desktop only.
	if !isMobile {
		out = append(out, UserFeature{Name: "Settings", Description: "Your preferences, synced to this account", Link: "/user?settings=1"})
	}
	if navOffers(s, sigParams, "Alerts") && sigParams.Get("UserEmailUnverified") != "true" {
		out = append(out, UserFeature{Name: "Price alerts", Description: "Cards you watch, delivered to Discord or email", Link: "/alerts"})
	}
	return out
}

// contactReader is the alerts store as a reader, or a nil interface when
// there is none, so discordStatus's nil check holds.
func (s *site) contactReader() contactReader {
	store := s.alerts.Store()
	if store != nil {
		return store
	}
	return nil
}
