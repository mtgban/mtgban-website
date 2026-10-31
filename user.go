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
	Perks             []TierPerk
}

// patreonTiers are the tiers a Patreon membership maps to, in order of
// price, as Auth names them. Staff tiers and retired ones are not described.
var patreonTiers = []string{"Pioneer", "Modern", "Legacy", "Vintage"}

// tierSummaries describes the Any entry and each Patreon tier the table
// has, with the pages s shows; current names the reader's tier, matched
// without case.
func tierSummaries(s *site, table access.Table, current string) []TierSummary {
	var out []TierSummary
	// Any opens its pages to readers with no signature, so its flags reach
	// nobody: they get each page's defaults.
	open := map[string]map[string]string{}
	for page := range table["Any"] {
		open[page] = nil
	}
	if pages := tierPages(s, open); len(pages) > 0 {
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
// of the flags it sets, or that Search defaults; a key the registry lacks
// or s hides is skipped.
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
		switch key {
		case "Search":
			flags = searchFlags(flags)
		case "Global":
			flags = globalFlags(flags)
		}
		page := TierPage{Name: nav.Name, Description: nav.Description}
		for _, flag := range slices.Sorted(maps.Keys(flags)) {
			if perk, ok := aclFlagPerk(flag, flags[flag]); ok {
				page.Perks = append(page.Perks, perk)
			}
		}
		pages = append(pages, page)
	}
	return pages
}

// TierGroup is one page across the tier cards: which tiers grant it, and a
// row per perk any of them gives.
type TierGroup struct {
	Name, Description string
	Granted           []bool
	Rows              []TierRow
}

// TierRow is one perk across the tier cards, with a cell per tier, empty
// where the tier lacks it.
type TierRow struct {
	Name  string
	Cells []string
}

// tierComparison lays the tier cards side by side: a group per page in nav
// order, a row per perk from the most tiers to the fewest, then in flag
// order, cells in the order of tiers; a key the registry lacks is skipped.
func tierComparison(tiers []TierSummary) []TierGroup {
	var groups []TierGroup
	for _, key := range OrderNav {
		nav, known := ExtraNavs[key]
		if !known {
			continue
		}
		group := TierGroup{Name: nav.Name, Granted: make([]bool, len(tiers))}
		rows := map[string]*TierRow{}
		var flags []string
		for i, tier := range tiers {
			for _, page := range tier.Pages {
				if page.Name != group.Name {
					continue
				}
				group.Description = page.Description
				group.Granted[i] = true
				for _, perk := range page.Perks {
					row, found := rows[perk.flag]
					if !found {
						row = &TierRow{Name: perk.Row, Cells: make([]string, len(tiers))}
						rows[perk.flag] = row
						flags = append(flags, perk.flag)
					}
					row.Cells[i] = perk.Cell
				}
			}
		}
		if !slices.Contains(group.Granted, true) {
			continue
		}
		slices.Sort(flags)
		slices.SortStableFunc(flags, func(a, b string) int {
			return granted(rows[b].Cells) - granted(rows[a].Cells)
		})
		for _, flag := range flags {
			group.Rows = append(group.Rows, *rows[flag])
		}
		groups = append(groups, group)
	}
	return groups
}

// granted counts the tiers a row's cells give the perk to.
func granted(cells []string) int {
	n := 0
	for _, cell := range cells {
		if cell != "" {
			n++
		}
	}
	return n
}

// searchFlags is a tier's Search flags as the page reads them: the
// backpacks and the chart history take their defaults where unset, and
// the backpacks are clamped by the backpack's size.
func searchFlags(flags map[string]string) map[string]string {
	v := url.Values{}
	for flag, value := range flags {
		v.Set(flag, value)
	}
	out := maps.Clone(flags)
	if out == nil {
		out = map[string]string{}
	}
	out["SearchBackpackMax"] = strconv.Itoa(backpackMaxFromValues(v))
	out["SearchBackpackTabs"] = strconv.Itoa(backpackTabsFromValues(v))
	out["SearchChartLoopback"] = strconv.Itoa(lookbackFromValue(v.Get("SearchChartLoopback")).Days())
	return out
}

// globalFlags is a tier's Global flags with AnySpread always set, so every
// tier shows the spread floor it gets.
func globalFlags(flags map[string]string) map[string]string {
	out := maps.Clone(flags)
	if out == nil {
		out = map[string]string{}
	}
	out["AnySpread"] = flags["AnySpread"]
	return out
}

// TierPerk is what one of a tier's flags gives: the pill its card shows,
// if any, and the row and cell it takes when the tiers are compared.
type TierPerk struct {
	Label, Row, Cell string
	flag             string // orders the rows
}

// aclFlagPerk says what a signed ACL value gives the reader, in the words
// the pages use; false for a flag or value the page does not name.
func aclFlagPerk(flag, value string) (TierPerk, bool) {
	perk := func(label, row, cell string) (TierPerk, bool) {
		return TierPerk{Label: label, Row: row, Cell: cell, flag: flag}, true
	}
	on := func(label string) (TierPerk, bool) {
		if set, _ := strconv.ParseBool(value); !set {
			return TierPerk{}, false
		}
		return perk(label, label, "✓")
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		n = 0
	}
	switch flag {
	case "UploadBuylistEnabled":
		return on("Show Buylist prices")
	case "UploadChangeStoresEnabled":
		return on("Choose which stores to price")
	case "UploadOptimizer":
		return on("Access the Optimizer")
	case "UploadNoLimit":
		return on("Unlimited list size")
	case "UploadCustom":
		return on("Import custom searches")
	case "UploadPublish":
		return on("Publish an upload as a store")
	case "NewsEnabled":
		switch value {
		case "0day":
			return perk("Same-day data", "Data delay", "Same day")
		case "1day":
			return perk("Data one day behind", "Data delay", "1 day")
		case "3day":
			return perk("Data three days behind", "Data delay", "3 days")
		}
	case "NewsLarge":
		return on("Double the rows per page")
	case "SearchDownloadCSV":
		return on("CSV download of results")
	case "SearchChartLoopback":
		if n > 0 {
			return perk("Price charts back "+historySpan(n), "Price chart history", historySpan(n))
		}
	case "SearchOfflineMode":
		return on("Offline mode")
	case "SearchBackpackMax":
		if n > 0 {
			return perk("Backpack of "+plural(n, "card"), "Backpack size", plural(n, "card"))
		}
	case "SearchBackpackTabs":
		// Every tier keeps one backpack, which its card does not mention
		if n == 1 {
			return perk("", "Number of available backpacks", "1")
		}
		if n > 1 {
			return perk(fmt.Sprintf("Up to %d backpacks", n), "Number of available backpacks", strconv.Itoa(n))
		}
	case "SearchDisabled":
		return listPerk(flag, value, "Retail stores", "Every retail store shown", "Some retail stores hidden")
	case "SearchBuylistDisabled":
		return listPerk(flag, value, "Buylists", "Every buylist shown", "Some buylists hidden")
	case "ArbitEnabled":
		switch {
		case value == "ALL":
			return perk("Every store", "Stores", "All")
		case value != "":
			count := len(strings.Split(value, ","))
			return perk(plural(count, "store"), "Stores", strconv.Itoa(count))
		}
	case "ArbitDisabledVendors":
		if value != "" {
			return perk("Some vendors excluded", "Vendors", "Some excluded")
		}
	case "AnyEnabled":
		return on("Expanded store selection")
	case "AnyExperimentsEnabled":
		return on("Experimental stores included")
	case "AnySpread":
		// The lowest spread Global lists singles at; the grant lowers it
		set, _ := strconv.ParseBool(value)
		if set {
			floor := fmt.Sprintf("%g%%", float64(MinSpreadGlobalPro))
			return perk("Spreads down to "+floor, "Lowest spread", floor)
		}
		return perk("", "Lowest spread", fmt.Sprintf("%g%%", float64(MinSpreadGlobal)))
	case "SleepersCYOA":
		return on("Pick your own store pairing")
	case "AlertsMax":
		if n > 0 {
			return perk("Up to "+plural(n, "alert"), "Alerts", strconv.Itoa(n))
		}
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
		if len(names) > 0 {
			channels := strings.Join(names, " and ")
			return perk("Delivered by "+channels, "Delivery", channels)
		}
	case "APImode":
		if value != "" {
			modes := strings.Join(strings.Split(value, ","), ", ")
			return perk("Price API modes: "+modes, "Price API modes", modes)
		}
	}
	return TierPerk{}, false
}

// historySpan spells a chart history of days in years when it is within a
// week a year of whole ones (720 days is 2 years) or rounds to whole ones in
// months, else in months, and in days under half a month.
func historySpan(days int) string {
	years := (days + 182) / 365
	off := days - years*365
	if off < 0 {
		off = -off
	}
	if years > 0 && off <= 7*years {
		return plural(years, "year")
	}
	// Rounded to months of 30.44 days, a year's average
	months := (days*100 + 1522) / 3044
	if months > 0 && months%12 == 0 {
		return plural(months/12, "year")
	}
	if months > 0 {
		return plural(months, "month")
	}
	return plural(days, "day")
}

// listPerk reads a blocklist flag's value: NONE clears it, a list hides
// some.
func listPerk(flag, value, row, none, some string) (TierPerk, bool) {
	switch value {
	case "":
		return TierPerk{}, false
	case "NONE":
		return TierPerk{Label: none, Row: row, Cell: "All", flag: flag}, true
	}
	return TierPerk{Label: some, Row: row, Cell: "Some hidden", flag: flag}, true
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
	Compare    []TierGroup // Tiers side by side
	// CanRefresh is whether the page offers Refresh now: the site renews
	// signatures and this browser holds the session to renew from.
	CanRefresh bool
	// CanEndSessions is whether the page offers Log out everywhere: the site
	// keeps sessions and this browser holds one.
	CanEndSessions bool
	// RefreshNote says what the last Refresh now did, empty before one.
	RefreshNote string
}

// refreshNotes are the notes the Account page shows after Refresh now, by
// the refreshed value its redirect carries.
var refreshNotes = map[string]string{
	"yes":   "Refreshed: your tier is the one Patreon reports now",
	"no":    "Not refreshed: try again in a few minutes",
	"ended": "Not refreshed: this sign-in has ended, log in again to keep it renewing",
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
	if r.Method == http.MethodPost {
		s.writeAccountAction(w, r)
		return
	}
	sig := verifiedSignature(r)
	pageVars := genPageNav(s, r, "Account", sig)
	pageVars.User = &UserVars{}
	if pageVars.ErrorMessage == "" {
		pageVars.User = s.userVars(r.Context(), parseSig(sig), pageVars.IsMobile)
		hasSession := pageVars.User.SignedIn && readCookie(r, sessionCookie) != ""
		pageVars.User.CanRefresh = hasSession && renewalEnabled()
		pageVars.User.CanEndSessions = hasSession && UserStateDB != nil
		pageVars.User.RefreshNote = refreshNotes[r.FormValue("refreshed")]
	}
	render(w, "user.html", pageVars)
}

// writeAccountAction answers a POST to the Account page with a redirect,
// whatever it does. Refresh now renews the signature this browser holds from
// the session its BAN_SESSION cookie names, as a due signature would be, only
// without waiting for its age, rests the sessions for renewalRefreshRest so
// that a second press asks Patreon nothing, and says on the page whether it
// renewed. Log out everywhere ends every session of the reader's email when
// this browser holds one of them, and clears this browser's cookies either
// way: a signature alone, which links and logs can leak, ends nobody else's
// sessions. Both act on the reader the signature cookie names, never on a
// ?sig= or a form field.
func (s *site) writeAccountAction(w http.ResponseWriter, r *http.Request) {
	// A form on another site's page is refused before it is read
	if crossSitePost(r) {
		http.Error(w, "cross-site form refused", http.StatusForbidden)
		return
	}

	values, signed := signatureIsValid(cookieSignature(r))
	email := ""
	if signed {
		email = values.Get("UserEmail")
	}
	switch r.PostFormValue("action") {
	case "refresh":
		where := "/user?refreshed=no"
		if email != "" && renewalEnabled() {
			_, outcome := s.renewSignature(w, r, values, renewalRefreshRest, "refresh")
			switch outcome {
			case renewalRefused:
				where = "/user"
			case renewalRenewed:
				where = "/user?refreshed=yes"
			case renewalEnded, renewalSessionGone:
				where = "/user?refreshed=ended"
			}
		}
		http.Redirect(w, r, where, http.StatusSeeOther)
	case "logout-everywhere":
		// With the database down the cookies go anyway, and the sessions
		// wait for the prune or the next press
		session := readCookie(r, sessionCookie)
		if email != "" && session != "" && UserStateDB != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			_, err := UserStateDB.DeletePatreonSessionsFor(ctx, session, userstate.HashEmail(email))
			cancel()
			if err != nil {
				LogPages["Admin"].Println("DeletePatreonSessionsFor", err)
			}
		}
		clearLoginCookies(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/user", http.StatusSeeOther)
	}
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
	v.Compare = tierComparison(v.Tiers)
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
// grants; nobody for an anonymous one.
func userFeatures(s *site, sigParams url.Values, isMobile bool) []UserFeature {
	if sigParams.Get("UserEmail") == "" {
		return nil
	}
	var out []UserFeature
	if navOffers(s, sigParams, "Search") {
		out = append(out,
			UserFeature{Name: "Favorites", Description: "Cards you starred, with their best prices", Link: "/search"},
			UserFeature{Name: "Recent searches", Description: "What you looked up lately, on every device you sign in on", Link: "/search"},
		)
	}
	// The settings modal is desktop only.
	if !isMobile {
		out = append(out, UserFeature{Name: "Settings", Description: "Your preferences, mostly saved in this browser", Link: "/user?settings=1"})
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
