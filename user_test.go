package main

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// The live table's shape: Any, the four Patreon tiers, a retired one and
// a staff one, with the flags the pages read.
func fixtureACL() access.Table {
	return access.Table{
		"Any":     {"Search": {}, "API": {}},
		"Pioneer": {"Search": {}, "Upload": {}},
		"Modern": {
			"Search":    {},
			"Upload":    {"UploadChangeStoresEnabled": "true"},
			"Newspaper": {"NewsEnabled": "3day"},
			"Global":    {},
		},
		"Legacy": {
			"Search":    {},
			"Upload":    {"UploadOptimizer": "true", "UploadBuylistEnabled": "true", "UploadChangeStoresEnabled": "true", "SomethingNew": "true"},
			"Newspaper": {"NewsEnabled": "1day"},
			"Sleepers":  {},
			"Global":    {"AnyEnabled": "true"},
			"Bogus":     {},
		},
		"Vintage": {
			"Search":    {"SearchDownloadCSV": "true"},
			"Upload":    {"UploadNoLimit": "true"},
			"Newspaper": {"NewsEnabled": "1day", "NewsLarge": "true"},
			"Sleepers":  {"SleepersCYOA": "true"},
			"Global":    {"AnyEnabled": "true", "AnySpread": "true"},
			"Alerts":    {"AlertsMax": "5", "AlertChannels": "discord,email"},
		},
		"Lost Boys": {"Search": {}},
		"Admin":     {"Admin": {}},
	}
}

func tierNames(tiers []TierSummary) []string {
	var names []string
	for _, t := range tiers {
		names = append(names, t.Name)
	}
	return names
}

func TestTierSummariesFollowTheACL(t *testing.T) {
	showNavs(t, "Newspaper", "Alerts")
	tiers := tierSummaries(newSite(), fixtureACL(), "legacy")

	want := []string{"Everyone", "Pioneer", "Modern", "Legacy", "Vintage"}
	if got := tierNames(tiers); !slices.Equal(got, want) {
		t.Fatalf("tiers %v, want %v", got, want)
	}

	everyone := tiers[0]
	if everyone.Key != "" || everyone.Current {
		t.Fatalf("Everyone row %+v", everyone)
	}
	if got := pageNames(everyone.Pages); !slices.Equal(got, []string{"Search", "API"}) {
		t.Fatalf("Everyone pages %v", got)
	}

	legacy := tiers[3]
	if !legacy.Current || legacy.Key != "legacy" {
		t.Fatalf("Legacy not marked current: %+v", legacy)
	}
	// Bogus is not a page; the others follow OrderNav.
	if got := pageNames(legacy.Pages); !slices.Equal(got, []string{"Search", "Newspaper", "Sleepers", "Upload", "Global"}) {
		t.Fatalf("Legacy pages %v", got)
	}
	upload := legacy.Pages[3]
	if upload.Description != ExtraNavs["Upload"].Description {
		t.Fatalf("Upload description %q", upload.Description)
	}
	// Sorted by flag name; the unknown flag adds nothing.
	wantPerks := []string{"Buylist prices", "Choose which stores to price", "Sell-list optimizer"}
	if !slices.Equal(upload.Perks, wantPerks) {
		t.Fatalf("Upload perks %v, want %v", upload.Perks, wantPerks)
	}
	if got := legacy.Pages[1].Perks; !slices.Equal(got, []string{"Data one day behind"}) {
		t.Fatalf("Newspaper perks %v", got)
	}

	for _, tier := range tiers {
		if tier.Name != "Legacy" && tier.Current {
			t.Fatalf("%s marked current", tier.Name)
		}
	}
}

func pageNames(pages []TierPage) []string {
	var names []string
	for _, p := range pages {
		names = append(names, p.Name)
	}
	return names
}

func TestTierSummariesSkipMissingTiersAndEmptyAny(t *testing.T) {
	s := newSite()
	table := access.Table{"Modern": {"Search": {}}, "Any": {}}
	tiers := tierSummaries(s, table, "")
	if got := tierNames(tiers); !slices.Equal(got, []string{"Modern"}) {
		t.Fatalf("tiers %v", got)
	}
	if tierSummaries(s, nil, "Modern") != nil {
		t.Fatal("nil table gave tiers")
	}
}

// A page the site hides (Alerts with no store, Newspaper with no data)
// leaves the tier table too; the grant alone does not advertise it.
func TestTierSummariesSkipHiddenPages(t *testing.T) {
	s := newSite()
	if s.alerts.Store() != nil {
		t.Fatal("fresh site has an alerts store")
	}
	table := access.Table{
		"Any":     {"Search": {}},
		"Vintage": {"Search": {}, "Newspaper": {"NewsEnabled": "1day"}, "Alerts": {"AlertsMax": "5"}},
	}
	vintage := tierSummaries(s, table, "")[1]
	if got := pageNames(vintage.Pages); !slices.Equal(got, []string{"Search"}) {
		t.Fatalf("hidden pages listed: %v", got)
	}

	showNavs(t, "Alerts")
	vintage = tierSummaries(s, table, "")[1]
	if got := pageNames(vintage.Pages); !slices.Equal(got, []string{"Search", "Alerts"}) {
		t.Fatalf("with Alerts shown: %v", got)
	}
	if got := vintage.Pages[1].Perks; !slices.Equal(got, []string{"Up to 5 alerts"}) {
		t.Fatalf("Alerts perks %v", got)
	}
}

func TestACLFlagLabels(t *testing.T) {
	cases := []struct {
		flag, value, want string
		ok                bool
	}{
		{"UploadBuylistEnabled", "true", "Buylist prices", true},
		{"UploadBuylistEnabled", "false", "", false},
		{"UploadBuylistEnabled", "", "", false},
		{"UploadChangeStoresEnabled", "true", "Choose which stores to price", true},
		{"UploadOptimizer", "true", "Sell-list optimizer", true},
		{"UploadNoLimit", "true", "No limit on list size", true},
		{"UploadCustom", "true", "Import custom searches", true},
		{"UploadPublish", "true", "Publish an upload as a store", true},
		{"NewsEnabled", "0day", "Same-day data", true},
		{"NewsEnabled", "1day", "Data one day behind", true},
		{"NewsEnabled", "3day", "Data three days behind", true},
		{"NewsEnabled", "7day", "", false},
		{"NewsLarge", "true", "50 rows per page", true},
		{"SearchDownloadCSV", "true", "CSV download of results", true},
		{"SearchChartLoopback", "90", "Price charts back 90 days", true},
		{"SearchChartLoopback", "0", "", false},
		{"SearchChartLoopback", "lots", "", false},
		{"SearchOfflineMode", "true", "Offline mode", true},
		{"SearchDisabled", "NONE", "Every retail store shown", true},
		{"SearchDisabled", "CK,SCG", "Some retail stores hidden", true},
		{"SearchDisabled", "", "", false},
		{"SearchBuylistDisabled", "NONE", "Every buylist shown", true},
		{"SearchBuylistDisabled", "CK", "Some buylists hidden", true},
		{"ArbitEnabled", "ALL", "Every store", true},
		{"ArbitEnabled", "CK,SCG,TCG", "3 stores", true},
		{"ArbitEnabled", "CK", "1 store", true},
		{"ArbitEnabled", "", "", false},
		{"ArbitDisabledVendors", "CK", "Some vendors excluded", true},
		{"ArbitDisabledVendors", "", "", false},
		{"AnyEnabled", "true", "Compare the full store list", true},
		{"AnyExperimentsEnabled", "true", "Experimental stores included", true},
		{"AnySpread", "true", "Spread view", true},
		{"SleepersCYOA", "true", "Pick your own store pairing", true},
		{"SearchBackpackTabs", "3", "Up to 3 backpacks", true},
		{"SearchBackpackTabs", "1", "", false},
		{"AlertsMax", "5", "Up to 5 alerts", true},
		{"AlertsMax", "1", "Up to 1 alert", true},
		{"AlertsMax", "0", "", false},
		{"AlertsMax", "many", "", false},
		{"AlertChannels", "discord,email", "Delivered by Discord and email", true},
		{"AlertChannels", "email", "Delivered by email", true},
		{"AlertChannels", "pigeon", "", false},
		{"APImode", "retail,buylist", "Price API modes: retail, buylist", true},
		{"APImode", "", "", false},
		{"SearchChartDelete", "true", "", false},
		{"NeverHeardOfIt", "true", "", false},
	}
	for _, c := range cases {
		got, ok := aclFlagLabel(c.flag, c.value)
		if got != c.want || ok != c.ok {
			t.Errorf("aclFlagLabel(%q, %q) = %q, %v; want %q, %v", c.flag, c.value, got, ok, c.want, c.ok)
		}
	}
}

type fakeContacts struct {
	contact alerts.Contact
	found   bool
	err     error
}

func (f fakeContacts) Contact(context.Context, string) (alerts.Contact, bool, error) {
	return f.contact, f.found, f.err
}

func resolveTo(handle string) func(context.Context, string) (string, error) {
	return func(context.Context, string) (string, error) { return handle, nil }
}

func TestDiscordStatus(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		rd   contactReader
		want DiscordStatus
	}{
		{"nil reader", nil, DiscordStatus{State: "unavailable"}},
		{"no row", fakeContacts{}, DiscordStatus{State: "pending"}},
		{"read error", fakeContacts{found: true, err: errors.New("down")}, DiscordStatus{State: "unavailable"}},
		{"unlinked", fakeContacts{found: true, contact: alerts.Contact{}}, DiscordStatus{State: "unlinked"}},
		{"linked", fakeContacts{found: true, contact: alerts.Contact{DiscordUserID: "77"}}, DiscordStatus{State: "linked", Handle: "@elmo"}},
	}
	for _, c := range cases {
		got := discordStatus(ctx, c.rd, resolveTo("@elmo"), "hash")
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A slow or absent bot leaves the state linked and the handle empty.
func TestDiscordStatusLinkedWithoutHandleOnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolve := func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }
	got := discordStatus(ctx, fakeContacts{found: true, contact: alerts.Contact{DiscordUserID: "77"}}, resolve, "hash")
	if got != (DiscordStatus{State: "linked"}) {
		t.Fatalf("%+v", got)
	}
}

func TestDiscordHandleCachesForAnHour(t *testing.T) {
	saved := discordLookup
	t.Cleanup(func() {
		discordLookup = saved
		resetDiscordHandles()
	})
	resetDiscordHandles()
	calls := 0
	discordLookup = func(context.Context, string) (*discordgo.User, error) {
		calls++
		return &discordgo.User{Username: "elmo", Discriminator: "0"}, nil
	}
	ctx := context.Background()
	for range 2 {
		got, err := discordHandle(ctx, "77")
		if err != nil || got != "@elmo" {
			t.Fatalf("handle %q err %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("looked up %d times, want 1", calls)
	}
	// Age the entry past its hour: the next call asks again.
	discordHandles.Lock()
	entry := discordHandles.m["77"]
	entry.until = time.Now().Add(-time.Second)
	discordHandles.m["77"] = entry
	discordHandles.Unlock()
	if _, err := discordHandle(ctx, "77"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("looked up %d times after expiry, want 2", calls)
	}
}

// A failed lookup is remembered for a minute as a miss, so a deleted
// account or an outage costs one bot call, not one per page load.
func TestDiscordHandleCachesAMiss(t *testing.T) {
	saved := discordLookup
	t.Cleanup(func() {
		discordLookup = saved
		resetDiscordHandles()
	})
	resetDiscordHandles()
	calls := 0
	failing := true
	discordLookup = func(context.Context, string) (*discordgo.User, error) {
		calls++
		if failing {
			return nil, errors.New("404 unknown user")
		}
		return &discordgo.User{Username: "elmo", Discriminator: "0"}, nil
	}
	ctx := context.Background()
	for range 2 {
		got, err := discordHandle(ctx, "79")
		if err == nil || got != "" {
			t.Fatalf("handle %q err %v, want a miss", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("looked up %d times, want 1", calls)
	}
	discordHandles.Lock()
	entry := discordHandles.m["79"]
	discordHandles.Unlock()
	if ttl := time.Until(entry.until); entry.handle != "" || ttl > discordHandleMissTTL || ttl < discordHandleMissTTL-10*time.Second {
		t.Fatalf("miss cached as %+v, want an empty handle for %v", entry, discordHandleMissTTL)
	}
	// Age the miss: the next call asks again and a hit replaces it.
	failing = false
	discordHandles.Lock()
	entry.until = time.Now().Add(-time.Second)
	discordHandles.m["79"] = entry
	discordHandles.Unlock()
	got, err := discordHandle(ctx, "79")
	if err != nil || got != "@elmo" || calls != 2 {
		t.Fatalf("after expiry: handle %q err %v, %d lookups", got, err, calls)
	}
}

func TestDiscordHandleStopsAtTheContext(t *testing.T) {
	saved := discordLookup
	t.Cleanup(func() {
		discordLookup = saved
		resetDiscordHandles()
	})
	resetDiscordHandles()
	release := make(chan struct{})
	discordLookup = func(context.Context, string) (*discordgo.User, error) {
		<-release
		return &discordgo.User{Username: "elmo", Discriminator: "0"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := discordHandle(ctx, "90")
	close(release)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err %v after %v, want a timeout", err, time.Since(start))
	}
}

func TestDiscordHandleCoalescesLookups(t *testing.T) {
	saved := discordLookup
	t.Cleanup(func() {
		discordLookup = saved
		resetDiscordHandles()
	})
	resetDiscordHandles()
	var calls atomic.Int32
	release := make(chan struct{})
	discordLookup = func(context.Context, string) (*discordgo.User, error) {
		calls.Add(1)
		<-release
		return &discordgo.User{Username: "elmo", Discriminator: "0"}, nil
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if got, err := discordHandle(context.Background(), "91"); err != nil || got != "@elmo" {
				t.Errorf("got %q, %v", got, err)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d lookups, want 1", n)
	}
}

func TestDiscordHandleLegacyDiscriminator(t *testing.T) {
	saved := discordLookup
	t.Cleanup(func() {
		discordLookup = saved
		resetDiscordHandles()
	})
	resetDiscordHandles()
	discordLookup = func(context.Context, string) (*discordgo.User, error) {
		return &discordgo.User{Username: "elmo", Discriminator: "1234"}, nil
	}
	got, err := discordHandle(context.Background(), "78")
	if err != nil || got != "@elmo#1234" {
		t.Fatalf("handle %q err %v", got, err)
	}
}

func TestDiscordHandleWithoutSession(t *testing.T) {
	resetDiscordHandles()
	t.Cleanup(resetDiscordHandles)
	if dg != nil {
		t.Skip("a Discord session is connected")
	}
	if _, err := discordHandle(context.Background(), "77"); err == nil {
		t.Fatal("no session resolved a handle")
	}
}

// signedParams is what parseSig gives for a reader an hour from expiry
// with the named pages granted.
func signedParams(email, tier string, pages ...string) url.Values {
	v := url.Values{}
	v.Set("Expires", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	if email != "" {
		v.Set("UserEmail", email)
		v.Set("UserName", "Elmo")
	}
	if tier != "" {
		v.Set("UserTier", tier)
	}
	for _, page := range pages {
		v.Set(page, "true")
	}
	return v
}

func featureLinks(features []UserFeature) []string {
	var links []string
	for _, f := range features {
		links = append(links, f.Link)
	}
	return links
}

// showNavs lifts the named entries' hide rules (Alerts with no store,
// Newspaper with no data) for one test, so the grant alone decides.
func showNavs(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		nav := ExtraNavs[name]
		saved := nav.ShouldHide
		nav.ShouldHide = nil
		t.Cleanup(func() { nav.ShouldHide = saved })
	}
}

func TestUserFeaturesFollowTheGrants(t *testing.T) {
	withSigMode(t, false, true)
	showNavs(t, "Alerts")
	s := newSite()

	desktop := featureLinks(userFeatures(s, signedParams("a@b.com", "Vintage", "Search", "Alerts"), false))
	want := []string{"/search", "/search", "/user?settings=1", "/alerts"}
	if !slices.Equal(desktop, want) {
		t.Fatalf("desktop %v, want %v", desktop, want)
	}

	mobile := featureLinks(userFeatures(s, signedParams("a@b.com", "Vintage", "Search", "Alerts"), true))
	want = []string{"/search", "/search", "/alerts"}
	if !slices.Equal(mobile, want) {
		t.Fatalf("mobile %v, want %v", mobile, want)
	}

	noAlerts := featureLinks(userFeatures(s, signedParams("a@b.com", "Modern", "Search"), false))
	want = []string{"/search", "/search", "/user?settings=1"}
	if !slices.Equal(noAlerts, want) {
		t.Fatalf("without Alerts %v, want %v", noAlerts, want)
	}

	unverified := signedParams("a@b.com", "Vintage", "Search", "Alerts")
	unverified.Set("UserEmailUnverified", "true")
	if slices.Contains(featureLinks(userFeatures(s, unverified, false)), "/alerts") {
		t.Fatal("unverified reader offered the alerts link")
	}

	if got := userFeatures(s, signedParams("", "", "Search", "Alerts"), false); got != nil {
		t.Fatalf("anonymous reader got features %v", got)
	}
}

func TestUserVarsReadTheSignature(t *testing.T) {
	withSigMode(t, false, true)
	s := newSite()
	v := signedParams("a@b.com", "Legacy", "Search")
	v.Set("UserEmailUnverified", "true")
	got := s.userVars(context.Background(), v, false)
	if !got.SignedIn || got.Name != "Elmo" || got.Email != "a@b.com" || !got.Unverified || got.Tier != "Legacy" || got.TierKey != "legacy" {
		t.Fatalf("%+v", got)
	}
	if got.Discord != (DiscordStatus{State: "unverified"}) {
		t.Fatalf("unverified, Discord %+v", got.Discord)
	}

	verified := s.userVars(context.Background(), signedParams("a@b.com", "Legacy", "Search"), false)
	if verified.Discord.State != "unavailable" {
		t.Fatalf("no alerts store, Discord %+v", verified.Discord)
	}

	staff := s.userVars(context.Background(), signedParams("a@b.com", "Admin", "Search"), false)
	if staff.Tier != "Admin" || staff.TierKey != "" {
		t.Fatalf("staff tier %q key %q", staff.Tier, staff.TierKey)
	}

	noTier := s.userVars(context.Background(), signedParams("a@b.com", "", "Search"), false)
	if noTier.Tier != "" || noTier.TierKey != "" || !noTier.SignedIn {
		t.Fatalf("%+v", noTier)
	}

	anon := s.userVars(context.Background(), url.Values{}, false)
	if anon.SignedIn || anon.Features != nil {
		t.Fatalf("%+v", anon)
	}
}

func TestContactReaderNilWithoutStore(t *testing.T) {
	if rd := newSite().contactReader(); rd != nil {
		t.Fatalf("reader %#v, want nil", rd)
	}
}

// renderUserPage renders user.html the way production does, inside the
// base the device gets.
func renderUserPage(t *testing.T, vars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("user.html", vars.IsMobile)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, baseName, vars); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func pageVarsFor(user *UserVars) PageVars {
	return PageVars{
		Title:   "BAN Account",
		Hash:    "test",
		UserNav: &NavElem{Short: user.Email},
		User:    user,
	}
}

func TestUserPageRendersSignedOut(t *testing.T) {
	showNavs(t, "Newspaper", "Alerts")
	vars := pageVarsFor(&UserVars{Tiers: tierSummaries(newSite(), fixtureACL(), "")})
	vars.PatreonLogin = true
	vars.PatreonIDs = map[string]string{"magic": "cid"}
	vars.PatreonURL = "http://localhost/auth"
	out := renderUserPage(t, vars)
	for _, want := range []string{"Log in with Patreon", "What each tier unlocks", "Everyone", "Pioneer", "Vintage", "Data one day behind", "Up to 5 alerts"} {
		if !strings.Contains(out, want) {
			t.Errorf("signed-out page lacks %q", want)
		}
	}
	for _, unwanted := range []string{"Your features", "Log out", "Your tier"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("signed-out page carries %q", unwanted)
		}
	}
}

func TestUserPageRendersSignedIn(t *testing.T) {
	user := &UserVars{
		SignedIn: true, Name: "Elmo", Email: "a@b.com", Unverified: true,
		Tier: "Legacy", TierKey: "legacy",
		Discord:  DiscordStatus{State: "linked", Handle: "@elmo"},
		Features: []UserFeature{{Name: "Price alerts", Description: "Cards you watch", Link: "/alerts"}},
		Tiers:    tierSummaries(newSite(), fixtureACL(), "Legacy"),
	}
	out := renderUserPage(t, pageVarsFor(user))
	for _, want := range []string{"a@b.com", "Unverified", "@elmo", `href="/alerts"`, "Your tier", "Log out", `data-tier="legacy"`, "https://www.patreon.com/settings/apps"} {
		if !strings.Contains(out, want) {
			t.Errorf("signed-in page lacks %q", want)
		}
	}
	if strings.Contains(out, "Log in with Patreon") {
		t.Error("signed-in page offers login")
	}

	user.Discord = DiscordStatus{State: "unlinked"}
	user.Tier, user.TierKey = "", ""
	out = renderUserPage(t, pageVarsFor(user))
	for _, want := range []string{"Not linked", ">None<"} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	user.Features = nil
	for state, want := range map[string]string{
		"pending":     "Shown after your next login",
		"unavailable": "Not available on this site",
		"unverified":  "Verify your Patreon email to show it",
	} {
		user.Discord = DiscordStatus{State: state}
		out = renderUserPage(t, pageVarsFor(user))
		for _, w := range []string{want, "Your tier grants no personal features here", "Manage on Patreon"} {
			if !strings.Contains(out, w) {
				t.Errorf("%s page lacks %q", state, w)
			}
		}
	}
	if !strings.Contains(out, "lucide") {
		t.Error("page drops the lucide bundle the settings modal needs")
	}
}

func TestUserPageRendersOnMobileBase(t *testing.T) {
	vars := pageVarsFor(&UserVars{SignedIn: true, Email: "a@b.com", Tiers: tierSummaries(newSite(), fixtureACL(), "")})
	vars.IsMobile = true
	out := renderUserPage(t, vars)
	if !strings.Contains(out, `class="light-theme mobile`) || !strings.Contains(out, "Everyone") {
		t.Fatal("mobile render lacks the mobile base or the tier table")
	}
}

// The Links strip draws Account from the nav's own entry, which every reader
// has, signed in or not, and carries its data-tool so a layout that pinned it
// to the bar can rebuild it.
func TestNavbarLinksAccountFromTheNav(t *testing.T) {
	const button = `class="tools-quick-btn" href="/user" title="Account" data-tool="account"`
	for _, sig := range []string{"", tierSig("Pioneer")} {
		pv := genPageNav(testSite, nil, "Search", sig)
		if out := renderPage(t, "search.html", false, pv); !strings.Contains(out, button) {
			t.Errorf("sig %q: the Links strip lacks the Account button", sig)
		}
	}

	pv := genPageNav(testSite, nil, "Search", "")
	pv.Nav = slices.DeleteFunc(pv.Nav, func(n NavElem) bool { return n.Name == "Account" })
	if out := renderPage(t, "search.html", false, pv); strings.Contains(out, `title="Account"`) {
		t.Error("the Links strip links Account for a nav without it")
	}
}

// The Account page shows the backpacks a tier gets once the backpack's
// size has clamped them, not the number the ACL asked for.
func TestTierPagesClampTheBackpacks(t *testing.T) {
	pages := tierPages(newSite(), map[string]map[string]string{
		"Search": {"SearchBackpackMax": "500", "SearchBackpackTabs": "5"},
	})
	if len(pages) != 1 {
		t.Fatalf("pages %+v", pages)
	}
	want := []string{"Backpack of 500 cards", "Up to 2 backpacks"}
	if !slices.Equal(pages[0].Perks, want) {
		t.Errorf("perks %v, want %v", pages[0].Perks, want)
	}
	one := tierPages(newSite(), map[string]map[string]string{
		"Search": {"SearchBackpackMax": "1000", "SearchBackpackTabs": "3"},
	})
	want = []string{"Backpack of 1000 cards"}
	if !slices.Equal(one[0].Perks, want) {
		t.Errorf("clamped to one: perks %v, want %v", one[0].Perks, want)
	}
}
