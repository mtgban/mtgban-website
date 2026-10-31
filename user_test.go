package main

import (
	"context"
	"errors"
	"maps"
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
		"Any":     {"Search": {"SearchBackpackMax": "10"}, "API": {}},
		"Pioneer": {"Search": {"SearchBackpackMax": "100", "SearchChartLoopback": "720"}, "Upload": {}},
		"Modern": {
			"Search":    {},
			"Upload":    {"UploadChangeStoresEnabled": "true"},
			"Newspaper": {"NewsEnabled": "3day"},
			"Global":    {},
		},
		"Legacy": {
			"Search":    {"SearchBackpackMax": "250", "SearchBackpackTabs": "3", "SearchChartLoopback": "3650"},
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
	// A reader with no signature gets Search's defaults, never Any's flags
	defaults := []string{"Backpack of 100 cards", "Price charts back 1 month"}
	if !slices.Equal(perkLabels(everyone.Pages[0].Perks), defaults) {
		t.Fatalf("Everyone Search perks %v, want %v", perkLabels(everyone.Pages[0].Perks), defaults)
	}
	// Modern sets none of Search's flags and gets the same defaults
	if !slices.Equal(perkLabels(tiers[2].Pages[0].Perks), defaults) {
		t.Fatalf("Modern Search perks %v, want %v", perkLabels(tiers[2].Pages[0].Perks), defaults)
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
	wantPerks := []string{"Show Buylist prices", "Choose which stores to price", "Access the Optimizer"}
	if !slices.Equal(perkLabels(upload.Perks), wantPerks) {
		t.Fatalf("Upload perks %v, want %v", perkLabels(upload.Perks), wantPerks)
	}
	wantSearch := []string{"Backpack of 250 cards", "Up to 3 backpacks", "Price charts back 10 years"}
	if !slices.Equal(perkLabels(legacy.Pages[0].Perks), wantSearch) {
		t.Fatalf("Legacy Search perks %v, want %v", perkLabels(legacy.Pages[0].Perks), wantSearch)
	}
	if got := perkLabels(legacy.Pages[1].Perks); !slices.Equal(got, []string{"Data one day behind"}) {
		t.Fatalf("Newspaper perks %v", got)
	}

	for _, tier := range tiers {
		if tier.Name != "Legacy" && tier.Current {
			t.Fatalf("%s marked current", tier.Name)
		}
	}
}

// perkLabels is the pills a card shows for perks.
func perkLabels(perks []TierPerk) []string {
	var labels []string
	for _, p := range perks {
		if p.Label != "" {
			labels = append(labels, p.Label)
		}
	}
	return labels
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
	if got := perkLabels(vintage.Pages[1].Perks); !slices.Equal(got, []string{"Up to 5 alerts"}) {
		t.Fatalf("Alerts perks %v", got)
	}
}

func TestACLFlagLabels(t *testing.T) {
	cases := []struct {
		flag, value, want string
		ok                bool
	}{
		{"UploadBuylistEnabled", "true", "Show Buylist prices", true},
		{"UploadBuylistEnabled", "false", "", false},
		{"UploadBuylistEnabled", "", "", false},
		{"UploadChangeStoresEnabled", "true", "Choose which stores to price", true},
		{"UploadOptimizer", "true", "Access the Optimizer", true},
		{"UploadNoLimit", "true", "Unlimited list size", true},
		{"UploadCustom", "true", "Import custom searches", true},
		{"UploadPublish", "true", "Publish an upload as a store", true},
		{"NewsEnabled", "0day", "Same-day data", true},
		{"NewsEnabled", "1day", "Data one day behind", true},
		{"NewsEnabled", "3day", "Data three days behind", true},
		{"NewsEnabled", "7day", "", false},
		{"NewsLarge", "true", "Double the rows per page", true},
		{"SearchDownloadCSV", "true", "CSV download of results", true},
		{"SearchChartLoopback", "90", "Price charts back 3 months", true},
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
		{"AnyEnabled", "true", "Expanded store selection", true},
		{"AnyExperimentsEnabled", "true", "Experimental stores included", true},
		{"AnySpread", "true", "Spreads down to 50%", true},
		{"AnySpread", "", "", true},
		{"SleepersCYOA", "true", "Pick your own store pairing", true},
		{"SearchBackpackTabs", "3", "Up to 3 backpacks", true},
		{"SearchBackpackTabs", "1", "", true},
		{"SearchBackpackTabs", "0", "", false},
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
		got, ok := aclFlagPerk(c.flag, c.value)
		if got.Label != c.want || ok != c.ok {
			t.Errorf("aclFlagPerk(%q, %q) = %q, %v; want %q, %v", c.flag, c.value, got.Label, ok, c.want, c.ok)
		}
	}
}

// A flag's row and cell name it in the comparison: a check for one that is
// on or off, the value for one that counts or chooses.
func TestACLFlagRowsAndCells(t *testing.T) {
	cases := []struct{ flag, value, row, cell string }{
		{"UploadBuylistEnabled", "true", "Show Buylist prices", "✓"},
		{"NewsEnabled", "0day", "Data delay", "Same day"},
		{"NewsEnabled", "3day", "Data delay", "3 days"},
		{"SearchChartLoopback", "1", "Price chart history", "1 day"},
		{"SearchChartLoopback", "30", "Price chart history", "1 month"},
		{"SearchChartLoopback", "500", "Price chart history", "16 months"},
		{"SearchChartLoopback", "355", "Price chart history", "1 year"},
		{"SearchChartLoopback", "745", "Price chart history", "2 years"},
		{"SearchChartLoopback", "1800", "Price chart history", "5 years"},
		{"SearchChartLoopback", "720", "Price chart history", "2 years"},
		{"SearchBackpackMax", "250", "Backpack size", "250 cards"},
		{"SearchBackpackTabs", "3", "Number of available backpacks", "3"},
		{"SearchBackpackTabs", "1", "Number of available backpacks", "1"},
		{"SearchDisabled", "NONE", "Retail stores", "All"},
		{"SearchBuylistDisabled", "CK", "Buylists", "Some hidden"},
		{"ArbitEnabled", "ALL", "Stores", "All"},
		{"ArbitEnabled", "CK,SCG", "Stores", "2"},
		{"ArbitDisabledVendors", "CK", "Vendors", "Some excluded"},
		{"AnySpread", "true", "Lowest spread", "50%"},
		{"AnySpread", "false", "Lowest spread", "200%"},
		{"AlertsMax", "5", "Alerts", "5"},
		{"AlertChannels", "discord,email", "Delivery", "Discord and email"},
		{"APImode", "retail,buylist", "Price API modes", "retail, buylist"},
	}
	for _, c := range cases {
		got, ok := aclFlagPerk(c.flag, c.value)
		if !ok || got.Row != c.row || got.Cell != c.cell {
			t.Errorf("aclFlagPerk(%q, %q) = %q / %q, %v; want %q / %q", c.flag, c.value, got.Row, got.Cell, ok, c.row, c.cell)
		}
	}
}

// The comparison is the cards side by side: a group per page some tier
// grants, in nav order, and each perk one row whose cells line up with
// the tiers.
func TestTierComparisonLinesUpTheCards(t *testing.T) {
	showNavs(t, "Newspaper", "Alerts")
	tiers := tierSummaries(newSite(), fixtureACL(), "")
	groups := tierComparison(tiers)

	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	if want := []string{"Search", "Newspaper", "Sleepers", "Upload", "Global", "Alerts", "API"}; !slices.Equal(names, want) {
		t.Fatalf("groups %v, want %v", names, want)
	}

	// Everyone, Pioneer, Modern, Legacy, Vintage
	upload := groups[3]
	if want := []bool{false, true, true, true, true}; !slices.Equal(upload.Granted, want) {
		t.Errorf("Upload granted %v, want %v", upload.Granted, want)
	}
	if upload.Description != ExtraNavs["Upload"].Description {
		t.Errorf("Upload description %q", upload.Description)
	}
	rows := map[string][]string{}
	var order []string
	for _, r := range upload.Rows {
		rows[r.Name] = r.Cells
		order = append(order, r.Name)
	}
	// From the most tiers to the fewest, then in flag order
	if want := []string{"Choose which stores to price", "Show Buylist prices", "Unlimited list size", "Access the Optimizer"}; !slices.Equal(order, want) {
		t.Errorf("Upload rows %v, want %v", order, want)
	}
	if want := []string{"", "", "✓", "✓", ""}; !slices.Equal(rows["Choose which stores to price"], want) {
		t.Errorf("store choice cells %v, want %v", rows["Choose which stores to price"], want)
	}

	// Every tier has a backpack, and keeps one where its card says nothing
	search := map[string][]string{}
	for _, r := range groups[0].Rows {
		search[r.Name] = r.Cells
	}
	if want := []string{"100 cards", "100 cards", "100 cards", "250 cards", "100 cards"}; !slices.Equal(search["Backpack size"], want) {
		t.Errorf("backpack cells %v, want %v", search["Backpack size"], want)
	}
	if want := []string{"1", "1", "1", "3", "1"}; !slices.Equal(search["Number of available backpacks"], want) {
		t.Errorf("backpacks cells %v, want %v", search["Number of available backpacks"], want)
	}
	// Every tier with Global shows its spread floor, the grant's lower one
	global := groups[4]
	if global.Name != "Global" || global.Rows[0].Name != "Lowest spread" {
		t.Fatalf("Global rows %+v", global.Rows)
	}
	if want := []string{"", "", "200%", "200%", "50%"}; !slices.Equal(global.Rows[0].Cells, want) {
		t.Errorf("spread floor cells %v, want %v", global.Rows[0].Cells, want)
	}
	if tierComparison(nil) != nil {
		t.Error("no tiers gave groups")
	}
}

// A nav key the registry lacks, as in tests that swap in a smaller one,
// leaves its group out rather than panicking.
func TestTierComparisonSkipsUnknownNavs(t *testing.T) {
	tiers := tierSummaries(newSite(), fixtureACL(), "")
	saved := ExtraNavs
	t.Cleanup(func() { ExtraNavs = saved })
	ExtraNavs = maps.Clone(saved)
	delete(ExtraNavs, "Upload")

	var search bool
	for _, g := range tierComparison(tiers) {
		if g.Name == saved["Upload"].Name {
			t.Fatal("unknown nav kept its group")
		}
		search = search || g.Name == saved["Search"].Name
	}
	if !search {
		t.Error("the Search group went with the unknown nav")
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
	tiers := tierSummaries(newSite(), fixtureACL(), "")
	vars := pageVarsFor(&UserVars{Tiers: tiers, Compare: tierComparison(tiers)})
	vars.PatreonLogin = true
	vars.PatreonIDs = map[string]string{"magic": "cid"}
	vars.PatreonURL = "http://localhost/auth"
	out := renderUserPage(t, vars)
	for _, want := range []string{"Log in with Patreon", "What each tier unlocks", "Everyone", "Pioneer", "Vintage", "Data one day behind", "Up to 5 alerts", "Compare tiers", "<th scope=\"row\">Data delay</th>", "<td>3 days</td>", `<span class="user-compare-none" aria-hidden="true">–</span><span class="user-hidden">Not included</span>`} {
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
	user.Compare = tierComparison(user.Tiers)
	out := renderUserPage(t, pageVarsFor(user))
	for _, want := range []string{"a@b.com", "Unverified", "@elmo", `href="/alerts"`, "Your tier", "Log out", `data-tier="legacy"`, "https://www.patreon.com/settings/apps", `aria-current="true"`, `<col class="is-current">`} {
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
// size has clamped them, not the number the ACL asked for, and a size
// held to the most a backpack takes.
func TestTierPagesClampTheBackpacks(t *testing.T) {
	pages := tierPages(newSite(), map[string]map[string]string{
		"Search": {"SearchBackpackMax": "1000", "SearchBackpackTabs": "9"},
	})
	if len(pages) != 1 {
		t.Fatalf("pages %+v", pages)
	}
	want := []string{"Backpack of 1000 cards", "Up to 7 backpacks", "Price charts back 1 month"}
	if !slices.Equal(perkLabels(pages[0].Perks), want) {
		t.Errorf("perks %v, want %v", perkLabels(pages[0].Perks), want)
	}
	one := tierPages(newSite(), map[string]map[string]string{
		"Search": {"SearchBackpackMax": "5000", "SearchBackpackTabs": "1"},
	})
	want = []string{"Backpack of 1000 cards", "Price charts back 1 month"}
	if !slices.Equal(perkLabels(one[0].Perks), want) {
		t.Errorf("one backpack: perks %v, want %v", perkLabels(one[0].Perks), want)
	}
}
