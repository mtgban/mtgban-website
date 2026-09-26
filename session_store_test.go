package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

// keepScrapers starts the test from an empty site and a fresh session-store
// registry, and puts the served snapshots, the scraper config and the
// registry back the way they were afterwards, so what TestMain loaded is
// neither counted here nor left over for the next test. Sessions is a
// package-level var precisely so a test can swap it out this way.
func keepScrapers(t *testing.T) {
	t.Helper()
	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	prevConfig := Config.ScraperConfig.Config
	prevSessions := Sessions
	var noSellers []mtgban.Seller
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&noSellers)
	vendorsPtr.Store(&noVendors)
	Sessions = sessionstore.New(sessionHooks())
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		Config.ScraperConfig.Config = prevConfig
		Sessions = prevSessions
	})
}

func sessionInfo(shorthand string) mtgban.ScraperInfo {
	return mtgban.ScraperInfo{Name: "Session " + shorthand, Shorthand: shorthand}
}

// A sealed store holds products and a singles store holds cards, the way the
// scrapers that come in pairs are split, so the rows of the other kind stay
// out and are counted. This runs against the real card database this
// package's tests load - the one thing internal/sessionstore's own,
// datastore-free tests cannot exercise on their own.
func TestFromEntriesSplitsSealedFromSinglesWithRealCards(t *testing.T) {
	if len(backend().GetSealedUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed := backend().GetSealedUUIDs()[0]
	single := randomUUID(backend(), false)
	entries := []UploadEntry{
		{CardID: sealed, OriginalPrice: 100},
		{CardID: single, OriginalPrice: 1},
	}

	for _, sealedMode := range []bool{false, true} {
		info := sessionInfo("ZZS")
		info.SealedMode = sealedMode
		scraper, report, err := sessionstore.FromEntries(sessionstore.Retail, info, entries, backend())
		if err != nil {
			t.Fatalf("sealed=%v: %s", sealedMode, err)
		}
		if report.Entries != 1 || report.OtherSide != 1 {
			t.Errorf("sealed=%v: report = %+v, want one listed and one of the other kind", sealedMode, report)
		}
		inv := scraper.(mtgban.Seller).Inventory()
		want := single
		if sealedMode {
			want = sealed
		}
		_, found := inv[want]
		if !found || len(inv) != 1 {
			t.Errorf("sealed=%v: the store holds %v, want only %s", sealedMode, inv, want)
		}
	}
}

// A published store serves beside the loaded ones through the real
// updateSellers/updateVendors path, can be published again with a different
// list, and goes away when removed - on its own side only. The shadow-check
// edge cases (case, replace, independence) have their own coverage in
// internal/sessionstore against fakes; this proves the real hooks wire up to
// the same guarantees.
func TestPublishAndRemoveSessionStore(t *testing.T) {
	keepScrapers(t)

	rows := func(n int) []UploadEntry {
		var entries []UploadEntry
		for i := range n {
			entries = append(entries, UploadEntry{CardID: "uuid-" + string(rune('a'+i)), OriginalPrice: 1})
		}
		return entries
	}

	report, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), rows(3))
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}
	if report.Entries != 3 {
		t.Errorf("report = %+v, want 3 listed", report)
	}
	inv, err := findSellerInventory("ZZS")
	if err != nil || len(inv) != 3 {
		t.Fatalf("the site serves %d cards for ZZS (err %v), want 3", len(inv), err)
	}
	if !Sessions.Is(sessionstore.Retail, "ZZS") {
		t.Error("ZZS is not registered as a session store")
	}

	_, err = Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), rows(1))
	if err != nil {
		t.Fatalf("publishing again: %s", err)
	}
	inv, _ = findSellerInventory("ZZS")
	if len(inv) != 1 {
		t.Errorf("the site serves %d cards for ZZS after the second publish, want 1", len(inv))
	}

	// The same shorthand on the other side is its own store
	_, err = Sessions.Publish(backend(), sessionstore.Buylist, sessionInfo("ZZS"), rows(2))
	if err != nil {
		t.Fatalf("publishing the buylist: %s", err)
	}
	bl, err := findVendorBuylist("ZZS")
	if err != nil || len(bl) != 2 {
		t.Fatalf("the site buys %d cards for ZZS (err %v), want 2", len(bl), err)
	}

	err = Sessions.Remove(sessionstore.Retail, "ZZS")
	if err != nil {
		t.Fatalf("removing: %s", err)
	}
	_, err = findSellerInventory("ZZS")
	if err == nil {
		t.Error("ZZS still sells after being removed")
	}
	_, err = findVendorBuylist("ZZS")
	if err != nil {
		t.Error("removing the retail side took the buylist with it")
	}
	if Sessions.Is(sessionstore.Retail, "ZZS") {
		t.Error("ZZS is still registered after being removed")
	}

	err = Sessions.Remove(sessionstore.Retail, "ZZS")
	if err == nil {
		t.Error("removing ZZS twice said ok")
	}
	err = Sessions.Remove(sessionstore.Buylist, "ZZS")
	if err != nil {
		t.Fatalf("removing the buylist: %s", err)
	}
	if len(GetVendors()) != 0 {
		t.Errorf("%d vendors still serve, want none", len(GetVendors()))
	}
}

// A session store never shadows a real one: neither a configured scraper,
// loaded or not, nor whatever is serving under that shorthand already. The
// case-insensitive matching itself is covered against fakes in
// internal/sessionstore; this proves the real hooks - isConfiguredScraper,
// GetSellers, updateSellers - deliver the same refusal.
func TestPublishSessionStoreRefusesARealStore(t *testing.T) {
	keepScrapers(t)
	Config.ScraperConfig.Config = map[string]map[string][]string{
		"cardkingdom": {"retail": {"CK"}, "buylist": {"CK"}},
	}
	err := updateSellers(inventoryOf("ZZREAL", 5, time.Now()))
	if err != nil {
		t.Fatalf("loading a real seller: %s", err)
	}
	rows := []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}}

	for _, tt := range []struct {
		kind      string
		shorthand string
	}{
		{sessionstore.Retail, "CK"},
		{sessionstore.Buylist, "CK"},
		{sessionstore.Retail, "ZZREAL"},
	} {
		_, err := Sessions.Publish(backend(), tt.kind, sessionInfo(tt.shorthand), rows)
		if err == nil {
			t.Errorf("%s/%s published over a real store", tt.kind, tt.shorthand)
		}
		if Sessions.Is(tt.kind, tt.shorthand) {
			t.Errorf("%s/%s registered as a session store", tt.kind, tt.shorthand)
		}
	}
	inv, _ := findSellerInventory("ZZREAL")
	if len(inv) != 5 {
		t.Errorf("the real seller serves %d cards after the refusals, want its 5", len(inv))
	}

	// The buylist side of ZZREAL is free: nothing serves it and nothing
	// configures it
	_, err = Sessions.Publish(backend(), sessionstore.Buylist, sessionInfo("ZZREAL"), rows)
	if err != nil {
		t.Errorf("the free side of a shorthand refused: %s", err)
	}
	err = Sessions.Remove(sessionstore.Buylist, "ZZREAL")
	if err != nil {
		t.Errorf("removing it: %s", err)
	}
	_, err = findSellerInventory("ZZREAL")
	if err != nil {
		t.Error("removing the session buylist took the real seller with it")
	}
}

// A shorthand the config claims after the store was published is a real
// store from then on: the registry may still remember it, but neither the
// dashboard's remove nor a fresh publish may touch what serves under it.
func TestSessionStoreYieldsToTheConfig(t *testing.T) {
	keepScrapers(t)
	Config.ScraperConfig.Config = map[string]map[string][]string{}
	rows := []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}}

	_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), rows)
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}
	Config.ScraperConfig.Config = map[string]map[string][]string{
		"zzs": {"retail": {"ZZS"}},
	}

	err = Sessions.Remove(sessionstore.Retail, "ZZS")
	if err == nil {
		t.Error("removed a store the config now claims")
	}
	_, err = Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), rows)
	if err == nil {
		t.Error("published over a store the config now claims")
	}
	_, err = findSellerInventory("ZZS")
	if err != nil {
		t.Error("the claimed store stopped serving")
	}
}

// The dashboard marks a session store and offers to remove it, in place of
// the refresh and the logs a scraper from the bucket has.
func TestAdminDashboardOffersToRemoveSessionStores(t *testing.T) {
	pv := PageVars{
		BetaNav: &NavElem{Short: "b"},
		Tables: [][][]string{
			{
				{"Card Kingdom", "CK", "cardkingdom", "2026-09-06T10:00:00Z", "12345", "👍", "✅", ""},
				{"Session Store", "ZZS", "session", "2026-09-06T10:00:00Z", "3", "", "✅", "retail"},
			},
			{
				{"Session Store", "ZZS", "session", "2026-09-06T10:00:00Z", "2", "", "✅", "buylist"},
			},
		},
	}
	out := renderPage(t, "admin.html", false, pv)

	for _, want := range []string{
		// Remove is a POST (unlike refresh/logs, which stay plain links,
		// matching the destructive-action convention the grant-revoke form
		// already uses on this same page) - a form per session store, not a
		// link, so removing one is never a bare GET request away.
		`<input type="hidden" name="removestore" value="ZZS">`,
		`<input type="hidden" name="kind" value="retail">`,
		`<input type="hidden" name="kind" value="buylist">`,
		`href="?refresh=cardkingdom"`,
		`href="?logs=cardkingdom"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the page does not contain %s", want)
		}
	}
	if strings.Count(out, `name="removestore" value="ZZS"`) != 2 {
		t.Errorf("got %d remove forms for ZZS, want one per side",
			strings.Count(out, `name="removestore" value="ZZS"`))
	}
	for _, absent := range []string{
		`href="?refresh=session"`,
		`href="?logs=session"`,
		`href="?removestore=`,
		`name="removestore" value="CK"`,
	} {
		if strings.Contains(out, absent) {
			t.Errorf("the page contains %s", absent)
		}
	}
}

// The remove form on the dashboard - a POST, not a link, since dropping a
// live store is a destructive action - takes the store off the site and
// comes back to the page saying so.
func TestAdminRemovesASessionStore(t *testing.T) {
	keepScrapers(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false

	_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}

	removeZZS := func() *httptest.ResponseRecorder {
		form := url.Values{"removestore": {"ZZS"}, "kind": {"retail"}}
		req := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		Admin(rec, req)
		return rec
	}

	rec := removeZZS()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirect back to the page", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "ZZS+removed") && !strings.Contains(location, "ZZS%20removed") {
		t.Errorf("redirected to %q, want the page told ZZS was removed", location)
	}
	_, err = findSellerInventory("ZZS")
	if err == nil {
		t.Error("ZZS still serves after the dashboard removed it")
	}

	rec = removeZZS()
	location = rec.Header().Get("Location")
	if !strings.Contains(location, "error") {
		t.Errorf("removing it twice redirected to %q, want an error message", location)
	}
}

// The results page offers to publish only when UploadPublish is granted, and
// the offer carries the store's properties and no list: the rows are read
// off the page.
func TestUploadResultsOfferToPublishWhenGranted(t *testing.T) {
	entries := []UploadEntry{{CardID: "uuid-a", Quantity: 1, HasQuantity: true}}
	for _, granted := range []bool{true, false} {
		out := renderUpload(t, PageVars{CanPublishStore: granted, UploadEntries: entries})
		for _, marker := range []string{"openStorePrompt()", `name="store_shorthand"`, `id="res_publishstore"`,
			`if (e.key === "Escape") closeStorePrompt();`} {
			if strings.Contains(out, marker) != granted {
				t.Errorf("granted=%v: %s present=%v", granted, marker, !granted)
			}
		}
	}

	// A list of products alone is a sealed store unless told otherwise
	sealedOnly := renderUpload(t, PageVars{CanPublishStore: true, UploadEntries: entries,
		SealedEntries: entries})
	if !strings.Contains(sealedOnly, `name="store_sealed" value="true" checked`) {
		t.Error("a sealed-only list does not default to sealed mode")
	}
	mixed := renderUpload(t, PageVars{CanPublishStore: true, UploadEntries: entries,
		SealedEntries: entries, SinglesEntries: entries})
	if strings.Contains(mixed, `name="store_sealed" value="true" checked`) {
		t.Error("a mixed list defaults to sealed mode")
	}
}

// End to end: the page posts its rows back with the store, the handler
// serves them, and shows the confirmation on the same page - not by
// redirecting to /admin, which a publisher need not be able to reach at
// all. Without the UploadPublish grant the request is an upload like any
// other.
func TestUploadPublishesAStoreWhenGranted(t *testing.T) {
	keepScrapers(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	form := url.Values{}
	form.Set("mode", "true")
	form.Set("publishstore", "true")
	form.Set("rows", "uuid-a\t2\tSP\t1.5\n"+"uuid-b\t1\t\t0\n")
	form.Set("store_name", " Session Store ")
	form.Set("store_shorthand", "ZZS")
	form.Set("store_credit", "1.25")
	form.Set("store_family", "ZZ")
	form.Set("store_qtyprio", "true")

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		Upload(rec, req)
		return rec
	}

	rec := post()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want the results page rendered in place", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1 rows listed, 1 without a price left out") {
		t.Error("the page does not show the publish confirmation")
	}

	bl, err := findVendorBuylist("ZZS")
	if err != nil {
		t.Fatal("the buylist is not served")
	}
	if len(bl) != 1 || bl["uuid-a"][0].BuyPrice != 1.5 || bl["uuid-a"][0].Quantity != 2 || bl["uuid-a"][0].Conditions != "SP" {
		t.Errorf("the buylist holds %+v", bl)
	}
	var info mtgban.ScraperInfo
	for _, vendor := range GetVendors() {
		if vendor.Info().Shorthand == "ZZS" {
			info = vendor.Info()
		}
	}
	if info.Name != "Session Store" || info.CreditMultiplier != 1.25 ||
		info.Family != "ZZ" || !info.QuantityPriority || info.SealedMode || info.MetadataOnly {
		t.Errorf("the store's info reads %+v", info)
	}

	// Without the grant the request is an upload like any other: no
	// confirmation, and nothing served
	DevMode, SigCheck = true, true
	form.Set("store_shorthand", "ZZT")
	rec = post()
	if strings.Contains(rec.Body.String(), "Published") {
		t.Error("a request without UploadPublish shows a publish confirmation")
	}
	_, err = findVendorBuylist("ZZT")
	if err == nil {
		t.Error("a request without UploadPublish published a store")
	}
}

// testSig builds a cookie value GetParamFromSig can read: a base64 query
// string carrying the given params plus a future Expires, the one field
// getSignatureFromCookies checks before handing the sig back. No HMAC is
// needed here - that check belongs to enforceSigning, which these handler
// tests call the page's own function under rather than through.
func testSig(params map[string]string) string {
	v := url.Values{}
	for key, val := range params {
		v.Set(key, val)
	}
	v.Set("Expires", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

// UploadPublish is its own grant, not a side effect of Admin: a signature
// carrying one without the other is read exactly as it says. SigCheck alone
// closes the DevMode && !SigCheck bypass every other grant in Upload also
// reads, so only the sig decides it; DevMode stays on so render's hot-reload
// path works without a prebuilt TemplateCache, which no test populates.
func TestUploadPublishGateReadsItsOwnGrant(t *testing.T) {
	keepScrapers(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, true
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	post := func(sig, shorthand string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("publishstore", "true")
		form.Set("rows", "uuid-a\t1\t\t1\n")
		form.Set("store_name", "Session Store")
		form.Set("store_shorthand", shorthand)
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		rec := httptest.NewRecorder()
		Upload(rec, req)
		return rec
	}

	rec := post(testSig(map[string]string{"Admin": "true"}), "ZZG1")
	if strings.Contains(rec.Body.String(), "Published") {
		t.Error("Admin alone published a store")
	}
	_, err := findSellerInventory("ZZG1")
	if err == nil {
		t.Error("Admin alone published a store")
	}

	rec = post(testSig(map[string]string{"UploadPublish": "true"}), "ZZG2")
	if !strings.Contains(rec.Body.String(), "Published") {
		t.Fatal("the page does not show a publish confirmation")
	}
	_, err = findSellerInventory("ZZG2")
	if err != nil {
		t.Error("UploadPublish did not publish a store")
	}
}
