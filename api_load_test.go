package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/simplecloud"
)

// apiLoadSig mints a signature carrying store as the page-signature "API"
// field, which is what LoadFromCloud itself checks.
func apiLoadSig(t *testing.T, store string) string {
	t.Helper()
	return signedAs(t, url.Values{"API": {store}}, time.Now().Add(time.Hour))
}

// withLocalDumpsBucket points DataBucket at a fresh temp directory, and
// resets Config.Game, the sellers, vendors and scraper index around it.
func withLocalDumpsBucket(t *testing.T, game string) {
	t.Helper()
	t.Chdir(t.TempDir())

	prevGame := Config.Game
	prevBucket := DataBucket
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevIdx := scraperIndexPtr.Load()
	var noSellers []mtgban.Seller
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&noSellers)
	vendorsPtr.Store(&noVendors)
	scraperIndexPtr.Store(newScraperIndex())

	Config.Game = game
	DataBucket = &simplecloud.FileBucket{}

	t.Cleanup(func() {
		Config.Game = prevGame
		DataBucket = prevBucket
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		scraperIndexPtr.Store(prevIdx)
	})
}

func TestLoadFromCloudLoadsEveryDumpAStoreLists(t *testing.T) {
	signingEnabled(t, false)
	withLocalDumpsBucket(t, "magic")

	now := time.Now()
	writeSellerDump(t, filepath.Join("magic", "cardkingdom", "retail", "CK.json.xz"), inventoryOf("CK", 3, now))
	writeVendorDump(t, filepath.Join("magic", "cardkingdom", "buylist", "CK.json.xz"), buylistOf("CK", 3, now))

	req := httptest.NewRequest(http.MethodGet, "/api/load/cardkingdom?sig="+apiLoadSig(t, "cardkingdom"), nil)
	w := httptest.NewRecorder()
	testSite.LoadFromCloud(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if len(GetSellers()) != 1 || GetSellers()[0].Info().Shorthand != "CK" {
		t.Errorf("sellers after load: %+v", GetSellers())
	}
	if len(GetVendors()) != 1 || GetVendors()[0].Info().Shorthand != "CK" {
		t.Errorf("vendors after load: %+v", GetVendors())
	}
	store, ok := scraperStoreOf("CK")
	if !ok || store != "cardkingdom" {
		t.Errorf("scraperStoreOf(CK) = %q, %v, want cardkingdom, true", store, ok)
	}
}

func TestLoadFromCloud404sWhenTheStoreListsNothing(t *testing.T) {
	signingEnabled(t, false)
	withLocalDumpsBucket(t, "magic")

	req := httptest.NewRequest(http.MethodGet, "/api/load/nostore?sig="+apiLoadSig(t, "nostore"), nil)
	w := httptest.NewRecorder()
	testSite.LoadFromCloud(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, body = %s, want 404", w.Code, w.Body.String())
	}
}

func TestLoadFromCloud404sOnAMismatchedSignature(t *testing.T) {
	signingEnabled(t, false)
	withLocalDumpsBucket(t, "magic")

	// Signed for a different store than the one requested.
	req := httptest.NewRequest(http.MethodGet, "/api/load/cardkingdom?sig="+apiLoadSig(t, "abugames"), nil)
	w := httptest.NewRecorder()
	testSite.LoadFromCloud(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a signature minted for a different store", w.Code)
	}
}

// Pins that LoadFromCloud drops a shorthand missing from a fresh listing,
// end to end through updateScraperIndexStore.
func TestLoadFromCloudUpdatesTheIndexToWhatItJustListed(t *testing.T) {
	signingEnabled(t, false)
	withLocalDumpsBucket(t, "magic")

	scraperIndexPtr.Store(buildScraperIndex(map[string]map[string][]string{
		"cardkingdom": {"retail": {"CKOLD"}},
	}))

	writeSellerDump(t, filepath.Join("magic", "cardkingdom", "retail", "CK.json.xz"), inventoryOf("CK", 1, time.Now()))

	req := httptest.NewRequest(http.MethodGet, "/api/load/cardkingdom?sig="+apiLoadSig(t, "cardkingdom"), nil)
	w := httptest.NewRecorder()
	testSite.LoadFromCloud(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	_, ok := scraperStoreOf("CKOLD")
	if ok {
		t.Error("CKOLD, no longer listed, is still indexed")
	}
	store, ok := scraperStoreOf("CK")
	if !ok || store != "cardkingdom" {
		t.Errorf("scraperStoreOf(CK) = %q, %v, want cardkingdom, true", store, ok)
	}
}
