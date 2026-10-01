package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
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
func withLocalDumpsBucket(t *testing.T, game mtgmatcher.Game) {
	t.Helper()
	t.Chdir(t.TempDir())

	prevGame := Config().Game
	prevBucket := DataBucket
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevIdx := scraperIndexPtr.Load()
	var noSellers []mtgban.Seller
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&noSellers)
	vendorsPtr.Store(&noVendors)
	scraperIndexPtr.Store(newScraperIndex())

	Config().Game = game
	DataBucket = &simplecloud.FileBucket{}

	t.Cleanup(func() {
		Config().Game = prevGame
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

// A datastore ping while a reload runs is queued behind it, and the reply
// names the running reload's start.
func TestLoadDatastoreQueuesBehindTheRunningReload(t *testing.T) {
	t.Setenv("BAN_SECRET", "test-secret")
	savedPath := Config().DatastorePath
	t.Cleanup(func() { Config().DatastorePath = savedPath })
	// The queued load then fails fast instead of reading a real datastore.
	Config().DatastorePath = filepath.Join(t.TempDir(), "missing.json")

	s := newSite()
	release := make(chan struct{})
	started := make(chan struct{})
	s.reloads.Start("admin", "held", func() error {
		close(started)
		<-release
		return nil
	})
	<-started
	running := s.reloads.Status()

	body := `{"ts": 1}`
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write([]byte(body))
	req := httptest.NewRequest(http.MethodPost, "/api/load/datastore", strings.NewReader(body))
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	rec := httptest.NewRecorder()
	s.LoadDatastoreFromCloud(rec, req)

	want := fmt.Sprintf(`{"status": "ok", "state": "queued", "after": %q}`, running.StartedAt.UTC().Format(time.RFC3339))
	if rec.Code != http.StatusAccepted || rec.Body.String() != want {
		t.Errorf("reply %d %s, want %d %s", rec.Code, rec.Body.String(), http.StatusAccepted, want)
	}
	if !s.reloads.Status().Queued {
		t.Error("the ping was not queued")
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for state := s.reloads.Status(); state.Running || state.Source != "api"; state = s.reloads.Status() {
		if time.Now().After(deadline) {
			t.Fatalf("status = %+v, want the queued reload to have run", state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
