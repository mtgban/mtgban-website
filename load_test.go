package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/simplecloud"
)

func TestLoadSummary(t *testing.T) {
	tests := []struct {
		name   string
		loaded int
		failed []string
		want   string
	}{
		{
			name:   "all loaded",
			loaded: 3,
			want:   "Server loaded 3/3 scrapers",
		},
		{
			name:   "unloaded scrapers still count towards the total",
			loaded: 1,
			failed: []string{"a/retail/A: no such object"},
			want: "Server loaded 1/2 scrapers\n" +
				"not loaded (1): a/retail/A: no such object",
		},
		{
			name:   "listed in a stable order whatever order they finished in",
			loaded: 0,
			failed: []string{"c/retail/C: timeout", "a/retail/A: timeout"},
			want: "Server loaded 0/2 scrapers\n" +
				"not loaded (2): a/retail/A: timeout; c/retail/C: timeout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := loadSummary(test.loaded, test.failed)
			if got != test.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, test.want)
			}
		})
	}
}

// buylistOf builds a vendor holding n cards, stamped at ts so the freshness
// check has something to compare.
func buylistOf(shorthand string, n int, ts time.Time) mtgban.Vendor {
	bl := mtgban.BuylistRecord{}
	for i := range n {
		bl[fmt.Sprintf("uuid-%d", i)] = []mtgban.BuylistEntry{{BuyPrice: 1}}
	}
	return mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, BuylistTimestamp: &ts,
	})
}

func inventoryOf(shorthand string, n int, ts time.Time) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for i := range n {
		inv[fmt.Sprintf("uuid-%d", i)] = []mtgban.InventoryEntry{{Price: 1}}
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, InventoryTimestamp: &ts,
	})
}

// An empty dump is the case the shrink check cannot see - it asks for half the
// previous size, and zero is not half of anything - so it gets its own test on
// both paths a scraper can arrive by.
func TestBuildNextVendorsRejectsEmpty(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	now := time.Now()

	t.Run("first registration", func(t *testing.T) {
		next, err := buildNextVendors(nil, buylistOf("CK", 0, now), -1)
		if err == nil {
			t.Fatalf("empty buylist registered %d vendors, want an error", len(next))
		}
	})

	t.Run("replacing a loaded one", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		_, err := buildNextVendors(current, buylistOf("CK", 0, now), 0)
		if err == nil {
			t.Fatal("empty buylist replaced 500 entries, want an error")
		}
	})

	t.Run("a full one still replaces", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		next, err := buildNextVendors(current, buylistOf("CK", 500, now), 0)
		if err != nil {
			t.Fatalf("full buylist rejected: %s", err)
		}
		if len(next[0].Buylist()) != 500 {
			t.Errorf("got %d entries, want 500", len(next[0].Buylist()))
		}
	})

	t.Run("a halved one is still rejected", func(t *testing.T) {
		current := []mtgban.Vendor{buylistOf("CK", 500, old)}
		_, err := buildNextVendors(current, buylistOf("CK", 100, now), 0)
		if err == nil {
			t.Fatal("buylist missing 80% of its entries accepted, want an error")
		}
	})
}

func TestBuildNextSellersRejectsEmpty(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	now := time.Now()

	t.Run("first registration", func(t *testing.T) {
		next, err := buildNextSellers(nil, inventoryOf("CK", 0, now), -1)
		if err == nil {
			t.Fatalf("empty inventory registered %d sellers, want an error", len(next))
		}
	})

	t.Run("replacing a loaded one", func(t *testing.T) {
		current := []mtgban.Seller{inventoryOf("CK", 500, old)}
		_, err := buildNextSellers(current, inventoryOf("CK", 0, now), 0)
		if err == nil {
			t.Fatal("empty inventory replaced 500 entries, want an error")
		}
	})

	t.Run("a full one still replaces", func(t *testing.T) {
		current := []mtgban.Seller{inventoryOf("CK", 500, old)}
		next, err := buildNextSellers(current, inventoryOf("CK", 500, now), 0)
		if err != nil {
			t.Fatalf("full inventory rejected: %s", err)
		}
		if len(next[0].Inventory()) != 500 {
			t.Errorf("got %d entries, want 500", len(next[0].Inventory()))
		}
	})
}

// The reload endpoint answers with what the install decided, so the decision
// has to travel: a refusal that only reached the notification channel left
// the endpoint reporting ok while the site went on serving what it had.
func TestUpdateAnswersTheInstall(t *testing.T) {
	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	defer func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	}()

	now := time.Now()
	old := now.Add(-time.Hour)

	err := updateVendors(buylistOf("ZZV", 500, now))
	if err != nil {
		t.Fatalf("first registration refused: %s", err)
	}
	err = updateVendors(buylistOf("ZZV", 500, old))
	if err == nil {
		t.Fatal("older buylist installed, want the refusal answered")
	}
	for _, vendor := range GetVendors() {
		if vendor.Info().Shorthand == "ZZV" && !vendor.Info().BuylistTimestamp.Equal(now) {
			t.Error("refused buylist replaced the served one anyway")
		}
	}

	err = updateSellers(inventoryOf("ZZS", 500, now))
	if err != nil {
		t.Fatalf("first registration refused: %s", err)
	}
	err = updateSellers(inventoryOf("ZZS", 0, now))
	if err == nil {
		t.Fatal("empty inventory installed, want the refusal answered")
	}
}

func TestParseDumpKey(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		wantStore     string
		wantKind      string
		wantShorthand string
		wantOK        bool
	}{
		{
			name: "a retail dump", key: "magic/cardkingdom/retail/CK.json.xz",
			wantStore: "cardkingdom", wantKind: "retail", wantShorthand: "CK", wantOK: true,
		},
		{
			name: "a buylist dump", key: "magic/cardkingdom/buylist/CK.json.xz",
			wantStore: "cardkingdom", wantKind: "buylist", wantShorthand: "CK", wantOK: true,
		},
		{name: "a different game's prefix", key: "lorcana/coolstuffinc/retail/CSI.json.xz"},
		{name: "a kind that is neither retail nor buylist", key: "magic/cardkingdom/graded/CK.json.xz"},
		{name: "an extension other than json.xz", key: "magic/cardkingdom/retail/CK.json"},
		{name: "too few path segments", key: "magic/cardkingdom/CK.json.xz"},
		{name: "too many path segments", key: "magic/cardkingdom/retail/sub/CK.json.xz"},
		{name: "no filename at all", key: "magic/cardkingdom/retail/.json.xz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, kind, shorthand, ok := parseDumpKey(tt.key, "magic")
			if ok != tt.wantOK || store != tt.wantStore || kind != tt.wantKind || shorthand != tt.wantShorthand {
				t.Errorf("parseDumpKey(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
					tt.key, store, kind, shorthand, ok,
					tt.wantStore, tt.wantKind, tt.wantShorthand, tt.wantOK)
			}
		})
	}
}

// writeSellerDump writes seller to path (relative to the current directory)
// the way loadScraper reads it back, xz-compressed for the .json.xz suffix.
func writeSellerDump(t *testing.T, path string, seller mtgban.Seller) {
	t.Helper()
	w, err := simplecloud.InitWriter(context.Background(), &simplecloud.FileBucket{}, path)
	if err != nil {
		t.Fatal(err)
	}
	err = mtgban.WriteSellerToJSON(seller, w)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// writeVendorDump is writeSellerDump for the buylist side.
func writeVendorDump(t *testing.T, path string, vendor mtgban.Vendor) {
	t.Helper()
	w, err := simplecloud.InitWriter(context.Background(), &simplecloud.FileBucket{}, path)
	if err != nil {
		t.Fatal(err)
	}
	err = mtgban.WriteVendorToJSON(vendor, w)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// t.Chdir stands in for the bucket root: a FileBucket resolves keys relative
// to the process's current directory.
func TestListDumpsLocalDirectory(t *testing.T) {
	t.Chdir(t.TempDir())

	writeSellerDump(t, filepath.Join("magic", "cardkingdom", "retail", "CK.json.xz"), inventoryOf("CK", 3, time.Now()))
	writeVendorDump(t, filepath.Join("magic", "cardkingdom", "buylist", "CK.json.xz"), buylistOf("CK", 3, time.Now()))
	writeSellerDump(t, filepath.Join("magic", "sealed_ev", "retail", "CKEV.json.xz"), inventoryOf("CKEV", 1, time.Now()))
	// Stray, unrecognized entries a real bucket could hold, none of which
	// should stop the listing or appear in the result.
	writeSellerDump(t, filepath.Join("magic", "cardkingdom", "graded", "CKG.json.xz"), inventoryOf("CKG", 1, time.Now()))
	err := os.MkdirAll("magic", 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join("magic", "README.txt"), []byte("not a dump"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	writeSellerDump(t, filepath.Join("lorcana", "coolstuffinc", "retail", "CSI.json.xz"), inventoryOf("CSI", 1, time.Now()))

	idx, err := listDumps(context.Background(), &simplecloud.FileBucket{}, "magic", "magic/")
	if err != nil {
		t.Fatalf("listDumps: %v", err)
	}

	if !slices.Equal(idx.byStore["cardkingdom"]["retail"], []string{"CK"}) {
		t.Errorf("cardkingdom retail = %v, want [CK]", idx.byStore["cardkingdom"]["retail"])
	}
	if !slices.Equal(idx.byStore["cardkingdom"]["buylist"], []string{"CK"}) {
		t.Errorf("cardkingdom buylist = %v, want [CK]", idx.byStore["cardkingdom"]["buylist"])
	}
	if !slices.Equal(idx.byStore["sealed_ev"]["retail"], []string{"CKEV"}) {
		t.Errorf("sealed_ev retail = %v, want [CKEV]", idx.byStore["sealed_ev"]["retail"])
	}
	if _, found := idx.byStore["cardkingdom"]["graded"]; found {
		t.Error("the graded/ stray key was not skipped")
	}
	if _, found := idx.byStore["coolstuffinc"]; found {
		t.Error("lorcana's dump leaked into a magic-prefixed listing")
	}
	if got, want := idx.byShorthand["CK"], "cardkingdom"; got != want {
		t.Errorf("byShorthand[CK] = %q, want %q", got, want)
	}
}

// The end-to-end path: loadScrapersNG lists a local directory, installs each
// dump through the existing WorkerPool/loadScraper path, and publishes the
// index alongside the served sellers/vendors.
func TestLoadScrapersNGFromLocalDirectory(t *testing.T) {
	t.Chdir(t.TempDir())

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevIdx := scraperIndexPtr.Load()
	prevGame := Config.Game
	var noSellers []mtgban.Seller
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&noSellers)
	vendorsPtr.Store(&noVendors)
	Config.Game = "magic"
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		scraperIndexPtr.Store(prevIdx)
		Config.Game = prevGame
	})

	now := time.Now()
	writeSellerDump(t, filepath.Join("magic", "cardkingdom", "retail", "CK.json.xz"), inventoryOf("CK", 3, now))
	writeVendorDump(t, filepath.Join("magic", "cardkingdom", "buylist", "CK.json.xz"), buylistOf("CK", 3, now))
	writeSellerDump(t, filepath.Join("magic", "abugames", "retail", "ABU.json.xz"), inventoryOf("ABU", 2, now))

	err := loadScrapersNG(&simplecloud.FileBucket{})
	if err != nil {
		t.Fatalf("loadScrapersNG: %v", err)
	}

	sellers := GetSellers()
	if len(sellers) != 2 {
		t.Fatalf("got %d sellers, want 2: %+v", len(sellers), sellers)
	}
	vendors := GetVendors()
	if len(vendors) != 1 || vendors[0].Info().Shorthand != "CK" {
		t.Fatalf("got %d vendors, want 1 CK: %+v", len(vendors), vendors)
	}
	store, ok := scraperStoreOf("ABU")
	if !ok || store != "abugames" {
		t.Errorf("scraperStoreOf(ABU) = %q, %v, want abugames, true", store, ok)
	}
	store, ok = scraperStoreOf("CK")
	if !ok || store != "cardkingdom" {
		t.Errorf("scraperStoreOf(CK) = %q, %v, want cardkingdom, true", store, ok)
	}
}

// A fresh listing replaces one store's entries and leaves every other
// store alone.
func TestUpdateScraperIndexStoreReplacesOnlyThatStore(t *testing.T) {
	prevIdx := scraperIndexPtr.Load()
	t.Cleanup(func() { scraperIndexPtr.Store(prevIdx) })

	scraperIndexPtr.Store(buildScraperIndex(map[string]map[string][]string{
		"cardkingdom": {"retail": {"CK"}, "buylist": {"CKBLLast"}},
		"abugames":    {"retail": {"ABU"}},
	}))

	// cardkingdom's fresh listing dropped CKBLLast and picked up a new
	// retail-only shorthand.
	updateScraperIndexStore("cardkingdom", map[string][]string{"retail": {"CK", "CKNew"}})

	idx := currentScraperIndex()
	if !slices.Equal(idx.byStore["cardkingdom"]["retail"], []string{"CK", "CKNew"}) {
		t.Errorf("cardkingdom retail = %v, want [CK CKNew]", idx.byStore["cardkingdom"]["retail"])
	}
	if _, found := idx.byStore["cardkingdom"]["buylist"]; found {
		t.Error("cardkingdom's dropped buylist kind is still indexed")
	}
	if _, found := idx.byShorthand["CKBLLast"]; found {
		t.Error("the dropped shorthand still resolves in the reverse index")
	}
	if got, want := idx.byShorthand["CKNew"], "cardkingdom"; got != want {
		t.Errorf("byShorthand[CKNew] = %q, want %q", got, want)
	}
	// abugames was not touched by cardkingdom's update.
	if !slices.Equal(idx.byStore["abugames"]["retail"], []string{"ABU"}) {
		t.Errorf("abugames retail = %v, want [ABU]", idx.byStore["abugames"]["retail"])
	}
}

// Reloading one store gives it a shared shorthand; reloading an unrelated
// store, however many times, must never move it.
func TestUpdateScraperIndexStoreLeavesASharedShorthandsOwnerAlone(t *testing.T) {
	prevIdx := scraperIndexPtr.Load()
	t.Cleanup(func() { scraperIndexPtr.Store(prevIdx) })

	scraperIndexPtr.Store(buildScraperIndex(map[string]map[string][]string{
		"tcg_index":  {"retail": {"MKMLow"}},
		"cardmarket": {"retail": {"MKMLow"}},
		"abugames":   {"retail": {"ABU"}},
	}))

	updateScraperIndexStore("cardmarket", map[string][]string{"retail": {"MKMLow"}})
	if got, want := currentScraperIndex().byShorthand["MKMLow"], "cardmarket"; got != want {
		t.Fatalf("byShorthand[MKMLow] = %q after cardmarket's own reload, want %q", got, want)
	}

	for i := range 5 {
		updateScraperIndexStore("abugames", map[string][]string{"retail": {"ABU"}})
		if got, want := currentScraperIndex().byShorthand["MKMLow"], "cardmarket"; got != want {
			t.Fatalf("byShorthand[MKMLow] = %q after abugames reload #%d, want %q unchanged", got, i, want)
		}
	}
}
