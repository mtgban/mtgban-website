package offlineapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The catalog and the images manifest are not made of prices - the first is
// the datastore, the second is written by the mirror worker - but both used to
// run below the "no scrapers loaded" return, so a site whose scrapers had not
// landed served none of it. The images manifest is the half observable without
// a datastore, so it stands in for the pair.
func TestRefreshWithoutScrapersStillLoadsTheImagesManifest(t *testing.T) {
	s, dir := newTestService(t)
	s.deps.Sellers = func() []mtgban.Seller { return nil }
	s.deps.Vendors = func() []mtgban.Vendor { return nil }

	raw, err := json.Marshal(ImagesManifest{"NEO": {Hash: "abc123", Count: 302, Bytes: 24800000}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images-manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s.refreshManifest()

	if info, found := s.imagesStore.Get()["NEO"]; !found || info.Hash != "abc123" {
		t.Errorf("images manifest is %+v, want it loaded despite no scrapers", s.imagesStore.Get())
	}
}

// A catalog with no cards is not a catalog: serving one would answer a sync
// with an empty world instead of saying the server is not ready yet.
func TestCatalogIsNotBuiltWithoutCards(t *testing.T) {
	s, _ := newTestService(t)
	s.deps.Sellers = func() []mtgban.Seller { return nil }
	s.deps.Vendors = func() []mtgban.Vendor { return nil }

	s.refreshCatalog()

	if v := s.catalogVersion(); v != "" {
		t.Errorf("catalog version is %q with no datastore, want it unbuilt", v)
	}
}

// A reload in flight leaves the scrapers present but momentarily empty, so
// fingerprinting them yields no sets. Saving that would replace a good
// manifest with an empty one, and every offline client would be told there is
// nothing to sync. The recovery is worse than the outage: the next populated
// refresh would find no previous version to carry timestamps from, stamp every
// set as changed, and send every client to re-download the whole corpus.
func TestRefreshKeepsTheManifestWhenNothingIsPriced(t *testing.T) {
	s, _ := newTestService(t)

	before := manifestFile{
		Generated: "2026-08-26T14:20:01Z",
		Sets: map[string]setVersion{
			"NEO": {Fingerprint: "abc123", Version: "2026-08-26T14:20:01Z"},
			"MID": {Fingerprint: "def456", Version: "2026-08-26T14:20:01Z"},
		},
	}
	s.manifestStore.Set(before)
	t.Cleanup(func() { s.manifestStore.Set(manifestFile{}) })

	// present, but holding nothing: exactly the mid-reload window
	s.deps.Sellers = func() []mtgban.Seller { return []mtgban.Seller{emptySeller{}} }
	s.deps.Vendors = func() []mtgban.Vendor { return nil }

	s.refreshManifest()

	got := s.manifestStore.Get()
	if len(got.Sets) != 2 {
		t.Fatalf("manifest now has %d sets, want the previous 2 kept", len(got.Sets))
	}
	if got.Sets["NEO"].Version != "2026-08-26T14:20:01Z" {
		t.Errorf("NEO version = %q, want the original; a rewrite would resync every client",
			got.Sets["NEO"].Version)
	}
}

// emptySeller is a scraper that has loaded but holds no prices yet.
type emptySeller struct{}

func (emptySeller) Inventory() mtgban.InventoryRecord { return mtgban.InventoryRecord{} }
func (emptySeller) Load(context.Context) error        { return nil }
func (emptySeller) Info() mtgban.ScraperInfo          { return mtgban.ScraperInfo{Shorthand: "EMPTY"} }
