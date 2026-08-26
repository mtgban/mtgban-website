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

// Scrapers being loaded is not the same as their holding prices: a reload in
// flight leaves them empty for a moment. Saving that empty result over a good
// manifest tells every client there is nothing to sync, and the next populated
// refresh finds no versions to carry forward, so every client re-downloads the
// whole corpus.
func TestRefreshDoesNotSaveAnEmptyManifest(t *testing.T) {
	s, _ := newTestService(t)
	before := manifestFile{Sets: map[string]setVersion{
		"NEO": {Fingerprint: "abc123", Version: "2026-08-26T14:20:01Z"},
	}}
	s.manifestStore.Set(before)
	t.Cleanup(func() { s.manifestStore.Set(manifestFile{}) })

	s.deps.Sellers = func() []mtgban.Seller { return []mtgban.Seller{emptySeller{}} }
	s.deps.Vendors = func() []mtgban.Vendor { return nil }

	s.refreshManifest()

	got := s.manifestStore.Get()
	if len(got.Sets) != 1 || got.Sets["NEO"].Version != "2026-08-26T14:20:01Z" {
		t.Errorf("manifest = %+v, want the previous one untouched", got.Sets)
	}
}

// emptySeller is a scraper that has loaded but holds no prices yet.
type emptySeller struct{}

func (emptySeller) Inventory() mtgban.InventoryRecord { return mtgban.InventoryRecord{} }
func (emptySeller) Load(context.Context) error        { return nil }
func (emptySeller) Info() mtgban.ScraperInfo          { return mtgban.ScraperInfo{Shorthand: "EMPTY"} }
