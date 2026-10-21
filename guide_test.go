package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/palette"
)

// A store's singles and sealed scrapers share its name: CK and CKSealed are
// both "Card Kingdom". The guide gathers its stores in a map, and sorting by
// name alone left tied ones in the map's order, which changes per render, so
// a hundred renders all but ensure a wrong one if the tie is not broken.
func TestGuideStoresBreakNameTiesByShorthand(t *testing.T) {
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	store := func(name, shorthand string, sealed bool) mtgban.Seller {
		return mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{
			Name:       name,
			Shorthand:  shorthand,
			SealedMode: sealed,
		})
	}
	sellers := []mtgban.Seller{
		store("Card Kingdom", "CK", false),
		store("Card Kingdom", "CKSealed", true),
		store("Star City Games", "SCG", false),
		store("Star City Games", "SCGSealed", true),
	}
	vendors := []mtgban.Vendor{}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	want := []string{"CK", "CKSealed", "SCG", "SCGSealed"}
	for range 100 {
		var stores []GuideStore
		err := json.Unmarshal([]byte(guideStoresJSON()), &stores)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, s := range stores {
			got = append(got, s.Code)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("stores in order %v, want %v", got, want)
		}
	}
}

// The guide's store reference lists what a site search can name, so the
// stores only the price API serves are left out, sellers and vendors both.
func TestGuideStoresLeaveOutAPIOnlyStores(t *testing.T) {
	withConfigCopy(t)
	Config().Stores.APIOnlyStores = []string{"APIINDEX", "APIBUY"}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "An Index", Shorthand: "APIINDEX", MetadataOnly: true}),
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "A Buylist", Shorthand: "APIBUY"}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	var stores []GuideStore
	err := json.Unmarshal([]byte(guideStoresJSON()), &stores)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range stores {
		got = append(got, s.Code)
	}
	if !slices.Equal(got, []string{"CK"}) {
		t.Errorf("guide stores %v, want only CK", got)
	}
}

// The promo table names each type by the label the palette serves, so the
// page carries that list, and a label changed in go-mtgban reaches the guide
// with no edit here.
func TestGuideCarriesPromoLabels(t *testing.T) {
	skipWithoutDatastore(t)
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = true, false

	rec := httptest.NewRecorder()
	testSite.Guide(rec, httptest.NewRequest(http.MethodGet, "/guide", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	_, list, found := strings.Cut(rec.Body.String(), "window.__BAN_PROMOS = ")
	if !found {
		t.Fatal("page lacks the promo list")
	}
	var promos []palette.Promo
	err := json.NewDecoder(strings.NewReader(list)).Decode(&promos)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, promo := range promos {
		labels[promo.Value] = promo.Label
	}
	got := labels["boosterfun"]
	if got != "Booster Fun" {
		t.Errorf("boosterfun reads %q, want %q", got, "Booster Fun")
	}
}

// Before the first load the datastore has no palette lists, and the guide
// still renders, with an empty promo list.
func TestGuideBeforeTheFirstLoad(t *testing.T) {
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = true, false

	rec := httptest.NewRecorder()
	newSite().Guide(rec, httptest.NewRequest(http.MethodGet, "/guide", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "window.__BAN_PROMOS = [];") {
		t.Error("page lacks an empty promo list")
	}
}
