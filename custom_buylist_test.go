package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The custom buylist rule prices no card from the Collectors' Editions, 30A or
// the World Championship Decks, on upload or on search, and still prices
// everything else, those sets' sealed products included.
func TestCustomBuylistSkipsSets(t *testing.T) {
	cardID := firstPlainCard(t)
	skipped := map[string]string{}
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) && skipped[co.SetCode] == "" {
			skipped[co.SetCode] = id
		}
	}
	for _, code := range customBuylistSkipSets {
		if skipped[code] == "" {
			t.Errorf("no %s card in the datastore", code)
		}
	}
	var sealedID string
	for _, id := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(id)
		if err == nil && slices.Contains(customBuylistSkipSets, co.SetCode) {
			sealedID = id
			break
		}
	}
	if sealedID == "" {
		t.Fatal("no sealed product of a skipped set in the datastore")
	}

	rule := EntryRule{SkipSets: customBuylistSkipSets, Rate: 0.5}
	priced := func(id string) bool {
		out := map[string]map[string]*BanPrice{}
		processEntry(backend(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", id, "CUSTOM", false, false, false, rule)
		return out[id]["CUSTOM"] != nil
	}
	for code, id := range skipped {
		if priced(id) {
			t.Errorf("%s card %s priced by the custom buylist", code, id)
		}
	}
	if !priced(cardID) {
		t.Errorf("plain card %s not priced by the custom buylist", cardID)
	}
	if !priced(sealedID) {
		t.Errorf("sealed product %s not priced by the custom buylist", sealedID)
	}

	// Search prices the rule off the reference sellers the cookies name.
	singles, sealed := mtgban.InventoryRecord{}, mtgban.InventoryRecord{}
	ids := []string{cardID, sealedID}
	for _, id := range skipped {
		ids = append(ids, id)
		singles.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	}
	singles.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1})
	sealed.Add(sealedID, &mtgban.InventoryEntry{Price: 10, Quantity: 1})
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(singles, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(sealed, mtgban.ScraperInfo{Shorthand: "CKSealed", Name: "Card Kingdom Sealed", SealedMode: true}),
	}, []mtgban.Vendor{})
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	for name, value := range map[string]string{
		"UploadCustomOpts": "enabled", "UploadCustomRate": "0.5",
		"UploadCustomBuyer": "CK", "UploadCustomSealedBuyer": "CKSealed",
	} {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	found := map[string]map[mtgban.Condition][]SearchEntry{}
	searchCustomBuylist(backend(), r, ids, found)
	for code, id := range skipped {
		if found[id] != nil {
			t.Errorf("search priced %s card %s off the custom buylist", code, id)
		}
	}
	if found[cardID] == nil || found[sealedID] == nil {
		t.Errorf("search priced %v, want the plain card %s and the sealed product %s", found, cardID, sealedID)
	}
}
