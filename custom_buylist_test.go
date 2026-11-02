package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
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
	withPrices(t, []mtgban.Seller{
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

// A rate cookie that is not a positive finite number turns the custom
// buylist off, for search and arbit alike, rather than pricing at it; such
// a minimum price is no minimum.
func TestCustomBuylistRefusesABadRate(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  float64
	}{
		{"0.5", 0.5},
		{"NaN", 0},
		{"Inf", 0},
		{"+Inf", 0},
		{"-Inf", 0},
		{"0", 0},
		{"-0.5", 0},
		{"half", 0},
	} {
		read := func(rate, minPrice string) customBuylistRule {
			r := httptest.NewRequest(http.MethodGet, "/search", nil)
			r.AddCookie(&http.Cookie{Name: "UploadCustomOpts", Value: "enabled"})
			r.AddCookie(&http.Cookie{Name: "UploadCustomRate", Value: rate})
			r.AddCookie(&http.Cookie{Name: "UploadCustomMinPrice", Value: minPrice})
			return readCustomBuylistRule(r)
		}
		rate := read(tt.value, "").rate
		if rate != tt.want {
			t.Errorf("rate cookie %q reads as %v, want %v", tt.value, rate, tt.want)
		}
		minPrice := read("0.5", tt.value).minPrice
		if minPrice != tt.want {
			t.Errorf("minimum price cookie %q reads as %v, want %v", tt.value, minPrice, tt.want)
		}
	}
}

// The custom buylist prices a card or sealed product only once it has been
// out by the rule's date, on upload and on search and arbit alike.
func TestCustomBuylistSkipsUnreleased(t *testing.T) {
	ids := []string{firstPlainCard(t), backend().GetSealedUUIDs()[0]}
	for _, id := range ids {
		co, err := backend().GetUUID(id)
		if err != nil {
			t.Fatal(err)
		}
		released, err := backend().CardReleaseDate(id)
		if err != nil {
			t.Fatal(err)
		}
		before := released.Add(-24 * time.Hour)

		if customBuylistSkips(backend(), co, released) {
			t.Errorf("%s skipped on its release date %s", id, released.Format(time.DateOnly))
		}
		if !customBuylistSkips(backend(), co, before) {
			t.Errorf("%s priced before its release date %s", id, released.Format(time.DateOnly))
		}

		priced := func(releasedBy time.Time) bool {
			out := map[string]map[string]*BanPrice{}
			rule := EntryRule{ReleasedBy: releasedBy, Rate: 0.5}
			processEntry(backend(), out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", id, "CUSTOM", false, false, false, rule)
			return out[id]["CUSTOM"] != nil
		}
		if !priced(released) || priced(before) {
			t.Errorf("%s priced %v on its release date and %v the day before, want true and false", id, priced(released), priced(before))
		}
	}
}

// A card whose set lists no release date counts as not out yet, whatever
// the rule's date.
func TestCustomBuylistSkipsUndated(t *testing.T) {
	co := &matcher.CardObject{}
	co.UUID, co.SetCode = "promo", "UND"
	b := &matcher.Backend{
		UUIDs: map[string]*matcher.CardObject{co.UUID: co},
		Sets:  map[string]*matcher.Set{"UND": {}},
	}
	releasedBy := time.Now()
	if !customBuylistSkips(b, co, releasedBy) {
		t.Error("undated card priced by the custom buylist")
	}
	out := map[string]map[string]*BanPrice{}
	processEntry(b, out, []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}, "", co.UUID, "CUSTOM", false, false, false, EntryRule{ReleasedBy: releasedBy})
	if out[co.UUID]["CUSTOM"] != nil {
		t.Error("undated card priced on upload by the custom buylist")
	}
}
