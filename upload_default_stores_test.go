package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

// storesOfBothKinds serves one singles store, ZZS, and one sealed one, ZZT,
// as sellers or vendors by kind, and returns a card and a product for them to
// price.
func storesOfBothKinds(t *testing.T, kind string) (card, product string) {
	t.Helper()
	keepScrapers(t)
	cards := twoCards(t)
	products := backend().GetSealedUUIDs()
	if len(products) == 0 {
		t.Skip("no datastore loaded")
	}
	card, product = cards[0], products[0]

	withSigMode(t, true, false)
	saved := affiliatesPtr.Load()
	t.Cleanup(func() { affiliatesPtr.Store(saved) })
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Upload") })
	}

	sealed := sessionInfo("ZZT")
	sealed.SealedMode = true
	_, err := Sessions.Publish(backend(), kind, sessionInfo("ZZS"), []UploadEntry{{CardID: card, OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing the singles store: %v", err)
	}
	_, err = Sessions.Publish(backend(), kind, sealed, []UploadEntry{{CardID: product, OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing the sealed store: %v", err)
	}
	return card, product
}

// uploadWithoutStores posts rows the way the results page's own form does,
// with no store list, and returns the labels on the results strips.
func uploadWithoutStores(t *testing.T, id string, cookies ...*http.Cookie) []string {
	t.Helper()
	form := url.Values{}
	form.Set("rows", id+"\t1\t\t0\t\n")
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	testSite.Upload(rec, req)

	var labels []string
	stat := regexp.MustCompile(`<div class="res-summary-stat">\s*<span class="label">([^<]*)</span>`)
	for _, m := range stat.FindAllStringSubmatch(rec.Body.String(), -1) {
		labels = append(labels, m[1])
	}
	return labels
}

// Without a store list, a request is priced against the stores the form would
// have ticked. Those come from the affiliate list, which every deployment
// shares, so it also names sealed stores and stores this game does not carry.
func TestUploadWithoutStoresKeepsOnlySinglesSellers(t *testing.T) {
	card, _ := storesOfBothKinds(t, sessionstore.Retail)
	affiliatesPtr.Store(&AffiliatesConfig{List: []string{"ZZS", "ZZT", "ZZX"}})

	labels := uploadWithoutStores(t, card)
	if !slices.Contains(labels, "Session ZZS") {
		t.Fatalf("the singles store is not priced: the strip shows %q", labels)
	}
	if slices.Contains(labels, "Session ZZT") {
		t.Errorf("a sealed store is a column of a singles list: %q", labels)
	}
	if slices.Contains(labels, "") {
		t.Errorf("a store this game does not carry is a nameless column: %q", labels)
	}
}

// The sealed defaults are a cookie once somebody has chosen them, and a store
// named in it can have gone since.
func TestUploadWithoutStoresDropsAGoneSealedStore(t *testing.T) {
	_, product := storesOfBothKinds(t, sessionstore.Retail)

	labels := uploadWithoutStores(t, product, &http.Cookie{Name: "enabledSealedSellers", Value: "ZZT|ZZGone"})
	if !slices.Contains(labels, "Session ZZT") {
		t.Fatalf("the sealed store is not priced: the strip shows %q", labels)
	}
	if slices.Contains(labels, "") {
		t.Errorf("a store that has gone is a nameless column: %q", labels)
	}
}

// Buylist mode falls back to the vendors' cookies, and a store they name can
// have gone just the same. Without a cookie the defaults are already the
// vendors served, so only a stale one tells the filtered fallback apart.
func TestUploadWithoutStoresDropsAGoneVendor(t *testing.T) {
	card, product := storesOfBothKinds(t, sessionstore.Buylist)
	buylist := &http.Cookie{Name: "uploadMode", Value: "true"}

	for _, tc := range []struct{ id, cookie, store string }{
		{card, "enabledVendors", "ZZS"},
		{product, "enabledSealedVendors", "ZZT"},
	} {
		stale := &http.Cookie{Name: tc.cookie, Value: tc.store + "|ZZGone"}
		labels := uploadWithoutStores(t, tc.id, buylist, stale)
		if !slices.Contains(labels, "Session "+tc.store) {
			t.Fatalf("%s: the store is not priced: the strip shows %q", tc.cookie, labels)
		}
		if slices.Contains(labels, "") {
			t.Errorf("%s: a store that has gone is a nameless column: %q", tc.cookie, labels)
		}
	}
}

// The optimizer's + Add store menu offers the stores this mode could price
// against that were not picked, in the picker's order: sealed ones only for
// a list with sealed products, and none to a reader who may not change stores.
func TestFillUploadKeysAddStores(t *testing.T) {
	selected := uploadStores{
		enabledStores:       []string{"CK"},
		enabledSealedStores: []string{"CKSealed"},
		singlesSellers:      []string{"CK", "SCG", "TCGPlayer"},
		sealedSellers:       []string{"CKSealed", "TCGSealed"},
		singlesVendors:      []string{"ABUGames", "CK", "CSI"},
		sealedVendors:       []string{"CKSealed", "SZSealed"},
	}
	singles := uploadIDs{cardIDs: []string{"card"}}
	both := uploadIDs{cardIDs: []string{"card"}, sealedProductIDs: []string{"product"}}
	sealedOnly := uploadIDs{sealedProductIDs: []string{"product"}}

	tests := []struct {
		name            string
		canChange       bool
		blMode          bool
		ids             uploadIDs
		stores, sealeds []string
	}{
		{"retail singles", true, false, singles, []string{"SCG", "TCGPlayer"}, nil},
		{"retail with sealed", true, false, both, []string{"SCG", "TCGPlayer"}, []string{"TCGSealed"}},
		{"buylist with sealed", true, true, both, []string{"ABUGames", "CSI"}, []string{"SZSealed"}},
		{"sealed only", true, false, sealedOnly, nil, []string{"TCGSealed"}},
		{"cannot change stores", false, false, both, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vars := UploadVars{CanChangeStores: tc.canChange}
			fillUploadKeys(&vars, tc.blMode, selected, tc.ids, uploadPrices{}, uploadIndexes{})
			if !slices.Equal(vars.OptAddStores, tc.stores) {
				t.Errorf("OptAddStores = %v, want %v", vars.OptAddStores, tc.stores)
			}
			if !slices.Equal(vars.OptAddSealedStores, tc.sealeds) {
				t.Errorf("OptAddSealedStores = %v, want %v", vars.OptAddSealedStores, tc.sealeds)
			}
		})
	}
}
