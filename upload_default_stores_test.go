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
// and returns a card and a product for them to price.
func storesOfBothKinds(t *testing.T) (card, product string) {
	t.Helper()
	keepScrapers(t)
	cards := twoCards(t)
	products := backend().GetSealedUUIDs()
	if len(products) == 0 {
		t.Skip("no datastore loaded")
	}
	card, product = cards[0], products[0]

	dev, sig := DevMode, SigCheck
	DevMode, SigCheck = true, false
	saved := affiliatesPtr.Load()
	t.Cleanup(func() {
		DevMode, SigCheck = dev, sig
		affiliatesPtr.Store(saved)
	})
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Upload") })
	}

	sealed := sessionInfo("ZZT")
	sealed.SealedMode = true
	_, err := Sessions.Publish(sessionstore.Retail, sessionInfo("ZZS"), []UploadEntry{{CardID: card, OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing the singles store: %v", err)
	}
	_, err = Sessions.Publish(sessionstore.Retail, sealed, []UploadEntry{{CardID: product, OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing the sealed store: %v", err)
	}
	return card, product
}

// uploadWithoutStores posts rows the way the handoff page does, with no store
// list, and returns the labels on the results strips.
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
	Upload(rec, req)

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
	card, _ := storesOfBothKinds(t)
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
	_, product := storesOfBothKinds(t)

	labels := uploadWithoutStores(t, product, &http.Cookie{Name: "enabledSealedSellers", Value: "ZZT|ZZGone"})
	if !slices.Contains(labels, "Session ZZT") {
		t.Fatalf("the sealed store is not priced: the strip shows %q", labels)
	}
	if slices.Contains(labels, "") {
		t.Errorf("a store that has gone is a nameless column: %q", labels)
	}
}
