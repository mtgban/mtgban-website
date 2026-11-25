package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/banprice"
)

// gradedAPIStores loads a raw seller and a slab one of a plain card, and
// returns the card.
func gradedAPIStores(t *testing.T) string {
	t.Helper()
	skipWithoutDatastore(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	cardID := somePlainCardUUIDs(t, 1)[0]
	slab := func(price float64, quantity int, slab mtgban.Slab) mtgban.InventoryEntry {
		return mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: quantity, URL: "u", Slab: &slab}
	}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{cardID: {{Conditions: "NM", Price: 10, URL: "u"}}},
			mtgban.ScraperInfo{Name: "RAWSHOP", Shorthand: "RAWSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{cardID: {
			slab(15, 1, mtgban.Slab{Label: "SGC 9"}),
			slab(20, 1, mtgban.Slab{Grader: "CGC", Score: 10}),
			slab(25, 2, mtgban.Slab{Grader: "CGC", Score: 10}),
			slab(30, 1, mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}),
			slab(40, 1, mtgban.Slab{Grader: "PSA", Score: 9}),
			slab(12, 1, mtgban.Slab{}),
		}}, mtgban.ScraperInfo{Name: "SLABSHOP", Shorthand: "SLABSHOP", GradedMode: true}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{cardID: {{Conditions: "NM", BuyPrice: 5, URL: "u"}}},
			mtgban.ScraperInfo{Name: "RAWSHOP", Shorthand: "RAWSHOP"}),
	})
	withConfigCopy(t)
	Config().Stores.APIDemoStores = []string{"RAWSHOP", "SLABSHOP"}
	return cardID
}

func gradedAPIMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/api/mtgban/search/", http.HandlerFunc(testSite.SearchAPI))
	mux.Handle("/api/mtgban/", http.HandlerFunc(testSite.PriceAPI))
	mux.Handle("/api/v2/search/", http.HandlerFunc(testSite.SearchAPI))
	mux.Handle("/api/v2/", http.HandlerFunc(testSite.PriceAPIv2))
	return mux
}

// getBody answers a request from an address of its own: the API limiter is
// shared and keyed on it.
func getBody(mux *http.ServeMux, host int, target string) string {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", host)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Body.String()
}

// Every price endpoint and search but graded's leaves the slab seller out,
// in both versions, and graded's serve nothing else.
func TestAPIKeepsSlabsToGraded(t *testing.T) {
	cardID := gradedAPIStores(t)
	// DevMode with no signature opens every endpoint as DEV_ACCESS
	withSigMode(t, true, false)
	co, err := backend().GetUUID(cardID)
	if err != nil {
		t.Fatal(err)
	}
	mux := gradedAPIMux()
	for _, tc := range []struct {
		target    string
		raw, slab bool
	}{
		{"/api/mtgban/stores.json", true, false},
		{"/api/mtgban/stores.json?filter=singles", true, false},
		{"/api/mtgban/retail.json", true, false},
		{"/api/mtgban/retail/" + co.SetCode + ".json", true, false},
		{"/api/mtgban/retail/" + cardID + ".json", true, false},
		{"/api/mtgban/all/" + cardID + ".json", true, false},
		{"/api/mtgban/retail/" + cardID + ".csv", true, false},
		{"/api/mtgban/search/retail/" + cardID + ".json", true, false},
		{"/api/mtgban/search/retail/" + cardID + ".csv", true, false},
		{"/api/mtgban/graded/" + cardID + ".json", false, false},
		{"/api/mtgban/search/retail/graded/" + cardID + ".json", false, false},
		{"/api/v2/stores.json", true, true},
		{"/api/v2/stores.json?filter=singles", true, false},
		{"/api/v2/stores.json?filter=graded", false, true},
		{"/api/v2/retail.json", true, false},
		{"/api/v2/singles.json", true, false},
		{"/api/v2/singles/" + cardID + ".csv", false, false},
		{"/api/v2/retail/" + cardID + ".json", true, false},
		{"/api/v2/retail/" + cardID + ".json?vendor=SLABSHOP", false, false},
		{"/api/v2/search/retail/" + cardID + ".json", true, false},
		{"/api/v2/graded.json", false, true},
		{"/api/v2/graded/" + co.SetCode + ".json", false, true},
		{"/api/v2/graded/" + cardID + ".json", false, true},
		{"/api/v2/graded/" + cardID + ".json?vendor=RAWSHOP", false, false},
		{"/api/v2/graded/" + cardID + ".csv", false, false},
		{"/api/v2/search/retail/graded/" + cardID + ".json", false, true},
		{"/api/v2/search/buylist/graded/" + cardID + ".json", false, false},
		{"/api/v2/search/retail/graded/" + cardID + ".csv", false, false},
	} {
		body := getBody(mux, 1, tc.target)
		if strings.Contains(body, "RAWSHOP") != tc.raw || strings.Contains(body, "SLABSHOP") != tc.slab {
			t.Errorf("%s: want raw %v, slab %v: %s", tc.target, tc.raw, tc.slab, body)
		}
	}
}

// A slab's condition is its grade, in the Graded page's order, and only
// copies of one grade and label are one entry.
func TestAPIGradedEntries(t *testing.T) {
	cardID := gradedAPIStores(t)
	withSigMode(t, true, false)
	mux := gradedAPIMux()
	want := []banprice.Entry{
		{Condition: "PSA 9", Grader: "PSA", Score: 9, Price: 40, Qty: 1},
		{Condition: "CGC 10 Pristine", Grader: "CGC", Score: 10, Label: "Pristine", Price: 30, Qty: 1},
		{Condition: "CGC 10", Grader: "CGC", Score: 10, Price: 20, Qty: 3},
		{Condition: "Other slabs", Label: "SGC 9", Price: 15, Qty: 1},
		{Condition: "Other slabs", Price: 12, Qty: 1},
	}
	for _, target := range []string{
		"/api/v2/graded/" + cardID + ".json?id=ban",
		"/api/v2/search/retail/graded/" + cardID + ".json?id=ban",
	} {
		var out PriceAPIOutputV2
		body := getBody(mux, 1, target)
		err := json.Unmarshal([]byte(body), &out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", target, err, body)
		}
		var got []banprice.Entry
		for _, stores := range out.Retail[cardID] {
			got = append(got, stores["SLABSHOP"]...)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", target, got, want)
		}
		if len(out.Buylist) != 0 {
			t.Errorf("%s answers a buylist", target)
		}
	}
}

// A key reads the slabs its scope names with the graded mode alone.
func TestAPIGradedNeedsItsMode(t *testing.T) {
	cardID := gradedAPIStores(t)
	signingEnabled(t, true)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")
	mux := http.NewServeMux()
	mux.Handle("/api/", enforceAPISigning(gradedAPIMux()))
	requests := 0
	for _, tc := range []struct {
		scope, modes string
		want         bool
	}{
		{"ALL_ACCESS", "retail,buylist,sealed", false},
		{"ALL_ACCESS", "retail,buylist,sealed,graded", true},
		{"RAWSHOP,SLABSHOP", "graded", true},
		{"RAWSHOP", "graded", false},
	} {
		key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
			API:     tc.scope,
			Fields:  url.Values{"APImode": {tc.modes}, "UserEmail": {"plan@example.com"}},
			Expires: time.Now().Add(time.Hour).Unix(),
		})
		for _, path := range []string{"/api/v2/graded/", "/api/v2/search/retail/graded/"} {
			requests++
			body := getBody(mux, requests, path+cardID+".json?sig="+url.QueryEscape(key))
			if strings.Contains(body, "SLABSHOP") != tc.want {
				t.Errorf("%s, %s %s: want slabs %v: %s", path, tc.scope, tc.modes, tc.want, body)
			}
		}
		requests++
		body := getBody(mux, requests, "/api/v2/retail/"+cardID+".json?sig="+url.QueryEscape(key))
		if strings.Contains(body, "SLABSHOP") {
			t.Errorf("retail, %s %s: serves slabs: %s", tc.scope, tc.modes, body)
		}
	}
}
