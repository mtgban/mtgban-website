package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
)

// A search that finds more cards than MaxAPISearchResults answers with that
// many on the price API, v1 and v2, and in the search CSV export: each builds
// every card's offers, so the page's cap does not bound them.
func TestSearchAPIStopsAtItsCap(t *testing.T) {
	skipWithoutDatastore(t)
	inventory := mtgban.InventoryRecord{}
	buylist := mtgban.BuylistRecord{}
	for _, id := range backend().GetUUIDs() {
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 1, Quantity: 1})
		buylist.Add(id, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 0.5, Quantity: 1})
	}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: "CKBL", Name: "Card Kingdom Buylist"}),
	})
	signingEnabled(t, false)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")

	query := url.PathEscape("t:creature")
	mux := http.NewServeMux()
	mux.Handle("/api/mtgban/search/", enforceAPISigning(http.HandlerFunc(testSite.SearchAPI)))
	mux.Handle("/api/v2/search/", enforceAPISigning(http.HandlerFunc(testSite.SearchAPI)))
	key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"APImode": {"all"}, "UserEmail": {"plan@example.com"}},
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	api := func(n int, target string) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target+"?sig="+url.QueryEscape(key), nil)
		// The API limiter is shared and keyed on the address.
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 200+n)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d", target, rec.Code)
		}
		return rec.Body.Bytes()
	}

	var v1 PriceAPIOutput
	err := json.Unmarshal(api(1, "/api/mtgban/search/retail/"+query+".json"), &v1)
	if err != nil {
		t.Fatal(err)
	}
	// v1 files a card's finishes under one key
	printings := 0
	for _, stores := range v1.Retail {
		for _, price := range stores {
			for _, p := range []float64{price.Regular, price.Foil, price.Etched} {
				if p != 0 {
					printings++
				}
			}
		}
	}
	if printings != MaxAPISearchResults {
		t.Errorf("v1 answers %d printings, want %d", printings, MaxAPISearchResults)
	}

	var v2 PriceAPIOutputV2
	err = json.Unmarshal(api(2, "/api/v2/search/retail/"+query+".json"), &v2)
	if err != nil {
		t.Fatal(err)
	}
	printings = 0
	for _, finishes := range v2.Retail {
		printings += len(finishes)
	}
	if printings != MaxAPISearchResults {
		t.Errorf("v2 answers %d printings, want %d", printings, MaxAPISearchResults)
	}

	sig := signedAs(t, url.Values{"SearchDownloadCSV": {"true"}}, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/search/export/retail/"+query+".csv", nil)
	req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
	rec := httptest.NewRecorder()
	testSite.SearchExport(rec, req)
	rows := strings.Count(strings.TrimSpace(rec.Body.String()), "\n")
	if rows != MaxAPISearchResults {
		t.Errorf("the CSV export holds %d rows, want %d", rows, MaxAPISearchResults)
	}
	cut, err := strconv.Atoi(rec.Header().Get("X-MTGBAN-Cut"))
	if err != nil || cut < 1 {
		t.Errorf("the CSV export says it cut %q cards, want at least 1", rec.Header().Get("X-MTGBAN-Cut"))
	}

	req = httptest.NewRequest(http.MethodGet, "/search/export/retail/"+url.PathEscape("s:M10")+".csv", nil)
	req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
	rec = httptest.NewRecorder()
	testSite.SearchExport(rec, req)
	if rec.Header().Get("X-MTGBAN-Cut") != "" {
		t.Errorf("the CSV export of one set says it cut %s cards", rec.Header().Get("X-MTGBAN-Cut"))
	}
}

// The export counts what it leaves out from every card the search found:
// past the page's cap that is the total the search counted, and a
// decklist's repeats are not cards.
func TestExportCutCountsTheCardsLeftOut(t *testing.T) {
	keys := func(n int) []string { return make([]string, n) }
	for _, c := range []struct {
		name   string
		result searchResults
		want   int
	}{
		{"under the cap", searchResults{keys: keys(MaxAPISearchResults)}, 0},
		{"a page that fills the cap", searchResults{keys: keys(MaxSearchTotalResults)}, MaxSearchTotalResults - MaxAPISearchResults},
		{"a search past the page's cap", searchResults{keys: keys(MaxSearchTotalResults), total: 15000, message: TooManyMessage}, 15000 - MaxAPISearchResults},
		{"a decklist with repeats", searchResults{keys: keys(MaxAPISearchResults), total: MaxAPISearchResults + 40}, 0},
	} {
		got := exportCut(c.result)
		if got != c.want {
			t.Errorf("%s: cuts %d, want %d", c.name, got, c.want)
		}
	}
}
