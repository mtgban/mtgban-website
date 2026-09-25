package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
)

// searchStores prices one card at Card Kingdom and at Star City Games and
// returns its name, with a plain name that a search path can carry.
func searchStores(t *testing.T) string {
	t.Helper()
	plain := regexp.MustCompile(`^[A-Za-z ]+$`)
	var id, name string
	for _, u := range backend().GetUUIDs() {
		co, err := backend().GetUUID(u)
		if err == nil && !co.Sealed && plain.MatchString(co.Name) {
			id, name = u, co.Name
			break
		}
	}
	if id == "" {
		t.Skip("mtgmatcher data not loaded")
	}

	priced := func(price float64) mtgban.InventoryRecord {
		inventory := mtgban.InventoryRecord{}
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: 1})
		return inventory
	}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(priced(1), mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(priced(2), mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}),
	}
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CKBL", Name: "Card Kingdom Buylist"}),
	}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	return name
}

// A key reaches the stores its plan was sold, on search as on the price
// API: the gateway forwards every plan's search here, signed with its scope.
func TestSearchAPIKeepsToTheKeysStores(t *testing.T) {
	name := searchStores(t)
	signingEnabled(t, false)
	apiUsersMutex.Lock()
	if Config.APIUserSecrets == nil {
		Config.APIUserSecrets = map[string]string{}
	}
	Config.APIUserSecrets["plan@example.com"] = "plan-secret"
	apiUsersMutex.Unlock()
	t.Cleanup(func() {
		apiUsersMutex.Lock()
		delete(Config.APIUserSecrets, "plan@example.com")
		apiUsersMutex.Unlock()
	})

	handler := enforceAPISigning(http.HandlerFunc(SearchAPI))
	requests := 0
	// A key scoped to scope, or none at all when scope is empty.
	search := func(scope, cookie string) string {
		target := "/api/mtgban/search/retail/" + url.PathEscape(name) + ".json"
		if scope != "" {
			key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
				API:     scope,
				Fields:  url.Values{"APImode": {"all"}, "UserEmail": {"plan@example.com"}},
				Expires: time.Now().Add(time.Hour).Unix(),
			})
			target += "?sig=" + url.QueryEscape(key)
		}
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		}
		// The API limiter is shared and keyed on the address.
		requests++
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 40+requests)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}

	for _, scope := range []string{"CK", "ALL_ACCESS"} {
		body := search(scope, "")
		if !strings.Contains(body, "Card Kingdom") {
			t.Fatalf("%s: a store in scope is missing: %s", scope, body)
		}
		if strings.Contains(body, "Star City Games") != (scope == "ALL_ACCESS") {
			t.Errorf("%s: Star City Games shown %v", scope, strings.Contains(body, "Star City Games"))
		}
	}

	// The middleware checked the key, not a cookie sent beside it.
	forged := base64.StdEncoding.EncodeToString([]byte("API=ALL_ACCESS&Expires=99999999999"))
	body := search("CK", forged)
	if !strings.Contains(body, "Card Kingdom") || strings.Contains(body, "Star City Games") {
		t.Errorf("a forged cookie widened a key scoped to CK: %s", body)
	}

	// A reader's own signature is not a key, even where its tier grants the
	// API page, which signs as API=true: once it verifies, it keeps the
	// site's store policy.
	site := signedAs(t, url.Values{"UserEmail": {"sub@example.com"}, "API": {"true"}}, time.Now().Add(time.Hour))
	if !strings.Contains(search("", site), "Star City Games") {
		t.Error("a checked site signature lost a store it is shown on the site")
	}

	// A key's signature can sit in the cookie too, put there by a page it
	// opened, and its scope holds there as well.
	keyCookie := signedAs(t, url.Values{"UserEmail": {"key@example.com"}, "APImode": {"all"}, "API": {"CK"}}, time.Now().Add(time.Hour))
	body = search("", keyCookie)
	if !strings.Contains(body, "Card Kingdom") || strings.Contains(body, "Star City Games") {
		t.Errorf("a key's scope was dropped when it came in the cookie: %s", body)
	}

	// The site's own export is not a key, and keeps every store it shows.
	sig := signedAs(t, url.Values{"SearchDownloadCSV": {"true"}}, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api/search/retail/"+url.PathEscape(name)+".csv", nil)
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	rec := httptest.NewRecorder()
	SearchAPI(rec, req)
	if !strings.Contains(rec.Body.String(), "Star City Games") {
		t.Errorf("the search page's export lost a store: %s", rec.Body.String())
	}
}
