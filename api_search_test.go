package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apisig"
)

// plainCard is a card with a plain name that a search path can carry.
func plainCard(t *testing.T) (id, name string) {
	t.Helper()
	plain := regexp.MustCompile(`^[A-Za-z ]+$`)
	for _, u := range backend().GetUUIDs() {
		co, err := backend().GetUUID(u)
		if err == nil && !co.Sealed && plain.MatchString(co.Name) {
			return u, co.Name
		}
	}
	t.Skip("mtgmatcher data not loaded")
	return "", ""
}

// publishStores swaps in sellers and vendors for the test.
func publishStores(t *testing.T, sellers []mtgban.Seller, vendors []mtgban.Vendor) {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

// searchStores prices one card at Card Kingdom and at Star City Games and
// returns its name.
func searchStores(t *testing.T) string {
	t.Helper()
	id, name := plainCard(t)

	priced := func(price float64) mtgban.InventoryRecord {
		inventory := mtgban.InventoryRecord{}
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: 1})
		return inventory
	}
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(priced(1), mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(priced(2), mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "CKBL", Name: "Card Kingdom Buylist"}),
	})
	return name
}

// TestSearchAPIv2 answers a search in v2's shape, with the prices the v2
// price API gives the same card keyed as v1's search keys it, narrowed by
// the search's own filters and kept to the key's stores.
func TestSearchAPIv2(t *testing.T) {
	id, name := plainCard(t)
	plain := regexp.MustCompile(`^[A-Za-z ]+$`)
	var box *mtgmatcher.CardObject
	for _, u := range backend().GetSealedUUIDs() {
		co, err := backend().GetUUID(u)
		if err == nil && plain.MatchString(co.Name) {
			box = co
			break
		}
	}
	if box == nil {
		t.Skip("no sealed product with a plain name")
	}
	sealed := mtgban.InventoryRecord{}
	sealed.Add(box.UUID, &mtgban.InventoryEntry{Price: 99, Quantity: 1})
	ck := mtgban.InventoryRecord{}
	ck.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 1, Quantity: 2})
	ck.Add(id, &mtgban.InventoryEntry{Conditions: "SP", Price: 0.8, Quantity: 1})
	scg := mtgban.InventoryRecord{}
	scg.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: 2, Quantity: 1})
	ckbl := mtgban.BuylistRecord{}
	ckbl.Add(id, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 0.5, Quantity: 3})
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(ck, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"}),
		mtgban.NewSellerFromInventory(scg, mtgban.ScraperInfo{Shorthand: "SCG", Name: "Star City Games"}),
		mtgban.NewSellerFromInventory(sealed, mtgban.ScraperInfo{Shorthand: "CKSealed", Name: "Card Kingdom Sealed", SealedMode: true}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ckbl, mtgban.ScraperInfo{Shorthand: "CKBL", Name: "Card Kingdom Buylist"}),
	})
	signingEnabled(t, false)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")

	mux := http.NewServeMux()
	mux.Handle("/api/v2/search/", enforceAPISigning(http.HandlerFunc(testSite.SearchAPI)))
	mux.Handle("/api/v2/", enforceAPISigning(http.HandlerFunc(testSite.PriceAPIv2)))
	requests := 0
	// getAs asks with a key sold modes, get with one sold every mode.
	getAs := func(modes, scope, target string) PriceAPIOutputV2 {
		t.Helper()
		key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
			API:     scope,
			Fields:  url.Values{"APImode": {modes}, "UserEmail": {"plan@example.com"}},
			Expires: time.Now().Add(time.Hour).Unix(),
		})
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		req := httptest.NewRequest(http.MethodGet, target+sep+"sig="+url.QueryEscape(key), nil)
		// The API limiter is shared and keyed on the address.
		requests++
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 100+requests)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out PriceAPIOutputV2
		err := json.Unmarshal(rec.Body.Bytes(), &out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", target, err, rec.Body.String())
		}
		return out
	}
	get := func(scope, target string) PriceAPIOutputV2 {
		t.Helper()
		return getAs("all", scope, target)
	}
	search := func(scope, mode, query string) PriceAPIOutputV2 {
		return get(scope, "/api/v2/search/"+mode+"/"+url.PathEscape(query)+".json")
	}

	for _, mode := range []string{"retail", "buylist"} {
		found := search("ALL_ACCESS", mode, name)
		priced := get("ALL_ACCESS", "/api/v2/"+mode+"/"+id+".json?id=scryfall")
		if found.Error != "" || found.Meta.Version != APIVersionV2 {
			t.Fatalf("%s: error %q, meta %+v", mode, found.Error, found.Meta)
		}
		got, want := wireOf(t, found.Retail)+wireOf(t, found.Buylist), wireOf(t, priced.Retail)+wireOf(t, priced.Buylist)
		if got != want || len(found.Retail)+len(found.Buylist) == 0 {
			t.Errorf("%s search = %s, want the price API's %s", mode, got, want)
		}
	}

	co, err := backend().GetUUID(id)
	if err != nil {
		t.Fatal(err)
	}
	key, finish := co.Identifiers["scryfallId"], v2Finish(co)
	nm := search("ALL_ACCESS", "retail", name+" cond:NM").Retail[key][finish]
	if len(nm["CK"]) != 1 || nm["CK"][0].Condition != "NM" || nm["SCG"] == nil {
		t.Errorf("cond:NM = %+v, want CK's NM alone and SCG", nm)
	}
	scoped := search("CK", "retail", name).Retail[key][finish]
	if scoped["CK"] == nil || scoped["SCG"] != nil {
		t.Errorf("a key scoped to CK reached %v", slices.Collect(maps.Keys(scoped)))
	}

	// Sealed defaults to MTGJSON ids as v1's search does, but keeps an id
	// the request asks for, where v1 forces MTGJSON
	for mode, want := range map[string]string{"": box.UUID, "name": box.Name} {
		got := get("ALL_ACCESS", "/api/v2/search/retail/sealed/"+url.PathEscape(box.Name)+".json?id="+mode).Retail
		if got[want]["sealed"]["CKSealed"] == nil {
			t.Errorf("sealed search id=%q keys %v, want %q", mode, slices.Collect(maps.Keys(got)), want)
		}
	}

	// A key sold no sealed mode reads no sealed prices, as on the price API
	noSealed := getAs("retail,buylist", "ALL_ACCESS", "/api/v2/search/retail/sealed/"+url.PathEscape(box.Name)+".json")
	if len(noSealed.Retail) > 0 || len(noSealed.Buylist) > 0 {
		t.Errorf("a key without sealed read %d sealed products", len(noSealed.Retail)+len(noSealed.Buylist))
	}

	unknown := get("ALL_ACCESS", "/api/v2/search/retail/"+url.PathEscape(name)+".json?id=tcgplayer")
	if !strings.Contains(unknown.Error, `unknown id "tcgplayer"`) || unknown.Retail != nil {
		t.Errorf("id=tcgplayer: error %q, %d cards", unknown.Error, len(unknown.Retail))
	}
}

// A key reaches the stores its plan was sold, on search as on the price
// API: the gateway forwards every plan's search here, signed with its scope.
func TestSearchAPIKeepsToTheKeysStores(t *testing.T) {
	name := searchStores(t)
	signingEnabled(t, false)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")

	handler := enforceAPISigning(http.HandlerFunc(testSite.SearchAPI))
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
	testSite.SearchAPI(rec, req)
	if !strings.Contains(rec.Body.String(), "Star City Games") {
		t.Errorf("the search page's export lost a store: %s", rec.Body.String())
	}
}

// TestSearchCSVKeepsThePageOrder exports in the order the page sorts by,
// a price sort included, rather than falling back to release order. It
// reads the sort as the page does: the query's own sort:, else the sort
// parameter, else the reader's saved default.
func TestSearchCSVKeepsThePageOrder(t *testing.T) {
	uuids, err := backend().SearchEquals("Counterspell")
	if err != nil || len(uuids) < 3 {
		t.Skip("mtgmatcher data not loaded")
	}
	sortData := resolveSortingData(backend(), uuids)
	sort.Slice(uuids, func(i, j int) bool { return cmpSets(sortData[uuids[i]], sortData[uuids[j]]) })

	// Priced up in release order, so the retail sort runs against it.
	price := map[string]float64{}
	inventory := mtgban.InventoryRecord{}
	for i, id := range uuids {
		price[id] = float64(i + 1)
		inventory.Add(id, &mtgban.InventoryEntry{Conditions: "NM", Price: price[id], Quantity: 1})
	}
	publishStores(t, []mtgban.Seller{mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "TCGMarket", Name: "TCG Market"})}, []mtgban.Vendor{})

	sig := signedAs(t, url.Values{"SearchDownloadCSV": {"true"}}, time.Now().Add(time.Hour))
	exported := func(query, sortMode, saved string) []string {
		req := httptest.NewRequest(http.MethodGet, "/api/search/retail/"+url.PathEscape(query)+".csv?id=mtgjson&sort="+sortMode, nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		if saved != "" {
			req.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: saved})
		}
		rec := httptest.NewRecorder()
		testSite.SearchAPI(rec, req)
		var ids []string
		for _, line := range strings.Split(rec.Body.String(), "\n")[1:] {
			id, _, found := strings.Cut(line, ",")
			if found {
				ids = append(ids, id)
			}
		}
		return ids
	}

	released := exported("Counterspell", "", "")
	for _, c := range []struct {
		name               string
		query, sort, saved string
	}{
		{"the sort parameter", "Counterspell", "retail", ""},
		{"the query's own sort", "Counterspell sort:retail", "", ""},
		{"the query's sort over the parameter", "Counterspell sort:retail", "chrono", ""},
		{"the saved default", "Counterspell", "", "retail"},
	} {
		got := exported(c.query, c.sort, c.saved)
		if len(got) < 3 {
			t.Fatalf("%s: exported %d printings, want several", c.name, len(got))
		}
		if !sort.SliceIsSorted(got, func(i, j int) bool { return price[got[i]] > price[got[j]] }) {
			t.Errorf("%s: the export is not dearest first: %v", c.name, got)
		}
		if slices.Equal(got, released) {
			t.Errorf("%s: the export came out in release order", c.name)
		}
	}
	got := exported("Counterspell", "chrono", "retail")
	if !slices.Equal(got, released) {
		t.Errorf("the sort parameter did not win over the saved default: %v", got)
	}
}
