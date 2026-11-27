package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/timeseries"
)

// languageCopyOf returns a nonfoil printing of set carrying an identifier
// that names a card of another set in space, and that card.
func languageCopyOf(t *testing.T, set, identifier string, space matcher.IDSpace) (*matcher.CardObject, *matcher.CardObject) {
	t.Helper()
	b := backend()
	for _, uuid := range b.GetUUIDsInSet(set) {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Foil {
			continue
		}
		original := originalOf(b, space, co.Identifiers[identifier], co)
		if original != nil {
			return co, original
		}
	}
	t.Fatalf("no card of %s carries the %s of another set's card", set, identifier)
	return nil, nil
}

// TestAPIKeepsLanguageCopiesOffTheirOriginalsIDs checks that a price of a
// language copy answers under the id of the card it is a copy of only for a
// request in its language, which the original's price gives way to.
func TestAPIKeepsLanguageCopiesOffTheirOriginalsIDs(t *testing.T) {
	skipWithoutDatastore(t)
	for _, tc := range []struct {
		set, mode, identifier string
		space                 matcher.IDSpace
		lang                  string
	}{
		{"FWB", "mtgjson", "mtgjsonId", matcher.IDSpaceMTGJSON, ""},
		{"LEGITA", "mtgjson", "mtgjsonId", matcher.IDSpaceMTGJSON, ""},
		{"FBBFR", "scryfall", "scryfallId", matcher.IDSpaceScryfall, ""},
		{"4BBES", "scryfall", "scryfallId", matcher.IDSpaceScryfall, ""},
		{"4BBPT", "mtgjson", "mtgjsonId", matcher.IDSpaceMTGJSON, "Portuguese"},
		{"4BBPT", "mtgjson", "mtgjsonId", matcher.IDSpaceMTGJSON, ""},
	} {
		t.Run(tc.set+" "+tc.mode, func(t *testing.T) {
			co, original := languageCopyOf(t, tc.set, tc.identifier, tc.space)
			id := original.Identifiers[tc.identifier]

			inv := mtgban.InventoryRecord{}
			inv.Add(original.UUID, &mtgban.InventoryEntry{Conditions: "NM", Price: 700, Quantity: 1, URL: "u"})
			inv.Add(co.UUID, &mtgban.InventoryEntry{Conditions: "NM", Price: 300, Quantity: 1, URL: "u"})
			bl := mtgban.BuylistRecord{}
			bl.Add(original.UUID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 200, Quantity: 1, URL: "u"})
			bl.Add(co.UUID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 250, Quantity: 1, URL: "u"})
			withPrices(t, []mtgban.Seller{
				mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Copies", Shorthand: "COPIES"}),
			}, []mtgban.Vendor{
				mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Name: "Copies", Shorthand: "COPIES"}),
			})
			b, p, stores := backend(), currentPrices(), []string{"COPIES"}

			if co.Language == "" {
				t.Fatalf("%s names no language", co)
			}
			// The original's prices, then the copy's for a request in its language
			for _, want := range []struct {
				lang           string
				retail, bought float64
			}{{"", 700, 200}, {"Ancient Greek", 700, 200}, {cmp.Or(tc.lang, co.Language), 300, 250}} {
				for _, hashes := range [][]string{nil, {original.UUID, co.UUID}} {
					retail := getSellerPrices(b, p, tc.mode, want.lang, stores, "", hashes, "", true, true, false, "")
					if len(retail) != 1 || retail[id]["COPIES"] == nil || retail[id]["COPIES"].Regular != want.retail {
						t.Errorf("%q: retail of %v = %v, want %s alone at %v", want.lang, hashes, retail, id, want.retail)
					}
					buylist := getVendorPrices(b, p, tc.mode, want.lang, stores, "", hashes, "", true, true, false, "")
					if len(buylist) != 1 || buylist[id]["COPIES"] == nil || buylist[id]["COPIES"].Regular != want.bought {
						t.Errorf("%q: buylist of %v = %v, want %s alone at %v", want.lang, hashes, buylist, id, want.bought)
					}
				}
				v2 := collectV2(t, b, sellerSectionV2(b, p, tc.mode, want.lang, stores, "", nil, "", false))
				entries := v2[id][v2Finish(co)]["COPIES"]
				if len(v2) != 1 || len(entries) != 1 || entries[0].Price != want.retail {
					t.Errorf("%q: v2 retail = %v, want %s alone at %v", want.lang, v2, id, want.retail)
				}
				// History keys its series by the same rule
				answers := original
				if want.retail == 300 {
					answers = co
				}
				for _, card := range []*matcher.CardObject{original, co} {
					got := getIDFromMode(b, p, tc.mode, want.lang, card)
					if (card == answers) != (got == id) || (card != answers && got != "") {
						t.Errorf("%q: %s answers %q", want.lang, card, got)
					}
				}
			}
			if got := getIDFromMode(b, p, "ban", "", co); got != co.UUID {
				t.Errorf("the copy's own id = %q, want %q", got, co.UUID)
			}
		})
	}
}

// TestAPIKeepsIDsSharedInOneSet checks that a finish filed as a card of its
// own answers the id it shares with a card of its set.
func TestAPIKeepsIDsSharedInOneSet(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	for _, uuid := range b.GetUUIDsInSet("SLD") {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Foil || co.Etched {
			continue
		}
		id := co.Identifiers["mtgjsonId"]
		shared := b.ConvertID(matcher.IDSpaceMTGJSON, id)
		other, err := b.GetUUID(shared)
		if err != nil || shared == co.UUID || other.Number == co.Number {
			continue
		}
		if got := getIDFromMode(b, currentPrices(), "mtgjson", "", co); got != id {
			t.Errorf("%s answers %q, want the %q it shares with %s", co, got, id, other)
		}
		return
	}
	t.Skip("no card of SLD shares its id with another of the set")
}

// TestAPILanguage checks a request's language, named by code or by name.
func TestAPILanguage(t *testing.T) {
	for in, want := range map[string]string{"": "", "en": "", "English": "", "de": "German", "german": "German", "PT": "Portuguese", "Chinese Simplified": "Chinese Simplified"} {
		got, err := apiLanguage(in)
		if err != nil || got != want {
			t.Errorf("%q = %q, %v, want %q", in, got, err, want)
		}
	}
	if _, err := apiLanguage("Klingon"); err == nil {
		t.Error("Klingon was taken as a language")
	}
}

// TestLanguageCopySetsListEveryCopy checks that languageCopySet names every
// set holding a copy of another set's card, and the sets of those cards.
func TestLanguageCopySetsListEveryCopy(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	missing := map[string]bool{}
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil {
			continue
		}
		for space, field := range map[matcher.IDSpace]string{matcher.IDSpaceMTGJSON: "mtgjsonId", matcher.IDSpaceScryfall: "scryfallId"} {
			original := originalOf(b, space, co.Identifiers[field], co)
			if original == nil {
				continue
			}
			for _, set := range []string{co.SetCode, original.SetCode} {
				if !languageCopySet(set) {
					missing[set] = true
				}
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("languageCopySet lacks %v", slices.Sorted(maps.Keys(missing)))
	}
}

// TestSharedLanguage checks the language a request naming none reads its
// cards in: theirs when they share one other than English.
func TestSharedLanguage(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	both := slices.Concat(b.GetUUIDsInSet("FBB"), b.GetUUIDsInSet("FBBFR"))
	for _, tc := range []struct {
		name  string
		uuids []string
		want  string
	}{
		{"FBBFR", b.GetUUIDsInSet("FBBFR"), "French"},
		{"4BBPT", b.GetUUIDsInSet("4BBPT"), "Portuguese (Brazil)"},
		{"FBB", b.GetUUIDsInSet("FBB"), ""},
		{"FBB and FBBFR", both, ""},
		{"FBBFR and 4BBES", slices.Concat(b.GetUUIDsInSet("FBBFR"), b.GetUUIDsInSet("4BBES")), ""},
		{"none", nil, ""},
	} {
		if got := sharedLanguage(b, tc.uuids); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestAPIReadsALanguageCopySetInItsLanguage checks that a request naming no
// language finds a copy under the id it shares with its original where it
// asks for that copy's set alone, on search, the price API and history,
// and finds the original where it asks for both.
func TestAPIReadsALanguageCopySetInItsLanguage(t *testing.T) {
	skipWithoutDatastore(t)
	co, original := languageCopyOf(t, "FBBFR", "scryfallId", matcher.IDSpaceScryfall)
	id := original.Identifiers["scryfallId"]
	inv := mtgban.InventoryRecord{}
	inv.Add(original.UUID, &mtgban.InventoryEntry{Conditions: "NM", Price: 700, Quantity: 1, URL: "u"})
	inv.Add(co.UUID, &mtgban.InventoryEntry{Conditions: "NM", Price: 300, Quantity: 1, URL: "u"})
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Copies", Shorthand: "COPIES"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Copies", Shorthand: "COPIES"}),
	})
	signingEnabled(t, false)
	withAPIUserSecret(t, "plan@example.com", "plan-secret")
	key := apisig.Mint([]byte("plan-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"APImode": {"all"}, "UserEmail": {"plan@example.com"}},
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	requests := 0
	retail := func(handler http.HandlerFunc, target string) float64 {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target+"&sig="+url.QueryEscape(key), nil)
		// The API limiter is shared and keyed on the address.
		requests++
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 120+requests)
		rec := httptest.NewRecorder()
		enforceAPISigning(handler).ServeHTTP(rec, req)
		var out PriceAPIOutputV2
		err := json.Unmarshal(rec.Body.Bytes(), &out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", target, err, rec.Body.String())
		}
		entries := out.Retail[id][v2Finish(co)]["COPIES"]
		if len(out.Retail) != 1 || len(entries) != 1 {
			t.Errorf("%s: %v, want %s alone", target, out.Retail, id)
			return 0
		}
		return entries[0].Price
	}
	for _, tc := range []struct {
		handler http.HandlerFunc
		target  string
		want    float64
	}{
		{testSite.SearchAPI, "/api/v2/search/retail/" + url.PathEscape(co.Name+" s:FBBFR") + ".json?id=scryfall", 300},
		{testSite.SearchAPI, "/api/v2/search/retail/" + url.PathEscape(co.Name) + ".json?id=scryfall", 700},
		{testSite.PriceAPIv2, "/api/v2/retail/FBBFR.json?id=scryfall", 300},
		{testSite.PriceAPIv2, "/api/v2/retail/" + co.UUID + ".json?id=scryfall", 300},
		{testSite.PriceAPIv2, "/api/v2/retail/" + original.UUID + ".json?id=scryfall", 700},
	} {
		if got := retail(tc.handler, tc.target); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.target, got, tc.want)
		}
	}

	historyFixture(t, map[int64]map[string]timeseries.ProviderPrices{
		1: {"2026-10-06": {1: 7}},
		2: {"2026-10-06": {1: 3}},
	}, nil)
	historyBanID = func(card *matcher.CardObject) int64 {
		return map[string]int64{original.UUID: 1, co.UUID: 2}[card.UUID]
	}
	days := 365
	page := slices.Index(backend().GetUUIDsInSet("FBBFR"), co.UUID)/historyCardsAllowed(days) + 1
	for _, target := range []string{
		"/api/v2/history/" + co.UUID + ".json",
		fmt.Sprintf("/api/v2/history/FBBFR.json?page=%d", page),
	} {
		_, out := historyGet(t, testSite, target, "history", strconv.Itoa(days), nil)
		ck := out.Retail[id][v2Finish(co)]["CK"]
		if out.Error != "" || ck == nil || !slices.Equal(ck.Prices, []float64{3}) {
			t.Errorf("%s: %q %v, want %s at 3", target, out.Error, out.Retail, id)
		}
	}
}
