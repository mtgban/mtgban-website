package main

import (
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// storeNameCell reads the store named on each price row, locked or not.
var storeNameCell = regexp.MustCompile(`class="store-name[^"]*"[^>]*>([^<]+)<`)

// Only a signed-in user may reorder each card's stores or use the stores that
// are not affiliates: logged out, the stores are listed by name whatever the
// listing priority cookie asks for, the other stores locked or, under
// search_hide_non_affiliates, left out. The server-side modal data (the settings body's own render pins the
// markup in TestSettingsBodyDrawsListingLocked) marks the pills locked rather
// than bound to that cookie.
func TestListingPriorityNeedsASignature(t *testing.T) {
	skipWithoutDatastore(t)
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}

	// Name order and price order disagree on both sides.
	uuid := backend().GetUUIDs()[0]
	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor
	for _, store := range []struct {
		name       string
		retail     float64
		buy        float64
		shorthands [2]string
	}{
		{"Alpha", 20, 10, [2]string{"ZZA", "ZZC"}},
		{"Beta", 10, 20, [2]string{"ZZB", "ZZD"}},
		{"Gamma", 15, 15, [2]string{"ZZE", "ZZF"}},
	} {
		inventory := mtgban.InventoryRecord{}
		err := inventory.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: store.retail, Quantity: 1, URL: "https://example.test"})
		if err != nil {
			t.Fatal(err)
		}
		buylist := mtgban.BuylistRecord{}
		err = buylist.Add(uuid, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: store.buy, Quantity: 1, URL: "https://example.test"})
		if err != nil {
			t.Fatal(err)
		}
		sellers = append(sellers, mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Name: store.name + " Seller", Shorthand: store.shorthands[0]}))
		vendors = append(vendors, mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Name: store.name + " Vendor", Shorthand: store.shorthands[1]}))
	}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	prevAffiliates := affiliatesPtr.Load()
	t.Cleanup(func() { affiliatesPtr.Store(prevAffiliates) })
	affiliatesPtr.Store(&AffiliatesConfig{List: []string{"ZZA", "ZZB"}, BuylistList: []string{"ZZC", "ZZD"}})

	for _, tc := range []struct {
		name       string
		sig        string
		hide       bool
		sellers    []string
		vendors    []string
		lockedRows int
		locked     bool
	}{
		{"logged out", "", false, []string{"Alpha Seller", "Beta Seller", "Gamma Seller"}, []string{"Alpha Vendor", "Beta Vendor", "Gamma Vendor"}, 2, true},
		{"logged out, hiding", "", true, []string{"Alpha Seller", "Beta Seller"}, []string{"Alpha Vendor", "Beta Vendor"}, 0, true},
		{"signed in, hiding", grantSig(t), true, []string{"Beta Seller", "Gamma Seller", "Alpha Seller"}, []string{"Beta Vendor", "Gamma Vendor", "Alpha Vendor"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withConfigCopy(t)
			Config().SearchHideNonAffiliates = tc.hide
			req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(uuid), nil)
			req.AddCookie(&http.Cookie{Name: "SearchListingPriority", Value: "prices"})
			if tc.sig != "" {
				req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: tc.sig})
			}
			rec := httptest.NewRecorder()
			testSite.Search(rec, req)
			page := rec.Body.String()

			var gotSellers, gotVendors []string
			for _, match := range storeNameCell.FindAllStringSubmatch(page, -1) {
				name := strings.TrimSpace(match[1])
				switch {
				case strings.HasSuffix(name, " Seller"):
					gotSellers = append(gotSellers, name)
				case strings.HasSuffix(name, " Vendor"):
					gotVendors = append(gotVendors, name)
				}
			}
			if !slices.Equal(gotSellers, tc.sellers) {
				t.Errorf("retail rows %q, want %q (%d bytes)", gotSellers, tc.sellers, len(page))
			}
			if !slices.Equal(gotVendors, tc.vendors) {
				t.Errorf("buylist rows %q, want %q", gotVendors, tc.vendors)
			}
			if n := strings.Count(page, "price-row-locked"); n != tc.lockedRows {
				t.Errorf("%d locked rows, want %d", n, tc.lockedRows)
			}

			if v := settingsModalData(testSite, req); v.ListingLocked != tc.locked {
				t.Errorf("ListingLocked = %v, want %v", v.ListingLocked, tc.locked)
			}
		})
	}
}

// A logged-out reader gets the stores that are not affiliates locked or,
// with hide, removed, along with a condition only they price: a side left
// with nothing must be empty for the page to say there are no offers.
func TestGateNonAffiliates(t *testing.T) {
	offers := func() map[mtgban.Condition][]SearchEntry {
		return map[mtgban.Condition][]SearchEntry{
			"INDEX": {{Shorthand: "TCGLow"}},
			"NM":    {{Shorthand: "AFF"}, {Shorthand: "OTHER"}},
			"SP":    {{Shorthand: "OTHER"}},
		}
	}

	locked := offers()
	gateNonAffiliates(locked, []string{"AFF"}, false)
	for cond, want := range map[mtgban.Condition][]bool{"INDEX": {false}, "NM": {false, true}, "SP": {true}} {
		var got []bool
		for _, entry := range locked[cond] {
			got = append(got, entry.Locked)
		}
		if !slices.Equal(got, want) {
			t.Errorf("locking: %s rows locked %v, want %v", cond, got, want)
		}
	}

	hidden := offers()
	gateNonAffiliates(hidden, []string{"AFF"}, true)
	got := map[mtgban.Condition][]string{}
	for cond, entries := range hidden {
		for _, entry := range entries {
			got[cond] = append(got[cond], entry.Shorthand)
		}
	}
	want := map[mtgban.Condition][]string{"INDEX": {"TCGLow"}, "NM": {"AFF"}}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("hiding: offers %v, want %v", got, want)
	}

	none := map[mtgban.Condition][]SearchEntry{"NM": {{Shorthand: "OTHER"}}}
	gateNonAffiliates(none, []string{"AFF"}, true)
	if len(none) != 0 {
		t.Errorf("hiding every store left %v, want no conditions", none)
	}
}
