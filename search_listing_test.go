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

	"github.com/mtgban/go-mtgban/mtgban"
)

// storeNameCell reads the store named on each price row, locked or not.
var storeNameCell = regexp.MustCompile(`class="store-name[^"]*"[^>]*>([^<]+)<`)

// Only a signed-in user may reorder each card's stores: logged out, they are
// listed by name whatever the listing priority cookie asks for, and the
// settings show the pills locked rather than bound to that cookie.
func TestListingPriorityNeedsASignature(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, true)
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

	for _, tc := range []struct {
		name    string
		sig     string
		sellers []string
		vendors []string
		locked  bool
	}{
		{"logged out", "", []string{"Alpha Seller", "Beta Seller"}, []string{"Alpha Vendor", "Beta Vendor"}, true},
		{"signed in", testSig(nil), []string{"Beta Seller", "Alpha Seller"}, []string{"Beta Vendor", "Alpha Vendor"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			if locked := strings.Contains(page, "settings-pills-locked"); locked != tc.locked {
				t.Errorf("listing pills locked = %v, want %v", locked, tc.locked)
			}
			if bound := strings.Contains(page, `id="settings-search-listing"`); bound == tc.locked {
				t.Errorf("listing pills bound to the cookie = %v, want %v", bound, !tc.locked)
			}
		})
	}
}
