package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/palette"
)

// The palette offers store: only for the stores search would show the
// reader: the block lists apply unless their own signature lifts them, and
// the API-only stores apply whatever it says.
func TestPaletteStoresFollowTheBlockLists(t *testing.T) {
	signingEnabled(t, false)
	publishStores(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Open Shop", Shorthand: "OPENSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "Blocked Shop", Shorthand: "BLOCKSHOP"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: "API Shop", Shorthand: "APISHOP"}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Open Buyer", Shorthand: "OPENBUY"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "Blocked Buyer", Shorthand: "BLOCKBUY"}),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "API Buyer", Shorthand: "APIBUY"}),
	})
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"BLOCKSHOP"}
	Config().Stores.SearchBuylistBlockList = []string{"BLOCKBUY"}
	Config().Stores.APIOnlyStores = []string{"APISHOP", "APIBUY"}

	stores := func(cookie string) (sellers, vendors []string) {
		req := httptest.NewRequest(http.MethodGet, "/api/palette/stores.json", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: cookie})
		}
		rec := httptest.NewRecorder()
		testSite.palette.Stores(rec, req)
		if rec.Header().Get("Cache-Control") != "private, no-cache" {
			t.Errorf("Cache-Control %q", rec.Header().Get("Cache-Control"))
		}
		var out palette.StoresResponse
		err := json.Unmarshal(rec.Body.Bytes(), &out)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range out.Sellers {
			sellers = append(sellers, s.Shorthand)
		}
		for _, v := range out.Vendors {
			vendors = append(vendors, v.Shorthand)
		}
		return sellers, vendors
	}

	sellers, vendors := stores("")
	if !slices.Equal(sellers, []string{"OPENSHOP"}) || !slices.Equal(vendors, []string{"OPENBUY"}) {
		t.Errorf("unsigned: sellers %v, vendors %v", sellers, vendors)
	}

	lifted := "SearchDisabled=NONE&SearchBuylistDisabled=NONE"
	fields, _ := url.ParseQuery(lifted)
	sellers, vendors = stores(signedAs(t, fields, time.Now().Add(time.Hour)))
	if !slices.Equal(sellers, []string{"BLOCKSHOP", "OPENSHOP"}) || !slices.Equal(vendors, []string{"BLOCKBUY", "OPENBUY"}) {
		t.Errorf("block lists lifted: sellers %v, vendors %v", sellers, vendors)
	}

	forged := base64.StdEncoding.EncodeToString([]byte(lifted))
	sellers, vendors = stores(forged)
	if !slices.Equal(sellers, []string{"OPENSHOP"}) || !slices.Equal(vendors, []string{"OPENBUY"}) {
		t.Errorf("forged: sellers %v, vendors %v", sellers, vendors)
	}
}
