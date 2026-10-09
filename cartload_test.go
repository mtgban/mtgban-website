package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// stubCartStores stands in ABU's buylist and one of its store splits, with
// one item id per condition, CSI's buylist and sealed buylist, and a store
// the bookmarklet does not fill.
func stubCartStores(t *testing.T) {
	t.Helper()
	buylist := mtgban.BuylistRecord{}
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "101"})
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "102"})
	buylist.Add("card-b", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "201"})
	// ABU prices this one's NM row at $0, which the scraper drops
	buylist.Add("card-e", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "501"})
	mkm := mtgban.BuylistRecord{}
	mkm.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "999"})
	inventory := mtgban.InventoryRecord{}
	inventory.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1, InstanceID: "301"})
	// ABU stocks this one only as SP, which a row with no condition was
	// priced at
	inventory.Add("card-d", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1, InstanceID: "402"})
	// CSI buys NM only and derives the other grades, all on the one row
	csi := mtgban.BuylistRecord{}
	csi.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "601"})
	csi.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 0.8, InstanceID: "601"})
	csiSealed := mtgban.BuylistRecord{}
	csiSealed.Add("box-a", &mtgban.BuylistEntry{BuyPrice: 90, InstanceID: "701"})

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: "ABUGames"}),
		mtgban.NewVendorFromBuylist(mkm, mtgban.ScraperInfo{Shorthand: "MKM"}),
		mtgban.NewVendorFromBuylist(csi, mtgban.ScraperInfo{Shorthand: "CSI"}),
		mtgban.NewVendorFromBuylist(csiSealed, mtgban.ScraperInfo{Shorthand: "CSISealed"}),
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "ABUScans"}),
	}
	vendorsPtr.Store(&vendors)
	sellersPtr.Store(&sellers)
}

func TestCartRows(t *testing.T) {
	stubCartStores(t)

	entries := []OptimizedUploadEntry{
		{CardID: "card-a", Quantity: 2},
		{CardID: "card-a", Condition: mtgban.SP, Quantity: 1},
		{CardID: "card-b", Condition: mtgban.NM, Quantity: 3},
		{CardID: "card-a", Condition: mtgban.NM, Quantity: 1},
		{CardID: "card-c", Condition: mtgban.NM, Quantity: 1},
		{CardID: "card-b", Condition: mtgban.MP, Quantity: 1},
		{CardID: "card-d", Quantity: 1},
		{CardID: "card-e", Quantity: 1},
		{CardID: "box-a", Quantity: 1},
	}

	for _, tc := range []struct {
		key     string
		buylist bool
		want    string
	}{
		// Every buylist row goes in as NM, and a card with no NM id stays out
		{"ABUGames", true, "101:4,201:4"},
		// A store row keeps its condition, or the one it was priced at
		{"ABUScans", false, "301:3,402:1"},
		{"CSI", true, "601:4"},
		// Sealed product carries no grade
		{"CSISealed", true, "701:1"},
	} {
		got := cartRows(tc.key, tc.buylist, entries)
		if got != tc.want {
			t.Errorf("%s rows = %q, want %q", tc.key, got, tc.want)
		}
	}

	got := cartLoadFor("MKM", true, entries)
	if got.Link != "" {
		t.Errorf("a store the bookmarklet does not fill got a button: %+v", got)
	}
	got = cartLoadFor("CSI", false, entries)
	if got.Link != "" {
		t.Errorf("CSI's retail side, which has its own import, got a button: %+v", got)
	}
}

// A split's button opens the store cart it is for, with its rows in the
// fragment, through the panel holding the loader, whose link survives
// html/template.
func TestCartLoadButtons(t *testing.T) {
	stubCartStores(t)
	entries := []OptimizedUploadEntry{{CardID: "card-a", Quantity: 2}}

	for _, tc := range []struct {
		key     string
		buylist bool
		link    string
	}{
		{"ABUGames", true, `href="https://abugames.com/cartview/buylist#ban=101:2" target="_blank" rel="noopener" data-store="ABU"`},
		{"ABUScans", false, `href="https://abugames.com/cartview/shop#ban=301:2" target="_blank" rel="noopener" data-store="ABU"`},
		{"CSI", true, `href="https://www.coolstuffinc.com/buylist_cart.php#ban=601:2" target="_blank" rel="noopener" data-store="CSI"`},
	} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			IsBuylist:       tc.buylist,
			Optimized:       map[string][]OptimizedUploadEntry{tc.key: entries},
			OptimizedKeys:   []string{tc.key},
			OptimizedTotals: map[string]float64{tc.key: 1},
		}})
		if !strings.Contains(out, tc.link) {
			t.Errorf("%s: no button with %s", tc.key, tc.link)
		}
		if !strings.Contains(out, `onclick="return openCartPrompt(this)"`) {
			t.Errorf("%s: the button skips the panel", tc.key)
		}
		if !strings.Contains(out, `onclick="return showCartPrompt(this.nextElementSibling)"`) {
			t.Errorf("%s: no way back to the panel", tc.key)
		}
		if !strings.Contains(out, `id="cart-overlay"`) || !strings.Contains(out, `href="javascript:void%20`) {
			t.Errorf("%s: no panel with the loader to drag", tc.key)
		}
	}

	for _, key := range []string{"MKM", "CSI"} {
		out := renderUpload(t, PageVars{UploadVars: UploadVars{
			Optimized:       map[string][]OptimizedUploadEntry{key: entries},
			OptimizedKeys:   []string{key},
			OptimizedTotals: map[string]float64{key: 1},
		}})
		if strings.Contains(out, `id="cart-overlay"`) {
			t.Errorf("a retail page with only a %s split carries the cart panel", key)
		}
	}
}

func TestCartBookmarklet(t *testing.T) {
	source, err := os.ReadFile("js/ban-to-cart.js")
	if err != nil {
		t.Fatal(err)
	}

	link := string(cartBookmarklet())
	code, found := strings.CutPrefix(link, "javascript:void%20")
	if !found {
		t.Fatalf("bookmarklet does not discard its result: %.40q", link)
	}
	decoded, err := url.PathUnescape(code)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != strings.TrimSpace(string(source)) {
		t.Error("bookmarklet does not decode back to js/ban-to-cart.js")
	}
}
