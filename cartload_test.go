package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// stubCartStores stands in ABU's buylist and one of its store splits, with
// one item id per condition, CSI's buylist and sealed buylist, SCG's and
// Mint's buylists, both sides of Strike Zone and Hareruya, and a store the
// bookmarklet does not fill.
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
	// SCG's ids are SKUs, one per condition
	scg := mtgban.BuylistRecord{}
	scg.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "SGL-A1"})
	scg.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 0.8, InstanceID: "SGL-A2"})
	// Mint's grades are derived from its one row too
	mint := mtgban.BuylistRecord{}
	mint.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "8137"})
	mint.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 0.5, InstanceID: "8137"})
	// Strike Zone lists each grade as its own row, under the id its cart's
	// import takes, one id for buying and selling
	sz := mtgban.BuylistRecord{}
	sz.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "USCIDU-637-F-978240-993-XAK-QHC"})
	sz.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.MP, BuyPrice: 0.5, InstanceID: "USCIDU-637-F-978240-997-XAK-ZZZ"})
	// Hareruya sells each condition of a lot under its own class, and buys a
	// card under one class whatever its grade
	ha := mtgban.BuylistRecord{}
	ha.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "356866"})
	ha.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 0.8, InstanceID: "356866"})
	haStock := mtgban.InventoryRecord{}
	haStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 2, InstanceID: "27947"})
	haStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1.5, InstanceID: "27948"})
	szStock := mtgban.InventoryRecord{}
	szStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 2, InstanceID: "USCIDU-637-F-978240-993-XAK-QHC"})
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
		mtgban.NewVendorFromBuylist(scg, mtgban.ScraperInfo{Shorthand: "SCG"}),
		mtgban.NewVendorFromBuylist(csi, mtgban.ScraperInfo{Shorthand: "CSI"}),
		mtgban.NewVendorFromBuylist(csiSealed, mtgban.ScraperInfo{Shorthand: "CSISealed"}),
		mtgban.NewVendorFromBuylist(mint, mtgban.ScraperInfo{Shorthand: "MMC"}),
		mtgban.NewVendorFromBuylist(sz, mtgban.ScraperInfo{Shorthand: "SZ"}),
		mtgban.NewVendorFromBuylist(ha, mtgban.ScraperInfo{Shorthand: "HA"}),
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "ABUScans"}),
		mtgban.NewSellerFromInventory(szStock, mtgban.ScraperInfo{Shorthand: "SZ"}),
		mtgban.NewSellerFromInventory(haStock, mtgban.ScraperInfo{Shorthand: "HA"}),
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
		{"SCG", true, "SGL-A1:4"},
		{"MMC", true, "8137:4"},
		{"SZ", true, "USCIDU-637-F-978240-993-XAK-QHC:4"},
		{"SZ", false, "USCIDU-637-F-978240-993-XAK-QHC:3"},
		// Each condition its own class in the store, one class on the buylist
		{"HA", false, "27947:3,27948:1"},
		{"HA", true, "356866:4"},
	} {
		got := cartRows(cartItems(tc.key, tc.buylist, entries), entries)
		if got != tc.want {
			t.Errorf("%s rows = %q, want %q", tc.key, got, tc.want)
		}
	}

	// The button carries each row's id in row order, for the page to rebuild
	// its list from the rows left ticked
	got := cartLoadFor("ABUScans", false, entries)
	if got.Items != "301,,,301,,,402,," {
		t.Errorf("ABUScans items = %q", got.Items)
	}

	got = cartLoadFor("MKM", true, entries)
	if got.Link != "" {
		t.Errorf("a store the bookmarklet does not fill got a button: %+v", got)
	}
	got = cartLoadFor("SCGRetail", false, entries)
	if got.Link != "" {
		t.Errorf("SCG's retail side, which has its own import, got a button: %+v", got)
	}
	got = cartLoadFor("MMC", false, entries)
	if got.Link != "" {
		t.Errorf("Mint's store side, which is not filled, got a button: %+v", got)
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
		{"ABUGames", true, `href="https://abugames.com/cartview/buylist#ban=101:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="ABU"`},
		{"ABUScans", false, `href="https://abugames.com/cartview/shop#ban=301:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="ABU"`},
		{"CSI", true, `href="https://www.coolstuffinc.com/buylist_cart.php#ban=601:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="CSI"`},
		{"SCG", true, `href="https://sellyourcards.starcitygames.com/mtg/uploads#ban=SGL-A1:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="SCG"`},
		{"MMC", true, `href="https://www.mtgmintcard.com/buylist-cart#ban=8137:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="MTG Mint Card"`},
		{"SZ", true, `href="http://shop.strikezoneonline.com/TUser?MC=CUVC&amp;MF=B&amp;BUID=637#ban=USCIDU-637-F-978240-993-XAK-QHC:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="Strike Zone"`},
		{"SZ", false, `href="http://shop.strikezoneonline.com/TUser?MC=CUVC&amp;MF=B&amp;BUID=637#ban=USCIDU-637-F-978240-993-XAK-QHC:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Strike Zone"`},
		{"HA", true, `href="https://www.hareruyamtg.com/ja/purchase/cart#ban=356866:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="Hareruya"`},
		{"HA", false, `href="https://www.hareruyamtg.com/en/cart#ban=27947:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Hareruya"`},
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

// An arbit section gets the buy side's store cart and the sell side's buylist
// cart, whichever way round the page reads, and one panel for both.
func TestCartLoadArbitButtons(t *testing.T) {
	stubCartStores(t)
	rows := []mtgban.ArbitEntry{{
		CardID:         "card-a",
		InventoryEntry: mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1},
		Quantity:       2,
	}}
	buy := `href="https://abugames.com/cartview/shop#ban=301:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="ABU" data-buylist="false"`
	sell := `href="https://www.coolstuffinc.com/buylist_cart.php#ban=601:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="CSI" data-buylist="true"`

	for _, tc := range []struct {
		name    string
		short   string
		key     string
		reverse bool
	}{
		{"arbit", "ABUScans", "CSI", false},
		{"reverse", "CSI", "ABUScans", true},
	} {
		page := renderArbit(t, PageVars{
			ScraperShort: tc.short,
			ReverseMode:  tc.reverse,
			UserNav:      &NavElem{Short: "beta"},
			Arb:          []Arbitrage{{Name: "Store", Key: tc.key, Arbit: rows}},
		})
		if !strings.Contains(page, buy) {
			t.Errorf("%s: no store cart button with %s", tc.name, buy)
		}
		if !strings.Contains(page, sell) {
			t.Errorf("%s: no buylist cart button with %s", tc.name, sell)
		}
		if strings.Count(page, `id="cart-overlay"`) != 1 {
			t.Errorf("%s: want the panel once", tc.name)
		}
	}

	page := renderArbit(t, reversePageVars())
	if strings.Contains(page, `id="cart-overlay"`) {
		t.Error("a page with no cart store carries the cart panel")
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
	version := cartVersion()
	if len(version) != 8 {
		t.Fatalf("version %q is not a short hash", version)
	}
	want := strings.Replace(strings.TrimSpace(string(source)), cartVersionMark, version, 1)
	if decoded != want {
		t.Error("bookmarklet does not decode back to js/ban-to-cart.js with its version stamped in")
	}
	if strings.Contains(decoded, cartVersionMark) {
		t.Error("the version mark survived into the bookmarklet")
	}
}
