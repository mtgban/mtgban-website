package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// stubCartStores stands in ABU's buylist and one of its store splits, with
// one item id per condition, CSI's buylist and sealed buylist, SCG's
// buylist, both sides of Mint, Strike Zone, Hareruya and Manaleak, Mana
// Pool's store, and a store the bookmarklet does not fill.
func stubCartStores(t *testing.T) {
	t.Helper()
	buylist := mtgban.BuylistRecord{}
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "101"})
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "102"})
	buylist.Add("card-b", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "201"})
	// ABU prices this one's NM row at $0, which the scraper drops
	buylist.Add("card-e", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "501"})
	// An id the loader would not take
	buylist.Add("card-f", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "601,602"})
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
	// and its store sells each condition as its own product
	mintStock := mtgban.InventoryRecord{}
	mintStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1.79, InstanceID: "283193"})
	mintStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1.29, InstanceID: "663174"})
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
	// Card Kingdom's cart takes its product id and its own grade names
	ckStock := mtgban.InventoryRecord{}
	ckStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 3.49, OriginalID: "10190", InstanceID: "4ED-123"})
	ckStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 2.79, OriginalID: "10190", InstanceID: "4ED-123"})
	ckSealed := mtgban.InventoryRecord{}
	ckSealed.Add("box-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100})
	// A graded slab's listing has a product id, but its cart add was never
	// measured
	ckGraded := mtgban.InventoryRecord{}
	ckGraded.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 50, OriginalID: "555001"})
	szStock := mtgban.InventoryRecord{}
	szStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 2, InstanceID: "USCIDU-637-F-978240-993-XAK-QHC"})
	// Manaleak sells and buys a card under one product id
	ml := mtgban.BuylistRecord{}
	ml.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 0.1, InstanceID: "7090"})
	mlStock := mtgban.InventoryRecord{}
	mlStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 0.2, Quantity: 1, InstanceID: "7090"})
	// Mana Pool's product ids name one condition and finish each
	mpStock := mtgban.InventoryRecord{}
	mpStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 0.5, InstanceID: "001229ab-da01-4346-91f9-23c145cd23c5"})
	mpStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 0.4, InstanceID: "088072ea-66c7-4ef2-86a2-fd90055698a8"})
	// StorePass buylists name a product and the variant it is bought in,
	// one per condition where the store prices each
	gn := mtgban.BuylistRecord{}
	gn.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 16, OriginalID: "152060", InstanceID: "151169"})
	vs := mtgban.BuylistRecord{}
	vs.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 18, OriginalID: "9907513360690", InstanceID: "50196675264818"})
	vs.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 15, OriginalID: "9907513360690", InstanceID: "50196675297586"})
	csiSealed := mtgban.BuylistRecord{}
	csiSealed.Add("box-a", &mtgban.BuylistEntry{BuyPrice: 90, InstanceID: "701"})
	// CSI's store cart takes a product id and the row id of its condition
	csiStock := mtgban.InventoryRecord{}
	csiStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 4.49, OriginalID: "434190", InstanceID: "10753983"})
	csiStock.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 3.49, OriginalID: "434190", InstanceID: "10753984"})

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
		mtgban.NewVendorFromBuylist(gn, mtgban.ScraperInfo{Shorthand: "GN"}),
		mtgban.NewVendorFromBuylist(vs, mtgban.ScraperInfo{Shorthand: "VS"}),
		mtgban.NewVendorFromBuylist(ml, mtgban.ScraperInfo{Shorthand: "ML"}),
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "ABUScans"}),
		mtgban.NewSellerFromInventory(szStock, mtgban.ScraperInfo{Shorthand: "SZ"}),
		mtgban.NewSellerFromInventory(haStock, mtgban.ScraperInfo{Shorthand: "HA"}),
		mtgban.NewSellerFromInventory(ckStock, mtgban.ScraperInfo{Shorthand: "CK"}),
		mtgban.NewSellerFromInventory(ckSealed, mtgban.ScraperInfo{Shorthand: "CKSealed"}),
		mtgban.NewSellerFromInventory(ckGraded, mtgban.ScraperInfo{Shorthand: "CKGraded"}),
		mtgban.NewSellerFromInventory(csiStock, mtgban.ScraperInfo{Shorthand: "CSI"}),
		mtgban.NewSellerFromInventory(mintStock, mtgban.ScraperInfo{Shorthand: "MMC"}),
		mtgban.NewSellerFromInventory(mlStock, mtgban.ScraperInfo{Shorthand: "ML"}),
		mtgban.NewSellerFromInventory(mpStock, mtgban.ScraperInfo{Shorthand: "MP"}),
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
		{"CSI", false, "434190-10753983:3,434190-10753984:1"},
		// Sealed product carries no grade
		{"CSISealed", true, "701:1"},
		{"SCG", true, "SGL-A1:4"},
		{"MMC", true, "8137:4"},
		// A buylist row goes in as NM, named by product and variant
		{"GN", true, "152060-151169:4"},
		{"VS", true, "9907513360690-50196675264818:4"},
		{"MMC", false, "283193:3,663174:1"},
		{"ML", true, "7090:4"},
		{"ML", false, "7090:3"},
		{"MP", false, "001229ab-da01-4346-91f9-23c145cd23c5:3,088072ea-66c7-4ef2-86a2-fd90055698a8:1"},
		{"SZ", true, "USCIDU-637-F-978240-993-XAK-QHC:4"},
		{"SZ", false, "USCIDU-637-F-978240-993-XAK-QHC:3"},
		// Each condition its own class in the store, one class on the buylist
		{"HA", false, "27947:3,27948:1"},
		{"HA", true, "356866:4"},
		// Card Kingdom's store cart has no button for now
		{"CK", false, ""},
		{"CKSealed", false, ""},
		{"CKGraded", false, ""},
	} {
		got := cartRows(cartItems(tc.key, tc.buylist, entries), entries)
		if got != tc.want {
			t.Errorf("%s rows = %q, want %q", tc.key, got, tc.want)
		}
	}

	ck := ckCartID(mtgban.InventoryEntry{Conditions: mtgban.SP, OriginalID: "10190"})
	if ck != "10190-EX" {
		t.Errorf("ckCartID = %q, want 10190-EX", ck)
	}

	// The button carries each row's id in row order, for the page to rebuild
	// its list from the rows left ticked
	got := cartLoadFor("ABUScans", false, entries)
	if got.Items != "301,,,301,,,402,," {
		t.Errorf("ABUScans items = %q", got.Items)
	}

	// An id the loader would drop stays out, and the others keep their rows
	got = cartLoadFor("ABUGames", true, []OptimizedUploadEntry{{CardID: "card-f", Quantity: 1}, {CardID: "card-a", Quantity: 1}})
	if got.Items != ",101" || !strings.Contains(got.Link, "#ban=101:1&") || !strings.HasSuffix(got.Link, "&skip=1") {
		t.Errorf("ABUGames with a bad id = %+v", got)
	}

	got = cartLoadFor("MKM", true, entries)
	if got.Link != "" {
		t.Errorf("a store the bookmarklet does not fill got a button: %+v", got)
	}
	got = cartLoadFor("SCGRetail", false, entries)
	if got.Link != "" {
		t.Errorf("SCG's retail side, which has its own import, got a button: %+v", got)
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
		{"CSI", false, `href="https://www.coolstuffinc.com/main_view_cart.php#ban=434190-10753983:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="CSI"`},
		{"SCG", true, `href="https://sellyourcards.starcitygames.com/mtg/uploads#ban=SGL-A1:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="SCG"`},
		{"MMC", true, `href="https://www.mtgmintcard.com/buylist-cart#ban=8137:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="MTG Mint Card"`},
		{"GN", true, `href="https://buylist.gamenerdz.com/retailer/buylist#ban=152060-151169:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="Game Nerdz"`},
		{"VS", true, `href="https://buylist.vegas.singles/retailer/buylist#ban=9907513360690-50196675264818:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="Vegas Singles"`},
		{"MMC", false, `href="https://www.mtgmintcard.com/shopping-cart#ban=283193:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="MTG Mint Card"`},
		{"ML", true, `href="https://www.manaleak.com/index.php?route=buylist/cart#ban=7090:2&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="Manaleak"`},
		{"ML", false, `href="https://www.manaleak.com/index.php?route=checkout/cart#ban=7090:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Manaleak"`},
		{"MP", false, `href="https://manapool.com/cart#ban=001229ab-da01-4346-91f9-23c145cd23c5:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Mana Pool"`},
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
		if !strings.Contains(out, `onclick="return window.openCartPrompt ? openCartPrompt(this) : true"`) {
			t.Errorf("%s: the button skips the panel", tc.key)
		}
		if !strings.Contains(out, `onclick="return window.showCartPrompt ? showCartPrompt(this.nextElementSibling) : false"`) {
			t.Errorf("%s: no way back to the panel", tc.key)
		}
		if !strings.Contains(out, `id="cart-overlay"`) || !strings.Contains(out, `href="javascript:void%20`) {
			t.Errorf("%s: no panel with the loader to drag", tc.key)
		}
		// A box the browser restored unticked would leave its row in the list
		if !strings.Contains(out, `checked autocomplete="off" class="opt-row-check"`) {
			t.Errorf("%s: the browser can restore a row's box", tc.key)
		}
	}

	for _, key := range []string{"MKM", "SCG", "CK", "CKGraded", "CKSealed"} {
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
		if !strings.Contains(page, `checked autocomplete="off" class="arb-row-check"`) {
			t.Errorf("%s: the browser can restore a row's box", tc.name)
		}
	}

	// Buying comes first, then selling, CK's own buylist import included
	ck := renderArbit(t, PageVars{
		ScraperShort: "ABUScans",
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "Store", Key: "CK", Arbit: rows}},
	})
	at, ckAt := strings.Index(ck, buy), strings.Index(ck, ">Load buylist at CK<")
	if at < 0 || ckAt < 0 || at > ckAt {
		t.Errorf("want Load at ABU before Load buylist at CK, at %d and %d", at, ckAt)
	}

	// CSI is bought from two ways, its deck builder and its cart: one button
	// each, told apart, the cart's keeping the name the loader's messages use
	csi := renderArbit(t, PageVars{
		ScraperShort: "CSI",
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "Store", Key: "CK", Arbit: rows}},
	})
	if strings.Count(csi, ">Load at CSI<") != 1 || !strings.Contains(csi, `data-store="CSI" data-buylist="false"`) {
		t.Errorf("want one Load at CSI, the cart's, got %d", strings.Count(csi, ">Load at CSI<"))
	}
	if !strings.Contains(csi, `class="arb-load-btn builder"`) || !strings.Contains(csi, ">Deck builder at CSI<") {
		t.Error("CSI's deck builder button is not told apart from its cart's")
	}

	// Mint's store cart asks for what the buylist takes, or as many as Mint
	// has where it names no amount; the buylist cart keeps the row's own
	mintRows := []mtgban.ArbitEntry{rows[0], {
		CardID:         "card-a",
		InventoryEntry: mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1},
		BuylistEntry:   mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 2, Quantity: 20},
		Quantity:       8,
	}}
	mint := renderArbit(t, PageVars{
		ScraperShort: "MMC",
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "Store", Key: "CSI", Arbit: mintRows}},
	})
	mintBuy := `href="https://www.mtgmintcard.com/shopping-cart#ban=283193:999,663174:20&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="MTG Mint Card" data-buylist="false" data-load-list="cart" data-load-items="283193,663174" data-load-qtys="999,20"`
	if !strings.Contains(mint, mintBuy) {
		t.Errorf("buying at Mint: no store cart button with %s", mintBuy)
	}
	mintSell := `href="https://www.coolstuffinc.com/buylist_cart.php#ban=601:10&amp;v=` + cartVersion() + `" target="_blank" rel="noopener" data-store="CSI" data-buylist="true" data-load-list="cart" data-load-items="601,601" onclick`
	if !strings.Contains(mint, mintSell) {
		t.Errorf("buying at Mint: no buylist cart button with %s", mintSell)
	}
	// Mana Pool's feed gives no stock, so its cart asks the same way, beside
	// its mass entry form, told apart from it
	mp := renderArbit(t, PageVars{
		ScraperShort: "MP",
		UserNav:      &NavElem{Short: "beta"},
		Arb:          []Arbitrage{{Name: "Store", Key: "CSI", Arbit: mintRows}},
	})
	mpBuy := `href="https://manapool.com/cart#ban=001229ab-da01-4346-91f9-23c145cd23c5:999,088072ea-66c7-4ef2-86a2-fd90055698a8:20&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Mana Pool" data-buylist="false" data-load-list="cart" data-load-items="001229ab-da01-4346-91f9-23c145cd23c5,088072ea-66c7-4ef2-86a2-fd90055698a8" data-load-qtys="999,20"`
	if !strings.Contains(mp, mpBuy) {
		t.Errorf("buying at Mana Pool: no store cart button with %s", mpBuy)
	}
	if strings.Count(mp, ">Load at Mana Pool<") != 1 || !strings.Contains(mp, `class="arb-load-btn builder"`) || !strings.Contains(mp, ">Mass entry at Mana Pool<") {
		t.Error("Mana Pool's mass entry button is not told apart from its cart's")
	}

	// Other stores' carts carry the page's quantities
	if strings.Contains(ck+csi, "data-load-qtys") {
		t.Error("a cart other than Mint's store asks its own quantities")
	}

	page := renderArbit(t, reversePageVars())
	if strings.Contains(page, `id="cart-overlay"`) {
		t.Error("a page with no cart store carries the cart panel")
	}

	// Global buys at the page's own store, and every section is a store, so
	// no buylist cart is filled
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"global", "CSI"},
		{"global CK", "CK"},
	} {
		page := renderArbit(t, PageVars{
			ScraperShort: "ABUScans",
			ArbitVars:    ArbitVars{GlobalMode: true},
			UserNav:      &NavElem{Short: "beta"},
			Arb:          []Arbitrage{{Name: "Store", Key: tc.key, Arbit: rows}},
		})
		if !strings.Contains(page, buy) {
			t.Errorf("%s: no store cart button with %s", tc.name, buy)
		}
		if strings.Contains(page, "Load buylist at") {
			t.Errorf("%s: a store section got a buylist button", tc.name)
		}
		if strings.Count(page, `data-load-list="cart"`) != 1 {
			t.Errorf("%s: want one cart button", tc.name)
		}
	}

	// On Global sealed the copies are the section's, under go-mtgban's
	// sealed shorthands, each listing ids as its scraper does
	stock := func(entry mtgban.InventoryEntry) mtgban.InventoryRecord {
		inv := mtgban.InventoryRecord{}
		inv.Add("box-a", &entry)
		return inv
	}
	sealed := func(short string, entry mtgban.InventoryEntry) mtgban.Seller {
		return mtgban.NewSellerFromInventory(stock(entry), mtgban.ScraperInfo{Shorthand: short, SealedMode: true})
	}
	sellers := append(GetSellers(),
		sealed("IndexSealed", mtgban.InventoryEntry{Price: 100}),
		sealed("TCGSealed", mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100, OriginalID: "500001", InstanceID: "600001"}),
		sealed("CSISealed", mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100, OriginalID: "434191", InstanceID: "10753985"}),
		sealed("SCGSealed", mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100, OriginalID: "SLD-1", InstanceID: "SLD-1"}),
		sealed("MPSealed", mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100}),
		sealed("HASealed", mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100, OriginalID: "88001", InstanceID: "88002"}),
		sealed("ABUSealed", mtgban.InventoryEntry{Price: 100, OriginalID: "abu-1"}),
	)
	sellersPtr.Store(&sellers)
	sealedRows := []mtgban.ArbitEntry{{
		CardID:         "box-a",
		InventoryEntry: mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 100},
		Quantity:       2,
	}}
	haCart := `href="https://www.hareruyamtg.com/en/cart#ban=88002:2&amp;v=` + cartVersion() + `&amp;side=retail" target="_blank" rel="noopener" data-store="Hareruya" data-buylist="false"`
	for _, tc := range []struct {
		short string
		key   string
		want  string
	}{
		{"IndexSealed", "TCGSealed", ">Load at TCG<"},
		{"IndexSealed", "HASealed", haCart},
		// CK's, CSI's and Manapool's deck builders and SCG's upload take
		// singles, and CSI's store cart was measured on singles only
		{"IndexSealed", "CKSealed", ""},
		{"IndexSealed", "CSISealed", ""},
		{"IndexSealed", "MPSealed", ""},
		{"IndexSealed", "SCGSealed", ""},
		// ABU lists sealed product with no item id its cart takes
		{"IndexSealed", "ABUSealed", ""},
		// Never the page's store's
		{"TCGSealed", "ABUSealed", ""},
	} {
		page := renderArbit(t, PageVars{
			ScraperShort: tc.short,
			ArbitVars:    ArbitVars{GlobalMode: true},
			UserNav:      &NavElem{Short: "beta"},
			Arb:          []Arbitrage{{Name: "Store", Key: tc.key, Arbit: sealedRows}},
		})
		buttons := strings.Count(page, `class="arb-load-btn buy"`)
		if tc.want == "" && buttons != 0 {
			t.Errorf("global sealed %s against %s: want no Load at button, got %d", tc.key, tc.short, buttons)
		}
		if tc.want != "" && (buttons != 1 || !strings.Contains(page, tc.want)) {
			t.Errorf("global sealed %s against %s: want only %s, got %d buttons", tc.key, tc.short, tc.want, buttons)
		}
		if strings.Contains(page, "Load buylist at") {
			t.Errorf("global sealed %s: a store section got a buylist button", tc.key)
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
	version := cartVersion()
	if len(version) != 8 {
		t.Fatalf("version %q is not a short hash", version)
	}
	want := strings.Replace(stripLoader(string(source)), cartVersionMark, version, 1)
	if decoded != want {
		t.Error("bookmarklet does not decode back to js/ban-to-cart.js with its version stamped in")
	}
	if strings.Contains(decoded, cartVersionMark) {
		t.Error("the version mark survived into the bookmarklet")
	}
	// Firefox drops a bookmark whose URL runs past 65,536 characters, and
	// the loader only grows as stores are added
	if len(link) >= 55000 {
		t.Errorf("bookmarklet is %d characters, too close to Firefox's limit of 65,536 on a bookmark", len(link))
	}
}

// The loader loses its comments and indentation and nothing else: a "//"
// inside a string or after code stays
func TestStripLoader(t *testing.T) {
	source := "(function () {\n" +
		"    // A comment\n" +
		"\n" +
		"    var url = \"https://api.abugames.com/\" + x; // kept\n" +
		"        var re = /a\\/\\/b/;\n" +
		"})();\n"
	want := "(function () {\n" +
		"var url = \"https://api.abugames.com/\" + x; // kept\n" +
		"var re = /a\\/\\/b/;\n" +
		"})();"
	got := stripLoader(source)
	if got != want {
		t.Errorf("stripLoader = %q, want %q", got, want)
	}
	if stripLoader(strings.Replace(source, "A comment", "Another", 1)) != got {
		t.Error("a comment's wording reaches the loader, and with it the version")
	}
}

// A cart page opened from here carries the affiliate query the store's own
// links do, where a code is configured
func TestCartLoadAffiliates(t *testing.T) {
	stubCartStores(t)
	saved := affiliatesPtr.Load()
	t.Cleanup(func() { affiliatesPtr.Store(saved) })
	affiliatesPtr.Store(&AffiliatesConfig{Codes: map[string]string{"CK": "ban", "MMC": "banmint", "CSI": "bancsi", "SCG": "123", "ABU": "unused", "MP": "banmp"}})
	entries := []OptimizedUploadEntry{{CardID: "card-a", Quantity: 2}}

	for _, tc := range []struct {
		key     string
		buylist bool
		want    string
	}{
		{"MMC", true, "https://www.mtgmintcard.com/buylist-cart?utm_campaign=banmint&utm_medium=referral&utm_source=banmint#ban="},
		{"MMC", false, "https://www.mtgmintcard.com/shopping-cart?utm_campaign=banmint&utm_medium=referral&utm_source=banmint#ban="},
		{"MP", false, "https://manapool.com/cart?ref=banmp#ban="},
		{"CSI", true, "https://www.coolstuffinc.com/buylist_cart.php?utm_referrer=bancsi#ban="},
		{"SCG", true, "https://goto.starcitygames.com/c/123/3052179/37198?u=https%3A%2F%2Fsellyourcards.starcitygames.com%2Fmtg%2Fuploads#ban="},
		// A store with no affiliate query keeps its plain page
		{"ABUGames", true, "https://abugames.com/cartview/buylist#ban="},
	} {
		got := cartLoadFor(tc.key, tc.buylist, entries).Link
		if !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s link = %q, want it to start %q", tc.key, got, tc.want)
		}
	}

	got := affiliated("CK", "https://www.cardkingdom.com/cart")
	if got != "https://www.cardkingdom.com/cart?partner=ban&utm_campaign=ban&utm_medium=affiliate&utm_source=ban" {
		t.Errorf("CK link = %q", got)
	}
}
