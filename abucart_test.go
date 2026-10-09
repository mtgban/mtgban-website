package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// stubABU stands in ABU's buylist and one of its store splits, with one item
// id per condition, and SCG holding ids of its own.
func stubABU(t *testing.T) {
	t.Helper()
	buylist := mtgban.BuylistRecord{}
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "101"})
	buylist.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "102"})
	buylist.Add("card-b", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "201"})
	// ABU prices this one's NM row at $0, which the scraper drops
	buylist.Add("card-e", &mtgban.BuylistEntry{Conditions: mtgban.SP, BuyPrice: 1, InstanceID: "501"})
	scg := mtgban.BuylistRecord{}
	scg.Add("card-a", &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, InstanceID: "999"})
	inventory := mtgban.InventoryRecord{}
	inventory.Add("card-a", &mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1, InstanceID: "301"})
	// ABU stocks this one only as SP, which a row with no condition was
	// priced at
	inventory.Add("card-d", &mtgban.InventoryEntry{Conditions: mtgban.SP, Price: 1, InstanceID: "402"})

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	vendors := []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: "ABUGames"}),
		mtgban.NewVendorFromBuylist(scg, mtgban.ScraperInfo{Shorthand: "SCG"}),
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Shorthand: "ABUScans"}),
	}
	vendorsPtr.Store(&vendors)
	sellersPtr.Store(&sellers)
}

func TestABUCartRows(t *testing.T) {
	stubABU(t)

	entries := []OptimizedUploadEntry{
		{CardID: "card-a", Quantity: 2},
		{CardID: "card-a", Condition: mtgban.SP, Quantity: 1},
		{CardID: "card-b", Condition: mtgban.NM, Quantity: 3},
		{CardID: "card-a", Condition: mtgban.NM, Quantity: 1},
		{CardID: "card-c", Condition: mtgban.NM, Quantity: 1},
		{CardID: "card-b", Condition: mtgban.MP, Quantity: 1},
		{CardID: "card-d", Quantity: 1},
		{CardID: "card-e", Quantity: 1},
	}

	// Every buylist row goes in as NM, and a card with no NM id stays out
	got := abuCartRows("ABUGames", true, entries)
	want := "101:4,201:4"
	if got != want {
		t.Errorf("buylist rows = %q, want %q", got, want)
	}

	// A store row keeps its condition, or the one it was priced at
	got = abuCartRows("ABUScans", false, entries)
	want = "301:3,402:1"
	if got != want {
		t.Errorf("store rows = %q, want %q", got, want)
	}

	got = abuCartRows("SCG", true, entries)
	if got != "" {
		t.Errorf("a store that is not ABU got rows %q", got)
	}
}

// The page's ABU button opens the cart the split is for, with its rows in
// the fragment, percent-encoded by html/template, through the panel holding
// the loader, whose link survives html/template.
func TestABULoadButtons(t *testing.T) {
	stubABU(t)
	entries := []OptimizedUploadEntry{{CardID: "card-a", Quantity: 2}}

	for _, tc := range []struct {
		key     string
		buylist bool
		link    string
	}{
		{"ABUGames", true, `href="https://abugames.com/cartview/buylist#mtgban=101%3a2"`},
		{"ABUScans", false, `href="https://abugames.com/cartview/shop#mtgban=301%3a2"`},
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
		if !strings.Contains(out, `onclick="return openABUPrompt(this)"`) {
			t.Errorf("%s: the button skips the panel", tc.key)
		}
		if !strings.Contains(out, `onclick="return showABUPrompt(this.previousElementSibling)"`) {
			t.Errorf("%s: no way back to the panel", tc.key)
		}
		if !strings.Contains(out, `id="abu-overlay"`) || !strings.Contains(out, `href="javascript:void%20`) {
			t.Errorf("%s: no panel with the loader to drag", tc.key)
		}
	}

	out := renderUpload(t, PageVars{UploadVars: UploadVars{
		IsBuylist:       true,
		Optimized:       map[string][]OptimizedUploadEntry{"SCG": entries},
		OptimizedKeys:   []string{"SCG"},
		OptimizedTotals: map[string]float64{"SCG": 1},
	}})
	if strings.Contains(out, `id="abu-overlay"`) {
		t.Error("a page with no ABU split carries the ABU panel")
	}
}

func TestABUBookmarklet(t *testing.T) {
	source, err := os.ReadFile("js/abu-cart.js")
	if err != nil {
		t.Fatal(err)
	}

	link := string(abuBookmarklet())
	code, found := strings.CutPrefix(link, "javascript:void%20")
	if !found {
		t.Fatalf("bookmarklet does not discard its result: %.40q", link)
	}
	decoded, err := url.PathUnescape(code)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != strings.TrimSpace(string(source)) {
		t.Error("bookmarklet does not decode back to js/abu-cart.js")
	}
}
