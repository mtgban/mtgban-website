package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestStoreLabel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sealed bool
		want   string
	}{
		{"Card Kingdom", false, "Card Kingdom"},
		{"Card Kingdom", true, "Card Kingdom (Sealed)"},
		{"ABU Games (credit)", true, "ABU Games (credit) (Sealed)"},
		{"", false, ""},
	} {
		got := storeLabel(tc.name, tc.sealed)
		if got != tc.want {
			t.Errorf("storeLabel(%q, %v) = %q, want %q", tc.name, tc.sealed, got, tc.want)
		}
	}
}

// selectOptions is the body of the select with this id, or "".
func selectOptions(body, id string) string {
	re := regexp.MustCompile(`(?s)<select[^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</select>`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// wantSortStoreOptions checks a preferred sort picker names the sealed
// store apart from the singles store sharing its name.
func wantSortStoreOptions(t *testing.T, where, options string) {
	t.Helper()
	for _, want := range []string{
		`<option value="ZZSAME">Same Store</option>`,
		`<option value="ZZSAMESEALED">Same Store (Sealed)</option>`,
	} {
		if !strings.Contains(options, want) {
			t.Errorf("%s lacks %s:\n%s", where, want, options)
		}
	}
}

func TestSettingsModalNamesSealedSortStores(t *testing.T) {
	signingEnabled(t, true)
	store := func(shorthand string, sealed bool) mtgban.ScraperInfo {
		return mtgban.ScraperInfo{Name: "Same Store", Shorthand: shorthand, SealedMode: sealed}
	}
	withPrices(t, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("ZZSAME", false)),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, store("ZZSAMESEALED", true)),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("ZZSAME", false)),
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, store("ZZSAMESEALED", true)),
	})
	body := fetchSettingsModal(t, grantSig(t, "Search"))
	for _, id := range []string{"settings-sellers-priority", "settings-vendors-priority"} {
		wantSortStoreOptions(t, id, selectOptions(body, id))
	}
}

func TestMobileSearchNamesSealedSortStores(t *testing.T) {
	keys := []string{"ZZSAME", "ZZSAMESEALED"}
	pv := PageVars{
		UserNav:    &NavElem{Short: "b"},
		IsMobile:   true,
		SellerKeys: keys,
		VendorKeys: keys,
		StoreNames: map[string]string{"ZZSAME": "Same Store", "ZZSAMESEALED": "Same Store"},
		SearchVars: SearchVars{SearchRan: true, SealedStores: map[string]bool{"ZZSAME": false, "ZZSAMESEALED": true}},
	}
	out := renderPage(t, "search.html", true, pv)
	for _, id := range []string{"m-set-sellers-priority", "m-set-vendors-priority"} {
		wantSortStoreOptions(t, id, selectOptions(out, id))
	}
}

func TestOptimizerNamesSealedStores(t *testing.T) {
	entries := []OptimizedUploadEntry{{CardID: "a", Quantity: 1}}
	keys := []string{"ZZSAME", "ZZSAMESEALED"}
	out := renderUpload(t, PageVars{
		StoreNames: map[string]string{"ZZSAME": "Same Store", "ZZSAMESEALED": "Same Store"},
		UploadVars: UploadVars{
			AllScraperKeys:    keys,
			SealedScraperKeys: []string{"ZZSAMESEALED"},
			Optimized:         map[string][]OptimizedUploadEntry{"ZZSAME": entries, "ZZSAMESEALED": entries},
			OptimizedKeys:     keys,
			OptimizedTotals:   map[string]float64{"ZZSAME": 1, "ZZSAMESEALED": 1},
			FilteredOut: []LeftoverEntry{
				{CardID: "b", Quantity: 1, Store: "ZZSAME", Price: 1},
				{CardID: "c", Quantity: 1, Store: "ZZSAMESEALED", Price: 1},
			},
		},
	})
	for _, want := range []string{
		`<span class="toc-store">Same Store</span>`,
		`<span class="toc-store">Same Store (Sealed)</span>`,
		`<h3>Same Store</h3>`,
		`<h3>Same Store (Sealed)</h3>`,
		`<td>Same Store</td>`,
		`<td>Same Store (Sealed)</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the optimizer lacks %s", want)
		}
	}
}

// The custom buylist's reference picker lists a store once: a store-like
// index (TCGplayer Direct, Card Trader) under Index, not again under
// Retailers.
func TestCustomReferenceListsEachStoreOnce(t *testing.T) {
	signingEnabled(t, true)
	store := func(shorthand, name string) mtgban.Seller {
		return mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Name: name, Shorthand: shorthand})
	}
	withPrices(t, []mtgban.Seller{
		store("TCGDirect", "TCGplayer Direct"),
		store("CT", "Card Trader"),
		store("ZZRETAIL", "Some Retailer"),
	}, nil)
	options := selectOptions(fetchSettingsModal(t, grantSig(t, "Upload", "UploadCustom")), "opt-customseller")
	values := regexp.MustCompile(`<option value="([^"]+)"`).FindAllStringSubmatch(options, -1)
	seen := map[string]int{}
	for _, v := range values {
		seen[v[1]]++
	}
	for _, key := range []string{"TCGDirect", "CT", "ZZRETAIL"} {
		if seen[key] != 1 {
			t.Errorf("%s listed %d times:\n%s", key, seen[key], options)
		}
	}
}

// A seller of slabs named as its store is marked wherever stores are listed,
// sorts after it, and is never the one the store's name finds.
func TestGradedStoreSharingAName(t *testing.T) {
	store := func(name, shorthand string, graded bool, price float64) mtgban.Seller {
		return mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"card": {{Conditions: "NM", Price: price}}},
			mtgban.ScraperInfo{Name: name, Shorthand: shorthand, GradedMode: graded})
	}
	withPrices(t, []mtgban.Seller{
		store("Same Store", "ZZSLAB", true, 50),
		store("Same Store", "ZZSAME", false, 5),
		store("Other Store Graded", "ZZOTHER", true, 9),
	}, nil)
	p := currentPrices()

	for shorthand, want := range map[string]string{
		"ZZSAME":  "Same Store",
		"ZZSLAB":  "Same Store (Graded)",
		"ZZOTHER": "Other Store Graded",
	} {
		if got := p.storeNames()[shorthand]; got != want {
			t.Errorf("%s is listed as %q, want %q", shorthand, got, want)
		}
	}
	if got := sortKeysByScraperName(p, []string{"ZZSLAB", "ZZSAME"}); got[0] != "ZZSAME" {
		t.Errorf("sorted %v, want the raw store first", got)
	}
	if got := string(guideStoresJSON(p)); !strings.Contains(got, `"name":"Same Store (Graded)","code":"ZZSLAB"`) {
		t.Errorf("the guide lists %s, want the slab seller marked", got)
	}
	if got := storeFactorOptions(p, []string{"ZZSLAB"}, nil); !strings.Contains(got, "Same Store (Graded)") {
		t.Errorf("store factors offer %s, want the slab seller marked", got)
	}

	inv, err := findSellerInventoryByName(p, "same store", false)
	if err != nil || inv["card"][0].Price != 5 {
		t.Errorf("the name finds %v, %v; want the raw store", inv, err)
	}
}
