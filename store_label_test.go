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
