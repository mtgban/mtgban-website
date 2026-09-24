package main

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

func TestGetSearchBlocklists(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/prices/", nil)
	r.Header.Set("Cookie", "SearchSellersList=TCGMarket,SCG,; SearchVendorsList=CK,")

	sig := base64.StdEncoding.EncodeToString([]byte("SearchDisabled=CONFIG_SELLER&SearchBuylistDisabled=CONFIG_VENDOR"))
	retail, buylist, personalized := getSearchBlocklists(r, sig)

	if got, want := retail, []string{"CONFIG_SELLER", "TCGMarket", "SCG"}; !equalStrings(got, want) {
		t.Errorf("retail blocklist = %#v, want %#v", got, want)
	}
	if got, want := buylist, []string{"CONFIG_VENDOR", "CK"}; !equalStrings(got, want) {
		t.Errorf("buylist blocklist = %#v, want %#v", got, want)
	}
	if !personalized {
		t.Error("store preferences should mark the response personalized")
	}
}

// Every request appends its reader's own stores to the config's lists. With
// spare capacity behind them, two readers' appends land in the same slots and
// one sees the other's stores.
func TestDefaultBlocklistsAreSafeToAppendTo(t *testing.T) {
	prev := Config.SearchRetailBlockList
	t.Cleanup(func() { Config.SearchRetailBlockList = prev })
	Config.SearchRetailBlockList = append(make([]string, 0, 4), "CONFIG_SELLER")

	a, _ := getDefaultBlocklists("")
	a = append(a, "CK")
	b, _ := getDefaultBlocklists("")
	b = append(b, "SCG")

	if a[1] != "CK" || b[1] != "SCG" {
		t.Errorf("one reader's blocklist became %v and the other's %v", a, b)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
