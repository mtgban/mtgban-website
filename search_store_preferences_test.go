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
	retail, buylist, personalized := getSearchBlocklists(r, sig, false)

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

func TestGetSearchBlocklistsSealedPreferences(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString([]byte("SearchDisabled=NONE&SearchBuylistDisabled=NONE"))
	tests := []struct {
		name       string
		cookie     string
		wantRetail []string
		wantBuy    []string
	}{
		{
			name:       "sealed values win",
			cookie:     "SearchSellersList=singles-seller; SearchVendorsList=singles-vendor; SearchSealedSellersList=sealed-seller; SearchSealedVendorsList=sealed-vendor",
			wantRetail: []string{"sealed-seller"},
			wantBuy:    []string{"sealed-vendor"},
		},
		{
			name:       "explicitly cleared sealed values do not fall back",
			cookie:     "SearchSellersList=singles-seller; SearchVendorsList=singles-vendor; SearchSealedSellersList=" + emptySearchListCookieValue + "; SearchSealedVendorsList=" + emptySearchListCookieValue,
			wantRetail: nil,
			wantBuy:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/sealed", nil)
			r.Header.Set("Cookie", tt.cookie)
			retail, buylist, personalized := getSearchBlocklists(r, sig, true)
			if !equalStrings(retail, tt.wantRetail) {
				t.Errorf("retail blocklist = %#v, want %#v", retail, tt.wantRetail)
			}
			if !equalStrings(buylist, tt.wantBuy) {
				t.Errorf("buylist blocklist = %#v, want %#v", buylist, tt.wantBuy)
			}
			if !personalized {
				t.Error("sealed preferences should mark the response personalized")
			}
		})
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
