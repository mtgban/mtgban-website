package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// The index prices and the custom-buylist gate do not need a loaded store
// list, so they pin the parts of the Upload tab's data a fixture run can see.
func TestUploadSettingsKeysReadTheGrant(t *testing.T) {
	withSigMode(t, true, true)

	get := func(sig string) uploadModalKeys {
		req := httptest.NewRequest(http.MethodGet, "/api/settings/modal", nil)
		if sig != "" {
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		}
		return uploadSettingsKeys(req)
	}

	if got := get("").AltKeys; !slices.Equal(got, UploadIndexComparePriceList) {
		t.Errorf("AltKeys = %v, want UploadIndexComparePriceList", got)
	}
	if get(testSig(map[string]string{"Upload": "true"})).CanUploadCustom {
		t.Error("CanUploadCustom without the UploadCustom grant")
	}
	if !get(testSig(map[string]string{"UploadCustom": "true"})).CanUploadCustom {
		t.Error("CanUploadCustom false with the UploadCustom grant")
	}
}

// keepScrapers empties the loaded stores for the test, so every list is
// empty, which is still the contract: the functions return, in display
// order, whatever is loaded.
func TestSettingsKeysWithNoScrapers(t *testing.T) {
	keepScrapers(t)
	if sellers, vendors := searchSettingsKeys(); len(sellers) != 0 || len(vendors) != 0 {
		t.Errorf("search keys = %v %v, want none", sellers, vendors)
	}
	if got := arbitVendorKeys(arbitBlockedVendors(""), false); len(got) != 0 {
		t.Errorf("arbit keys = %v, want none", got)
	}
	if got := globalVendorKeys(globalProbeBlocklist()); len(got) != 0 {
		t.Errorf("global keys = %v, want none", got)
	}
	r, b := sleepBlocklists("")
	if s, v := sleepModalKeys(r, b); len(s) != 0 || len(v) != 0 {
		t.Errorf("sleep keys = %v %v, want none", s, v)
	}
}

// A tab exists only for a page in the reader's nav, in rail order, and the
// Offline tab only with the grant the Search section checked.
func TestSettingsTabsFollowTheNav(t *testing.T) {
	nav := func(names ...string) []NavElem {
		var out []NavElem
		for _, name := range names {
			out = append(out, NavElem{Name: name, SettingsTab: ExtraNavs[name].SettingsTab})
		}
		return out
	}
	cases := []struct {
		name    string
		nav     []NavElem
		offline bool
		want    []string
	}{
		{"nothing", nil, false, nil},
		{"offline alone", nil, true, []string{"offline"}},
		{"search only", nav("Search"), false, []string{"search"}},
		{"global only", nav("Global"), false, []string{"arbit"}},
		{"three arbit routes make one tab", nav("Global", "Arbit", "Reverse"), false, []string{"arbit"}},
		{"rail order, not nav order", nav("Sleepers", "Newspaper", "Upload", "Search"), true,
			[]string{"search", "upload", "news", "sleep", "offline"}},
		{"pages without settings add nothing", nav("Screener", "Alerts", "Search"), false, []string{"search"}},
	}
	for _, c := range cases {
		if got := settingsTabs(c.nav, c.offline); !slices.Equal(got, c.want) {
			t.Errorf("%s: settingsTabs = %v, want %v", c.name, got, c.want)
		}
	}
}

// Sub-pages carry their section's tab: Sealed opens on Search's.
func TestSettingsTabOnSubPages(t *testing.T) {
	for _, sub := range ExtraNavs["Search"].SubPages {
		if sub.Name == "Sealed" && sub.SettingsTab != "search" {
			t.Errorf("Sealed.SettingsTab = %q, want search", sub.SettingsTab)
		}
	}
	for _, sub := range ExtraNavs["Newspaper"].SubPages {
		if sub.Name == "TCG Syp List" && sub.SettingsTab != "news" {
			t.Errorf("Syp.SettingsTab = %q, want news", sub.SettingsTab)
		}
	}
}
