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
