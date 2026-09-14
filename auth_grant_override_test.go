package main

import (
	"net/url"
	"testing"
)

// A grant's Overrides applies after its tier's own table, so it wins on the
// keys it names and leaves everything else the tier set untouched.
func TestApplyACLOverridesWinOverTier(t *testing.T) {
	v := url.Values{}
	tier := map[string]map[string]string{
		"Search": {"SearchOfflineMode": "false"},
		"Upload": {"UploadOptimizer": "true"},
	}
	overrides := map[string]map[string]string{
		"Search": {"SearchOfflineMode": "true"},
	}

	applyACL(v, tier)
	applyACL(v, overrides)

	if got := v.Get("SearchOfflineMode"); got != "true" {
		t.Errorf("SearchOfflineMode = %q, want %q (override should win)", got, "true")
	}
	if got := v.Get("UploadOptimizer"); got != "true" {
		t.Errorf("UploadOptimizer = %q, want %q (untouched by override, should keep the tier's value)", got, "true")
	}
	if got := v.Get("Search"); got != "true" {
		t.Errorf("Search = %q, want %q (page stays enabled)", got, "true")
	}
	if got := v.Get("Upload"); got != "true" {
		t.Errorf("Upload = %q, want %q (page stays enabled)", got, "true")
	}
}

// A nil Overrides map (the common case: a grant with no overrides) must not
// touch anything the tier already set.
func TestApplyACLNilOverridesIsANoop(t *testing.T) {
	v := url.Values{}
	tier := map[string]map[string]string{
		"Search": {"SearchOfflineMode": "false"},
	}

	applyACL(v, tier)
	applyACL(v, nil)

	if got := v.Get("SearchOfflineMode"); got != "false" {
		t.Errorf("SearchOfflineMode = %q, want %q (nil overrides must not change it)", got, "false")
	}
}

// An override can turn on a page the tier itself never granted, scoped to
// just this one signed user.
func TestApplyACLOverridesCanEnableANewPage(t *testing.T) {
	v := url.Values{}
	tier := map[string]map[string]string{
		"Search": {},
	}
	overrides := map[string]map[string]string{
		"Global": {},
	}

	applyACL(v, tier)
	applyACL(v, overrides)

	if got := v.Get("Global"); got != "true" {
		t.Errorf("Global = %q, want %q (override should be able to grant a new page)", got, "true")
	}
}
