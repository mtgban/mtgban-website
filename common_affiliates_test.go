package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// withAffiliateConfig points the config's affiliate fields at the given
// values for one test, restoring the config and the published value after.
func withAffiliateConfig(t *testing.T, codes map[string]string, list []string, path string) {
	t.Helper()
	saved := Config
	savedValue := affiliatesPtr.Load()
	t.Cleanup(func() {
		Config = saved
		affiliatesPtr.Store(savedValue)
	})
	Config.Affiliate = codes
	Config.AffiliatesList = list
	Config.AffiliatesBuylistList = nil
	Config.AffiliatesPath = path
}

// With no path set the inline config fields keep working, which is what lets
// this ship before any config is split.
func TestLoadAffiliatesFallsBackToTheConfig(t *testing.T) {
	withAffiliateConfig(t, map[string]string{"TCG": "12345"}, []string{"CK"}, "")
	if err := loadAffiliates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if Affiliates().Codes["TCG"] != "12345" {
		t.Errorf("codes did not come from the fallback: %v", Affiliates().Codes)
	}
	if len(Affiliates().List) != 1 {
		t.Errorf("got %d list entries from the fallback, want 1", len(Affiliates().List))
	}
}

// A path wins over the inline fields, wholly: values the file does not carry
// are not patched in from the config.
func TestLoadAffiliatesReadsThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affiliates.json")
	data := []byte(`{"affiliate": {"TCG": "67890"}, "affiliates_list": ["CK", "SCG"]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	withAffiliateConfig(t, map[string]string{"TCG": "12345"}, []string{"CK"}, path)
	if err := loadAffiliates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if Affiliates().Codes["TCG"] != "67890" {
		t.Errorf("codes did not come from the path: %v", Affiliates().Codes)
	}
	if len(Affiliates().List) != 2 {
		t.Errorf("got %d list entries from the path, want 2", len(Affiliates().List))
	}
	if Affiliates().BuylistList != nil {
		t.Errorf("buylist list not in the file but not empty: %v", Affiliates().BuylistList)
	}
}

// A configured path that cannot be read is an error, not a silent fallback,
// and the previously published value survives the failed reload.
func TestLoadAffiliatesKeepsTheValueOnError(t *testing.T) {
	withAffiliateConfig(t, map[string]string{"TCG": "12345"}, nil, "")
	if err := loadAffiliates(context.Background()); err != nil {
		t.Fatal(err)
	}

	Config.AffiliatesPath = filepath.Join(t.TempDir(), "nope.json")
	if err := loadAffiliates(context.Background()); err == nil {
		t.Fatal("missing affiliates path did not error")
	}
	if Affiliates().Codes["TCG"] != "12345" {
		t.Errorf("failed reload dropped the codes: %v", Affiliates().Codes)
	}
}
