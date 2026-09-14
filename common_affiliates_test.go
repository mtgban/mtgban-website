package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withAffiliateConfig points the config's affiliates path at the given
// value for one test, restoring the config and the published value after.
func withAffiliateConfig(t *testing.T, path string) {
	t.Helper()
	saved := Config
	savedValue := affiliatesPtr.Load()
	t.Cleanup(func() {
		Config = saved
		affiliatesPtr.Store(savedValue)
	})
	Config.AffiliatesPath = path
}

// With no path configured, both Load and Save refuse rather than reaching
// for a path that names no file.
func TestNoAffiliatesPathIsRefused(t *testing.T) {
	withAffiliateConfig(t, "")
	if err := loadAffiliates(context.Background()); err == nil {
		t.Error("load with no affiliates path did not error")
	}
	if err := saveAffiliates(context.Background(), AffiliatesConfig{}); err == nil {
		t.Error("save with no affiliates path did not error")
	}
}

// A Load reads the affiliate data from its shared file.
func TestLoadAffiliatesReadsThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affiliates.json")
	data := []byte(`{"affiliate": {"TCG": "67890"}, "affiliates_list": ["CK", "SCG"]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	withAffiliateConfig(t, path)
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

// A save writes the shared file and publishes the value. (The peer
// notification is a no-op here: tests run without a price DB.)
func TestSaveAffiliatesWritesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affiliates.json")
	withAffiliateConfig(t, path)

	next := AffiliatesConfig{Codes: map[string]string{"TCG": "67890"}, List: []string{"CK"}}
	if err := saveAffiliates(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if Affiliates().Codes["TCG"] != "67890" {
		t.Errorf("published codes are not the saved ones: %v", Affiliates().Codes)
	}

	var onDisk AffiliatesConfig
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Codes["TCG"] != "67890" || len(onDisk.List) != 1 {
		t.Errorf("file holds %+v, want the saved value", onDisk)
	}
}

// A configured path that cannot be read is an error, not a silent fallback,
// and the previously published value survives the failed reload.
func TestLoadAffiliatesKeepsTheValueOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affiliates.json")
	data := []byte(`{"affiliate": {"TCG": "12345"}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	withAffiliateConfig(t, path)
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
