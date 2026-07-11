package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWorkerConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "config.json")
	err := os.WriteFile(good, []byte(`{
		"datastore_path": "AllPrintings.json.xz",
		"datastore": {
			"bucket_access_key": "k",
			"bucket_access_secret": "s",
			"offline_images_path": "offline-mirror"
		}
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := loadWorkerConfig(good)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatastorePath != "AllPrintings.json.xz" ||
		cfg.Datastore.BucketAccessKey != "k" ||
		cfg.Datastore.BucketSecretKey != "s" ||
		cfg.Datastore.OfflineImagesPath != "offline-mirror" {
		t.Fatalf("config mismatch: %+v", cfg)
	}

	noMirror := filepath.Join(dir, "bad.json")
	os.WriteFile(noMirror, []byte(`{"datastore_path": "x", "datastore": {}}`), 0644)
	if _, err := loadWorkerConfig(noMirror); err == nil {
		t.Error("missing offline_images_path should error")
	}

	if _, err := loadWorkerConfig(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("missing file should error")
	}
}
