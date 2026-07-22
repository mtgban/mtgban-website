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
			"bucket_access_secret": "s"
		},
		"offline": {
			"images_path": "offline-mirror"
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
		cfg.Offline.ImagesPath != "offline-mirror" {
		t.Fatalf("config mismatch: %+v", cfg)
	}

	withKeys := filepath.Join(dir, "keys.json")
	err = os.WriteFile(withKeys, []byte(`{
		"datastore_path": "AllPrintings.json.xz",
		"datastore": {
			"bucket_access_key": "k",
			"bucket_access_secret": "s"
		},
		"offline": {
			"images_path": "b2://mtgban-images/magic"
		},
		"bucket_keys": {
			"mtgban-images": {"access_key": "ik", "access_secret": "is"}
		}
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = loadWorkerConfig(withKeys)
	if err != nil {
		t.Fatal(err)
	}
	if key, secret := cfg.bucketCredentials("mtgban-images"); key != "ik" || secret != "is" {
		t.Errorf("mtgban-images: got %q/%q, want bucket_keys entry", key, secret)
	}
	if key, secret := cfg.bucketCredentials("mtgban-datastore"); key != "k" || secret != "s" {
		t.Errorf("mtgban-datastore: got %q/%q, want datastore fallback", key, secret)
	}

	noMirror := filepath.Join(dir, "bad.json")
	os.WriteFile(noMirror, []byte(`{"datastore_path": "x", "offline": {}}`), 0644)
	if _, err := loadWorkerConfig(noMirror); err == nil {
		t.Error("missing offline.images_path should error")
	}

	winAbsolute := filepath.Join(dir, "winabs.json")
	os.WriteFile(winAbsolute, []byte(`{"datastore_path": "x", "offline": {"images_path": "C:/mirror"}}`), 0644)
	if _, err := loadWorkerConfig(winAbsolute); err == nil {
		t.Error("Windows absolute path should error")
	}

	if _, err := loadWorkerConfig(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("missing file should error")
	}
}
