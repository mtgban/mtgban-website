package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

func TestRebuildBundlesIsolatesSetFailures(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	os.MkdirAll(filepath.Join(base, "images"), 0755)
	os.WriteFile(filepath.Join(base, "images", "uuid-good.webp"), []byte("img-good"), 0644)
	// uuid-bad has state but no backing image file, so its set fails.

	state := imgmirror.State{
		"uuid-good": {Digest: "d1", Source: "s"},
		"uuid-bad":  {Digest: "d2", Source: "s"},
	}
	want := map[string]imgmirror.Card{
		"uuid-good": {URL: "s", SetCode: "NEO"},
		"uuid-bad":  {URL: "s", SetCode: "MID"},
	}

	err := rebuildBundles(context.Background(), &simplecloud.FileBucket{}, base, state, want, imgmirror.Manifest{})
	if err == nil {
		t.Fatal("expected aggregate error for the failed set")
	}

	got, err := loadManifest(context.Background(), &simplecloud.FileBucket{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["NEO"]; !ok {
		t.Error("surviving set NEO missing from saved manifest")
	}
	if _, ok := got["MID"]; ok {
		t.Error("failed set MID must not enter the manifest")
	}
}
