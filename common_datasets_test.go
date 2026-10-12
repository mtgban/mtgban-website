package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDatasetsConfig points the config's datasets path at the given value
// for one test, restoring the config, the published datasets and the chart
// providers after.
func withDatasetsConfig(t *testing.T, path string) {
	t.Helper()
	withConfigCopy(t)
	savedValue := datasetsPtr.Load()
	savedRegistry := providerRegistry.Load()
	t.Cleanup(func() {
		datasetsPtr.Store(savedValue)
		providerRegistry.Store(savedRegistry)
	})
	Config().DatasetsPath = path
}

// With no path configured the datasets are the config's own.
func TestDatasetsWithoutAPathAreTheConfigs(t *testing.T) {
	withDatasetsConfig(t, "")
	Config().TimeseriesConfig = TimeseriesConfig{Datasets: []DatasetConfig{
		{PublicName: "Inline", Provider: 3},
	}}

	err := loadDatasets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := Datasets()
	if len(got) != 1 || got[0].PublicName != "Inline" {
		t.Errorf("datasets did not come from the config: %+v", got)
	}
}

// A configured path wins over the config's datasets, and the chart providers
// are rebuilt from the file.
func TestLoadDatasetsReadsThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasets.json")
	data := []byte(`[{"retail": ["TCGMarket"], "public_name": "TCGplayer Market", "index": 3, "provider": 4, "color": "rgb(255, 159, 64)"}]`)
	err := os.WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	withDatasetsConfig(t, path)
	Config().TimeseriesConfig = TimeseriesConfig{Datasets: []DatasetConfig{
		{PublicName: "Inline", Provider: 3},
	}}
	err = loadDatasets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := Datasets()
	if len(got) != 1 || got[0].PublicName != "TCGplayer Market" || got[0].Retail[0] != "TCGMarket" {
		t.Errorf("datasets did not come from the path: %+v", got)
	}
	providers := chartProviders()
	if len(providers) != 1 || providers[0].Provider != 4 {
		t.Errorf("providers were not rebuilt from the path: %+v", providers)
	}
}

// A configured path that cannot be read is an error, not a silent fallback,
// and the previously published datasets survive the failed reload.
func TestLoadDatasetsKeepsTheValueOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasets.json")
	err := os.WriteFile(path, []byte(`[{"public_name": "Kept", "provider": 4}]`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	withDatasetsConfig(t, path)
	err = loadDatasets(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	Config().DatasetsPath = filepath.Join(t.TempDir(), "nope.json")
	err = loadDatasets(context.Background())
	if err == nil {
		t.Fatal("missing datasets path did not error")
	}
	got := Datasets()
	if len(got) != 1 || got[0].PublicName != "Kept" {
		t.Errorf("failed reload dropped the datasets: %+v", got)
	}
}

// With no path configured a save refuses rather than reaching for a path that
// names no file.
func TestNoDatasetsPathRefusesSave(t *testing.T) {
	withDatasetsConfig(t, "")
	err := saveDatasets(context.Background(), []DatasetConfig{{PublicName: "Saved", Provider: 4}})
	if err == nil {
		t.Error("save with no datasets path did not error")
	}
}

// A save writes the file, publishes the datasets and rebuilds the chart
// providers from them. (The peer notification is a no-op here: tests run
// without a price DB.)
func TestSaveDatasetsWritesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasets.json")
	withDatasetsConfig(t, path)

	err := saveDatasets(context.Background(), []DatasetConfig{{PublicName: "Saved", Provider: 4}})
	if err != nil {
		t.Fatal(err)
	}
	got := Datasets()
	if len(got) != 1 || got[0].PublicName != "Saved" {
		t.Errorf("published datasets are not the saved ones: %+v", got)
	}
	providers := chartProviders()
	if len(providers) != 1 || providers[0].Name != "Saved" {
		t.Errorf("providers were not rebuilt from the save: %+v", providers)
	}

	datasetsPtr.Store(nil)
	err = loadDatasets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got = Datasets()
	if len(got) != 1 || got[0].PublicName != "Saved" || got[0].Provider != 4 {
		t.Errorf("file holds %+v, want the saved datasets", got)
	}
}

// The Datasets tab offers Update only when there is a file to save to.
func TestAdminDatasetsUpdateNeedsAPath(t *testing.T) {
	pv := PageVars{UserNav: &NavElem{Short: "b"}}
	const update = `data-update-for="datasets"`

	withDatasetsConfig(t, "")
	out := renderPage(t, "admin.html", false, pv)
	if strings.Contains(out, update) {
		t.Error("Update offered with no datasets path")
	}
	if !strings.Contains(out, "timeseries_config.datasets (read-only)") {
		t.Error("tab does not say the config's datasets are read-only")
	}

	Config().DatasetsPath = "datasets.json"
	out = renderPage(t, "admin.html", false, pv)
	if !strings.Contains(out, update) {
		t.Error("Update not offered with a datasets path")
	}
}
