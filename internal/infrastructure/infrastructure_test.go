package infrastructure

import (
	"testing"

	"github.com/mtgban/mtgban-website/timeseries"
)

// A key the deployment sets replaces the file's whole; a key it leaves out
// comes from the file.
func TestOverReplacesWholeKeys(t *testing.T) {
	file := Config{
		SQLConfig:           &timeseries.SQLConfig{DBName: "file_prices"},
		BucketKeys:          map[string]BucketKey{"mtgban-datastore": {AccessKey: "file"}},
		GoogleCredentials:   "file.json",
		Uploader:            map[string]string{"moxfield": "https://file"},
		HandoffOrigins:      map[string]HandoffOrigin{"https://www.cardmarket.com": {Name: "Cardmarket"}},
		ObservabilityConfig: &timeseries.SQLConfig{DBName: "file_obs"},
	}
	own := Config{
		Uploader:            map[string]string{"collectr": "https://own"},
		ObservabilityConfig: &timeseries.SQLConfig{DBName: "own_obs"},
	}

	got := own.Over(file)
	if got.BucketKeys["mtgban-datastore"].AccessKey != "file" || got.GoogleCredentials != "file.json" || got.SQLConfig.DBName != "file_prices" {
		t.Errorf("unset keys %+v, want the file's", got)
	}
	if got.HandoffOrigins["https://www.cardmarket.com"].Name != "Cardmarket" {
		t.Errorf("handoff origins %v, want the file's", got.HandoffOrigins)
	}
	if len(got.Uploader) != 1 || got.Uploader["collectr"] != "https://own" {
		t.Errorf("uploader %v, want the deployment's own, whole", got.Uploader)
	}
	if got.ObservabilityConfig.DBName != "own_obs" {
		t.Errorf("observability db %q, want the deployment's own", got.ObservabilityConfig.DBName)
	}
}

// Patreon is overridden whole once the deployment sets any of it, and
// inherited when it is left zero.
func TestOverPatreon(t *testing.T) {
	file := Config{Patreon: Patreon{
		Source: "file",
		Client: map[string]string{"file": "file-client"},
		Secret: map[string]string{"file": "file-secret"},
	}}

	got := Config{Patreon: Patreon{Source: "own"}}.Over(file).Patreon
	if got.Source != "own" || got.Client != nil || got.Secret != nil {
		t.Errorf("patreon %+v, want the deployment's own, whole", got)
	}
	got = Config{}.Over(file).Patreon
	if got.Source != "file" || got.Client["file"] != "file-client" || got.Secret["file"] != "file-secret" {
		t.Errorf("patreon %+v, want the file's", got)
	}
}
