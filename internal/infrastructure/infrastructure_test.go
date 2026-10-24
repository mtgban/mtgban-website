package infrastructure

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

// The block decodes from the file's key, and a session lasts the days it
// names, 90 when it names none.
func TestPatreonRenewalMaxSession(t *testing.T) {
	var file Config
	err := json.Unmarshal([]byte(`{"patreon_renewal": {"max_session_days": 30}}`), &file)
	if err != nil {
		t.Fatal(err)
	}
	if file.PatreonRenewal.MaxSessionDays != 30 || file.PatreonRenewal.MaxSession() != 30*24*time.Hour {
		t.Errorf("block %+v lasts %v, want 30 days", file.PatreonRenewal, file.PatreonRenewal.MaxSession())
	}

	for _, days := range []int{0, -1} {
		got := PatreonRenewal{MaxSessionDays: days}.MaxSession()
		if got != 90*24*time.Hour {
			t.Errorf("max_session_days %d lasts %v, want 90 days", days, got)
		}
	}
	if DefaultMaxSessionDays != 90 {
		t.Errorf("default %d, want 90", DefaultMaxSessionDays)
	}
}

// An unset block stays out of the file the editor writes back.
func TestPatreonRenewalOmittedWhenUnset(t *testing.T) {
	out, err := json.Marshal(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "patreon_renewal") {
		t.Errorf("an unset block is written: %s", out)
	}
}

// The block is overridden whole once the deployment sets any of it, and
// inherited when it is left zero.
func TestOverPatreonRenewal(t *testing.T) {
	file := Config{PatreonRenewal: PatreonRenewal{MaxSessionDays: 90}}

	got := Config{PatreonRenewal: PatreonRenewal{MaxSessionDays: 14}}.Over(file).PatreonRenewal
	if got.MaxSessionDays != 14 {
		t.Errorf("patreon renewal %+v, want the deployment's own", got)
	}
	got = Config{}.Over(file).PatreonRenewal
	if got.MaxSessionDays != 90 {
		t.Errorf("patreon renewal %+v, want the file's", got)
	}
}
