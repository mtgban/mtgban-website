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

// Every key of the block decodes, and the durations come off the day counts.
func TestPatreonRenewalDecodesEveryKnob(t *testing.T) {
	var file Config
	err := json.Unmarshal([]byte(`{"patreon_renewal": {
		"after_days": 8, "grace_days": 3, "max_session_days": 60,
		"clear_on_negative": true, "renew_timeout_seconds": 7}}`), &file)
	if err != nil {
		t.Fatal(err)
	}
	got := file.PatreonRenewal
	want := PatreonRenewal{AfterDays: 8, GraceDays: 3, MaxSessionDays: 60, ClearOnNegative: true, RenewTimeoutSeconds: 7}
	if got != want {
		t.Errorf("block %+v, want %+v", got, want)
	}
	if got.After() != 8*24*time.Hour || got.Grace() != 3*24*time.Hour || got.RenewTimeout() != 7*time.Second {
		t.Errorf("after %v, grace %v, timeout %v; want 8 days, 3 days, 7s", got.After(), got.Grace(), got.RenewTimeout())
	}

	out, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	var again Config
	err = json.Unmarshal(out, &again)
	if err != nil || again.PatreonRenewal != want {
		t.Errorf("block written back as %s reads as %+v (%v), want %+v", out, again.PatreonRenewal, err, want)
	}
}

// A block that names nothing renews nothing, and a timeout that names no time
// waits five seconds.
func TestPatreonRenewalZeroValues(t *testing.T) {
	var zero PatreonRenewal
	if zero.After() != 0 || zero.Grace() != 0 {
		t.Errorf("an empty block renews after %v with %v grace, want neither", zero.After(), zero.Grace())
	}
	for _, seconds := range []int{0, -3} {
		got := PatreonRenewal{RenewTimeoutSeconds: seconds}.RenewTimeout()
		if got != 5*time.Second {
			t.Errorf("renew_timeout_seconds %d waits %v, want 5s", seconds, got)
		}
	}
	if DefaultRenewTimeoutSeconds != 5 {
		t.Errorf("default timeout %d, want 5", DefaultRenewTimeoutSeconds)
	}
}

// A deployment that sets any of the block replaces the file's whole, the
// knobs it leaves out included.
func TestOverPatreonRenewalReplacesTheWholeBlock(t *testing.T) {
	file := Config{PatreonRenewal: PatreonRenewal{AfterDays: 8, GraceDays: 3, ClearOnNegative: true, RenewTimeoutSeconds: 9}}

	got := Config{PatreonRenewal: PatreonRenewal{AfterDays: 1}}.Over(file).PatreonRenewal
	if got != (PatreonRenewal{AfterDays: 1}) {
		t.Errorf("block %+v, want the deployment's own after_days alone", got)
	}
	got = Config{}.Over(file).PatreonRenewal
	if got != file.PatreonRenewal {
		t.Errorf("block %+v, want the file's", got)
	}
}

// The secret decodes from the file's key, and stays out of the file the
// editor writes back while it is unset.
func TestPatreonWebhookSecretDecodes(t *testing.T) {
	var file Config
	err := json.Unmarshal([]byte(`{"patreon_webhook_secret": "hook-secret"}`), &file)
	if err != nil {
		t.Fatal(err)
	}
	if file.PatreonWebhookSecret != "hook-secret" {
		t.Errorf("secret %q, want the file's", file.PatreonWebhookSecret)
	}

	out, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	var again Config
	err = json.Unmarshal(out, &again)
	if err != nil || again.PatreonWebhookSecret != "hook-secret" {
		t.Errorf("secret written back as %s reads as %q (%v), want it kept", out, again.PatreonWebhookSecret, err)
	}

	out, err = json.Marshal(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "patreon_webhook_secret") {
		t.Errorf("an unset secret is written: %s", out)
	}
}

// A deployment that sets the secret keeps its own, and one that leaves it out
// takes the file's.
func TestOverPatreonWebhookSecret(t *testing.T) {
	file := Config{PatreonWebhookSecret: "file-secret"}

	got := Config{PatreonWebhookSecret: "own-secret"}.Over(file).PatreonWebhookSecret
	if got != "own-secret" {
		t.Errorf("secret %q, want the deployment's own", got)
	}
	got = Config{}.Over(file).PatreonWebhookSecret
	if got != "file-secret" {
		t.Errorf("secret %q, want the file's", got)
	}
	got = Config{}.Over(Config{}).PatreonWebhookSecret
	if got != "" {
		t.Errorf("secret %q, want none", got)
	}
}
