package main

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// withConfigFile starts the config over from a local file, the way a process
// does, and puts back what loadVars replaces or rebuilds when the test ends.
func withConfigFile(t *testing.T) string {
	t.Helper()
	saved, savedBucket, savedRegistry := Config(), ConfigBucket, chartProviders()
	t.Cleanup(func() {
		liveConfig.Store(saved)
		ConfigBucket = savedBucket
		providerRegistry.Store(&savedRegistry)
	})
	withSigMode(t, false, true)
	t.Setenv("BAN_SECRET", "test-secret")

	path := filepath.Join(t.TempDir(), "config.json")
	err := preloadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestConfig(t *testing.T, path, body string) {
	t.Helper()
	err := os.WriteFile(path, []byte(body), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

// A key or a field deleted from the file is gone after a reload, as after a
// restart. Decoding into the live config merged instead, so a revoked API
// secret kept verifying until the process restarted.
func TestConfigReloadDropsWhatTheFileDropped(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{
		"game": "lorcana",
		"port": "8080",
		"api_user_secrets": {"kept@example.com": "a", "revoked@example.com": "b"}
	}`)
	err := loadVars("8081", "", "flag-acl.json", "flag-grants.json")
	if err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, path, `{
		"game": "lorcana",
		"port": "8080",
		"api_user_secrets": {"kept@example.com": "a"}
	}`)
	err = reloadConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, found := Config().APIUserSecrets["revoked@example.com"]
	if found || Config().APIUserSecrets["kept@example.com"] != "a" {
		t.Errorf("api_user_secrets %v, want only the key the file still has", Config().APIUserSecrets)
	}

	// What loadVars adds to the file it adds again.
	for _, c := range []struct{ name, got, want string }{
		{"source path", Config().sourcePath, path},
		{"-port, over the file's port", Config().Port, "8081"},
		{"-acl", Config().ACLPath, "flag-acl.json"},
		{"-grants", Config().PatreonGrantsPath, "flag-grants.json"},
		{"default datastore path", Config().DatastorePath, DefaultDatastorePath},
		{"default gateway", Config().APIGateway.URL, DefaultAPIGatewayURL},
		{"default discord guild", Config().Discord.GuildID, defaultDiscordGuildID},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !slices.Equal(Config().APIGateway.Games, []mtgmatcher.Game{DefaultGame, "lorcana"}) {
		t.Errorf("gateway games %v, want the default game and this one", Config().APIGateway.Games)
	}
}

// A reload that fails leaves the live config alone. Decoding into the live one
// half-applied a file with a type error: its game and its secrets went live
// while the reload reported the failure.
func TestConfigReloadFailureKeepsTheConfig(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"game": "lorcana", "api_user_secrets": {"kept@example.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, path, `{"game": "onepiece", "api_user_secrets": {"new@example.com": "b"}, "instance_name": 5}`)
	err = reloadConfig()
	if err == nil {
		t.Fatal("a file with a type error reloaded")
	}
	want := map[string]string{"kept@example.com": "a"}
	if Config().Game != "lorcana" || !maps.Equal(Config().APIUserSecrets, want) {
		t.Errorf("game %q, api_user_secrets %v: the failed reload changed the live config",
			Config().Game, Config().APIUserSecrets)
	}
}

// A config naming a datasets file that cannot be read charts nothing.
func TestUnreadableDatasetsPathChartsNothing(t *testing.T) {
	path := withConfigFile(t)
	savedDatasets := datasetsPtr.Load()
	datasetsPtr.Store(nil)
	t.Cleanup(func() { datasetsPtr.Store(savedDatasets) })

	writeTestConfig(t, path, `{
		"port": "8080",
		"datasets_path": "`+filepath.Join(t.TempDir(), "nope.json")+`"
	}`)
	err := loadVars("8081", "", "flag-acl.json", "flag-grants.json")
	if err != nil {
		t.Fatal(err)
	}
	err = loadDatasets(context.Background())
	if err == nil {
		t.Fatal("unreadable datasets path did not error")
	}
	if len(Datasets()) != 0 || len(chartProviders()) != 0 {
		t.Errorf("datasets %+v, registry %+v: want both empty", Datasets(), chartProviders())
	}
}
