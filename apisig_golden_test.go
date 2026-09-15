package main

import (
	"context"
	"testing"
)

// Golden vectors for the API signature format. The gateway repo mints
// signatures the game backends verify, so these bytes must never change.
const (
	goldenSecret = "golden-secret"

	// GET + Expires + DefaultServerURL + url.Values.Encode() of
	// API, APImode, Expires, UserEmail (sorted by key by Encode).
	goldenDataWithExpiry = "GET1800000000http://www.mtgban.comAPI=BASE_ACCESS&APImode=retail%2Cbuylist&Expires=1800000000&UserEmail=golden%40example.com"
	goldenSigWithExpiry  = "u/Ep9NoOIBriYtarJXp5WYSlkQM="

	goldenDataNoExpiry = "GEThttp://www.mtgban.comAPI=ALL_ACCESS&APImode=all&UserEmail=golden%40example.com"
	goldenSigNoExpiry  = "MmcFVf0N2PrK3o8zk9O5YdDqz4g="
)

func TestAPISignatureGolden(t *testing.T) {
	cases := []struct {
		name, data, want string
	}{
		{"with expiry", goldenDataWithExpiry, goldenSigWithExpiry},
		{"no expiry", goldenDataNoExpiry, goldenSigNoExpiry},
	}
	for _, c := range cases {
		got := signHMACSHA1Base64([]byte(goldenSecret), []byte(c.data))
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestGenerateAPIKeyMatchesApisig(t *testing.T) {
	oldURL := ServerURL
	ServerURL = "https://www.mtgban.com"
	t.Cleanup(func() { ServerURL = oldURL })

	apiUsersMutex.Lock()
	if Config.APIUserSecrets == nil {
		Config.APIUserSecrets = map[string]string{}
	}
	Config.APIUserSecrets["golden@example.com"] = goldenSecret
	apiUsersMutex.Unlock()
	t.Cleanup(func() {
		apiUsersMutex.Lock()
		delete(Config.APIUserSecrets, "golden@example.com")
		apiUsersMutex.Unlock()
	})

	// Duration 0 means no Expires, so the output is deterministic.
	got, err := generateAPIKey(context.Background(), "golden@example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "QVBJPUFMTF9BQ0NFU1MmQVBJbW9kZT1hbGwmU2lnbmF0dXJlPU1tY0ZWZjBOMlBySzNvOHprOU81WWREcXo0ZyUzRCZVc2VyRW1haWw9Z29sZGVuJTQwZXhhbXBsZS5jb20="
	if got != want {
		t.Errorf("generateAPIKey:\n got %q\nwant %q", got, want)
	}
}
