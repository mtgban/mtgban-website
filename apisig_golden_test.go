package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
func TestEnforceAPISigningAcceptsGoldenBlob(t *testing.T) {
	if len(GetSellers()) == 0 || len(GetVendors()) == 0 {
		t.Skip("needs a loaded datastore; enforceAPISigning refuses with 503 otherwise")
	}
	oldCheck, oldURL := SigCheck, ServerURL
	SigCheck, ServerURL = true, "https://www.mtgban.com"
	t.Cleanup(func() { SigCheck, ServerURL = oldCheck, oldURL })

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

	blob := "QVBJPUFMTF9BQ0NFU1MmQVBJbW9kZT1hbGwmU2lnbmF0dXJlPU1tY0ZWZjBOMlBySzNvOHprOU81WWREcXo0ZyUzRCZVc2VyRW1haWw9Z29sZGVuJTQwZXhhbXBsZS5jb20="
	called := false
	h := enforceAPISigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest("GET", "/api/mtgban/stores.json?sig="+url.QueryEscape(blob), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatalf("valid blob rejected: %s", rec.Body.String())
	}

	called = false
	req = httptest.NewRequest("GET", "/api/mtgban/stores.json?sig="+url.QueryEscape(blob[:len(blob)-8]+"AAAAAAA="), nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || !strings.Contains(rec.Body.String(), "invalid or expired signature") {
		t.Errorf("tampered blob accepted, body %q", rec.Body.String())
	}
}
