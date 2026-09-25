package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
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

func TestRequestOrigin(t *testing.T) {
	tests := []struct {
		name, host, proto, want string
	}{
		{"forwarded", "onepiece.mtgban.com", "https", "https://onepiece.mtgban.com"},
		{"forwarded first hop", "onepiece.mtgban.com, attacker.example", "https, http", "https://onepiece.mtgban.com"},
		{"port", "magic.mtgban.com:8080", "", "http://magic.mtgban.com:8080"},
		{"untrusted", "attacker.example", "https", ""},
		{"malformed trusted suffix", "junk onepiece.mtgban.com", "https", ""},
		{"invalid port", "onepiece.mtgban.com:port", "https", ""},
		{"invalid proto", "onepiece.mtgban.com", "ftp", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			if tt.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			if strings.Contains(tt.host, ",") {
				req.Header.Set("X-Forwarded-Host", tt.host)
				req.Host = "internal:8080"
			}
			if got := requestOrigin(req); got != tt.want {
				t.Fatalf("requestOrigin = %q, want %q", got, tt.want)
			}
		})
	}

	if got := requestOrigin(nil); got != "" {
		t.Fatalf("requestOrigin(nil) = %q, want empty", got)
	}

	req := httptest.NewRequest("GET", "https://onepiece.mtgban.com/", nil)
	if got := requestOrigin(req); got != "https://onepiece.mtgban.com" {
		t.Fatalf("host-only HTTPS requestOrigin = %q, want https://onepiece.mtgban.com", got)
	}
}

func TestIsSecureRequestRequiresTrustedHost(t *testing.T) {
	for _, tt := range []struct {
		name, host, proto string
		want              bool
	}{
		{"trusted forwarded", "onepiece.mtgban.com", "https", true},
		{"untrusted forwarded", "attacker.example", "https", false},
		{"trusted direct TLS", "onepiece.mtgban.com", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			url := "http://" + tt.host + "/"
			if tt.name == "trusted direct TLS" {
				url = "https://" + tt.host + "/"
			}
			req := httptest.NewRequest("GET", url, nil)
			if tt.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			if got := isSecureRequest(req); got != tt.want {
				t.Fatalf("isSecureRequest = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicURLFallbacks(t *testing.T) {
	if got := absoluteURL(nil, "/go/"); got != "/go/" {
		t.Fatalf("absoluteURL(nil) = %q, want /go/", got)
	}
	if got := externalURL(nil); got != DefaultExternalURL {
		t.Fatalf("externalURL(nil) = %q, want %q", got, DefaultExternalURL)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "onepiece.mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := absoluteURL(req, "/go/"); got != "https://onepiece.mtgban.com/go/" {
		t.Fatalf("absoluteURL = %q, want request origin", got)
	}
}

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

func TestGenerateAPIKeyRejectsUnexpiredDemoKey(t *testing.T) {
	if _, err := generateAPIKey(context.Background(), DefaultAPIDemoUser, 0); err == nil {
		t.Fatal("generateAPIKey accepted a no-expiration demo key")
	}
}

// Every field an API key signs must be one the middleware verifies, or a
// minted key fails closed on this site.
func TestOptionalFieldsCoverAPIFields(t *testing.T) {
	for _, name := range apisig.APIFields {
		if !slices.Contains(OptionalFields, name) {
			t.Errorf("OptionalFields lacks %q", name)
		}
	}
}

func TestEnforceAPISigningDoesNotNeedServerURL(t *testing.T) {
	// enforceAPISigning only checks these are non-empty, and the stub next
	// handler never reads them, so one nil element each is enough.
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{nil}
	vendors := []mtgban.Vendor{nil}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	oldCheck, oldDev := SigCheck, DevMode
	SigCheck, DevMode = true, false
	t.Cleanup(func() { SigCheck, DevMode = oldCheck, oldDev })

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

	called := false
	h := enforceAPISigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/api/load/tcg_sealed?sig="+url.QueryEscape(
		"QVBJPUFMTF9BQ0NFU1MmQVBJbW9kZT1hbGwmU2lnbmF0dXJlPU1tY0ZWZjBOMlBySzNvOHprOU81WWREcXo0ZyUzRCZVc2VyRW1haWw9Z29sZGVuJTQwZXhhbXBsZS5jb20="), nil)
	req.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("valid cold-start request rejected: code %d body %s", rec.Code, rec.Body.String())
	}
}

// TestEnforceAPISigningAcceptsGoldenBlob runs the real middleware over the
// golden blob: accepted when valid, refused when tampered, and refused when
// Expires is unparseable even though the signature over it is good.
func TestEnforceAPISigningAcceptsGoldenBlob(t *testing.T) {
	// enforceAPISigning only checks these are non-empty, and the stub next
	// handler never reads them, so one nil element each is enough.
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
	sellers := []mtgban.Seller{nil}
	vendors := []mtgban.Vendor{nil}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	oldCheck, oldDev := SigCheck, DevMode
	SigCheck, DevMode = true, false
	t.Cleanup(func() { SigCheck, DevMode = oldCheck, oldDev })

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
	const wantErr = `{"error": "invalid or expired signature"}`

	called := false
	h := enforceAPISigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	// Each leg gets its own IP so the shared rate limiter cannot deny one.
	serve := func(sig, ip string) *httptest.ResponseRecorder {
		t.Helper()
		called = false
		req := httptest.NewRequest("GET", "/api/mtgban/stores.json?sig="+url.QueryEscape(sig), nil)
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := serve(blob, "192.0.2.1")
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("valid blob rejected: code %d body %s", rec.Code, rec.Body.String())
	}

	rec = serve(blob[:len(blob)-8]+"AAAAAAA=", "192.0.2.2")
	if called || strings.TrimSpace(rec.Body.String()) != wantErr {
		t.Errorf("tampered blob accepted, body %q", rec.Body.String())
	}

	// A valid signature over an unparseable Expires still has to be refused.
	v, err := apisig.Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("API", v.Get("API"))
	q.Set("APImode", v.Get("APImode"))
	q.Set("UserEmail", v.Get("UserEmail"))
	q.Set("Expires", "soon")
	v.Set("Expires", "soon")
	v.Set("Signature", apisig.Sign([]byte(goldenSecret), []byte("GET"+"soon"+apisig.DefaultLink+q.Encode())))
	badExpires := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	rec = serve(badExpires, "192.0.2.3")
	if called || strings.TrimSpace(rec.Body.String()) != wantErr {
		t.Errorf("bad Expires accepted, body %q", rec.Body.String())
	}
}
