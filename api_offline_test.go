package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func offlineTestSig(email, offlineFlag string) string {
	v := url.Values{}
	v.Set("UserEmail", email)
	if offlineFlag != "" {
		v.Set("SearchOfflineMode", offlineFlag)
	}
	v.Set("Expires", "9999999999")
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

func TestOfflineModeAllowed(t *testing.T) {
	withSigMode(t, false, false)

	tests := []struct {
		name  string
		sig   string
		want  bool
		email string
	}{
		{"no sig", "", false, ""},
		{"flag missing", offlineTestSig("a@b.c", ""), false, ""},
		{"flag false", offlineTestSig("a@b.c", "false"), false, ""},
		{"flag true", offlineTestSig("a@b.c", "true"), true, "a@b.c"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/api/offline/manifest.json", nil)
		if tt.sig != "" {
			r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: tt.sig})
		}
		email, ok := offlineModeAllowed(r)
		if ok != tt.want || (tt.want && email != tt.email) {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", tt.name, email, ok, tt.email, tt.want)
		}
	}
}

// The grant is read off the signature that names the reader: a valid ?sig=
// without it does not lend its email to a forged cookie that claims it.
func TestOfflineModeReadsOneCheckedSignature(t *testing.T) {
	signingEnabled(t, false)
	plain := signedAs(t, url.Values{"UserEmail": {"a@b.c"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	granted := signedAs(t, url.Values{"UserEmail": {"a@b.c"}, "UserTier": {"Test"}, "SearchOfflineMode": {"true"}}, time.Now().Add(time.Hour))
	forged := offlineTestSig("a@b.c", "true")

	for _, tc := range []struct {
		name          string
		query, cookie string
		want          bool
	}{
		{"valid ?sig= beside a forged cookie", plain, forged, false},
		{"forged cookie alone", "", forged, false},
		{"granted ?sig=", granted, "", true},
		{"granted cookie", "", granted, true},
	} {
		target := "/api/offline/manifest.json"
		if tc.query != "" {
			target += "?sig=" + url.QueryEscape(tc.query)
		}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: tc.cookie})
		}
		email, ok := offlineModeAllowed(r)
		if ok != tc.want || (ok && email != "a@b.c") {
			t.Errorf("%s: got (%q, %v), want %v", tc.name, email, ok, tc.want)
		}
	}
}
