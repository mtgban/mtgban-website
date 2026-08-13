package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
	oldDev, oldSig := DevMode, SigCheck
	DevMode, SigCheck = false, false
	defer func() { DevMode, SigCheck = oldDev, oldSig }()

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
