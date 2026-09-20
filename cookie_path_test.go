package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookiePath(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		global bool
		want   string
	}{
		{"SearchSellersList", "/search", false, "/"},
		{"SearchVendorsList", "/sealed", false, "/"},
		{"NewspaperList", "/newspaper?page=syp", false, "/newspaper"},
		{"SleepersEditionList", "/sleepers/bulk", false, "/sleepers"},
		{"ArbitVendorsList", "/arbit", false, "/arbit"},
		{"GlobalEditionList", "/global", false, "/global"},
		{"UploadOptimizerOpts", "/upload", false, "/upload"},
		{"MTGBAN", "/auth", true, "/"},
		{"Unknown", "/", false, "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://onepiece.mtgban.com"+tt.path, nil)
			if got := cookiePath(req, tt.name, tt.global); got != tt.want {
				t.Fatalf("cookiePath(%q, %q, %v) = %q, want %q", tt.name, tt.path, tt.global, got, tt.want)
			}
		})
	}
}

func TestSetCookieUsesRequestPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"SearchSellersList", "/sealed", "/"},
		{"NewspaperList", "/newspaper", "/newspaper"},
		{"SleepersEditionList", "/sleepers", "/sleepers"},
		{"UploadOptimizerOpts", "/upload", "/upload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://onepiece.mtgban.com"+tc.path, nil)
			recorder := httptest.NewRecorder()
			setCookie(recorder, req, tc.name, "value", time.Now().Add(time.Hour), false)
			if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, "Path="+tc.want+";") {
				t.Fatalf("Set-Cookie = %q, want Path=%s", got, tc.want)
			}
		})
	}
}

func TestSetCookieExpiresLegacyRootCopy(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://onepiece.mtgban.com/newspaper", nil)
	setCookie(recorder, req, "NewspaperList", "value", time.Now().Add(time.Hour), false)

	setCookies := recorder.Header().Values("Set-Cookie")
	if len(setCookies) != 2 {
		t.Fatalf("got %d Set-Cookie headers, want scoped cookie and legacy expiry", len(setCookies))
	}
	if !strings.Contains(setCookies[0], "Path=/newspaper") {
		t.Errorf("scoped Set-Cookie = %q, want Path=/newspaper", setCookies[0])
	}
	if !strings.Contains(setCookies[1], "Path=/") || !strings.Contains(setCookies[1], "Max-Age=0") {
		t.Errorf("legacy Set-Cookie = %q, want expired Path=/ copy", setCookies[1])
	}
}
