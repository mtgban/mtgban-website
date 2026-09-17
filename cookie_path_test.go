package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookiePath(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"SearchScope", "/"},
		{"SearchScopeOpen", "/"},
		{"SearchSealedSellersList", "/sealed"},
		{"SearchSealedVendorsList", "/sealed"},
		{"NewspaperList", "/newspaper"},
		{"BanNewspaperPref", "/newspaper"},
		{"SleepersSellersList", "/sleepers"},
		{"SleepersVendorsList", "/sleepers"},
		{"SleepersEditionList", "/sleepers"},
		{"ArbitVendorsList", "/arbit"},
		{"ReverseVendorsList", "/reverse"},
		{"GlobalVendorsList", "/global"},
		{"GlobalEditionList", "/global"},
		{"MTGBAN", "/"},
		{"SearchMiscOpts", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cookiePath(tt.name); got != tt.want {
				t.Fatalf("cookiePath(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestCookiePathsFollowNavLinks(t *testing.T) {
	var check func(NavElem)
	check = func(nav NavElem) {
		for _, name := range nav.CookieNames {
			if got, want := cookiePath(name), navLinkPath(nav.Link); got != want {
				t.Errorf("cookiePath(%q) = %q, want NavElem %q", name, got, want)
			}
		}
		for _, subPage := range nav.SubPages {
			check(subPage)
		}
	}

	for _, nav := range DefaultNav {
		check(nav)
	}
	for _, nav := range ExtraNavs {
		check(*nav)
	}
}

func TestSetCookieUsesConfiguredPath(t *testing.T) {
	req := httptest.NewRequest("GET", "https://onepiece.mtgban.com/", nil)
	for _, tc := range []struct {
		name string
		path string
	}{
		{"SearchScope", "/"},
		{"SearchSealedSellersList", "/sealed"},
		{"NewspaperList", "/newspaper"},
		{"SleepersEditionList", "/sleepers"},
		{"ArbitVendorsList", "/arbit"},
		{"ReverseVendorsList", "/reverse"},
		{"GlobalEditionList", "/global"},
		{"SearchMiscOpts", "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			setCookie(recorder, req, tc.name, "value", time.Now().Add(time.Hour), false)
			if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, "Path="+tc.path) {
				t.Fatalf("Set-Cookie = %q, want Path=%s", got, tc.path)
			}
		})
	}
}

func TestSetCookieExpiresLegacyRootCopy(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://onepiece.mtgban.com/", nil)
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
