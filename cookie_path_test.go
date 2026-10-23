package main

import (
	"net/http"
	"net/http/httptest"
	"os"
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
		{"BanNewspaperPref", "/newspaper?page=syp", false, "/newspaper"},
		{"SleepersEditionList", "/sleepers/bulk", false, "/sleepers"},
		{"ArbitVendorsList", "/arbit", false, "/arbit"},
		{"ReverseVendorsList", "/reverse", false, "/reverse"},
		{"UploadOptimizerOpts", "/upload", false, "/upload"},
		{"UploadCustomRate", "/upload", false, "/"},
		{"MTGBAN", "/auth", true, "/"},
		{"MTGBAN", "/auth", false, "/"},
		{"MobileSearchLayout", "/sealed", false, "/"},
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

func TestAuthCookieStaysRootScopedOnUntrustedHost(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://raw.example.invalid/auth", nil)
	setCookie(recorder, req, "MTGBAN", "sig", time.Now().Add(time.Hour), true)

	setCookies := recorder.Header().Values("Set-Cookie")
	if len(setCookies) != 1 {
		t.Fatalf("got %d Set-Cookie headers, want one auth cookie without legacy expiry", len(setCookies))
	}
	if !strings.Contains(setCookies[0], "Path=/;") {
		t.Errorf("auth Set-Cookie = %q, want Path=/", setCookies[0])
	}
}

// cookieTestRequest builds a request for target, as a proxy would forward it
// when proto is the X-Forwarded-Proto the edge saw.
func cookieTestRequest(target, proto string) *http.Request {
	req := httptest.NewRequest("GET", target, nil)
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	return req
}

func TestSetCookieHeaders(t *testing.T) {
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	const exp = "Expires=Wed, 02 Jan 2030 03:04:05 GMT"
	for _, tc := range []struct {
		name   string
		cookie string
		global bool
		target string
		proto  string
		want   []string
	}{
		{"parent domain", "MTGBAN", true, "http://magic.mtgban.com/auth", "https",
			[]string{"MTGBAN=sig; Path=/; Domain=mtgban.com; " + exp + "; Secure"}},
		{"bare domain", "MTGBAN", true, "http://mtgban.com/auth", "https",
			[]string{"MTGBAN=sig; Path=/; Domain=mtgban.com; " + exp + "; Secure"}},
		{"untrusted host", "MTGBAN", true, "http://raw.example.invalid/auth", "",
			[]string{"MTGBAN=sig; Path=/; " + exp + "; SameSite=Strict"}},
		{"localhost", "MTGBAN", true, "http://localhost:8080/auth", "",
			[]string{"MTGBAN=sig; Path=/; " + exp}},
		{"first party", "NewspaperList", false, "http://magic.mtgban.com/newspaper", "https",
			[]string{
				"NewspaperList=sig; Path=/newspaper; " + exp + "; Secure; SameSite=Strict",
				"NewspaperList=sig; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; Secure; SameSite=Strict",
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			setCookie(recorder, cookieTestRequest(tc.target, tc.proto), tc.cookie, "sig", expires, tc.global)
			got := recorder.Header().Values("Set-Cookie")
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("Set-Cookie = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBaseTemplatesLoadCookiesOnce(t *testing.T) {
	for _, path := range []string{"templates/base.html", "templates/mobile/base-mobile.html"} {
		t.Run(path, func(t *testing.T) {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			source := string(contents)
			if got := strings.Count(source, "/js/cookies.js"); got != 1 {
				t.Fatalf("found %d cookies.js references, want exactly one", got)
			}
			script := strings.Index(source, "/js/cookies.js")
			headEnd := strings.Index(source, "</head>")
			if headEnd < 0 || script > headEnd {
				t.Fatal("cookies.js is not loaded in the document head")
			}
		})
	}
}
