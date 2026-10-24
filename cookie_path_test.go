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
		{"GlobalPref", "/auth", true, "/"},
		{"BAN_SIG", "/auth", false, "/"},
		{"MTGBAN", "/auth", false, "/"},
		{"BAN_SESSION", "/auth", false, "/"},
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

// A login cookie is shared under the apex of the host it was set on, stays on
// the host for a dev box, and is never widened for a host that is not ours.
func TestCookieDomainIsTheApex(t *testing.T) {
	for _, tt := range []struct {
		host, forwardedHost string
		domain              string
		global              bool
	}{
		{"www.mtgban.com", "", "mtgban.com", true},
		{"mtgban.com", "", "mtgban.com", true},
		{"lorcana.mtgban.com", "", "mtgban.com", true},
		{"mtg.ban.cards", "", "ban.cards", true},
		{"ban.cards", "", "ban.cards", true},
		{"backend:8080", "pokemon.ban.cards", "ban.cards", true},
		{"localhost:8080", "", "", true},
		{"example.com", "", "", false},
		{"mtgban.com.evil.example", "", "", false},
		{"xban.cards", "", "", false},
	} {
		req := httptest.NewRequest("GET", "/auth", nil)
		req.Host = tt.host
		req.Header.Set("X-Forwarded-Proto", "https")
		if tt.forwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
		}
		domain, global := cookieDomain(req)
		if domain != tt.domain || global != tt.global {
			t.Errorf("cookieDomain(%s via %q) = %q, %v; want %q, %v", tt.host, tt.forwardedHost, domain, global, tt.domain, tt.global)
		}
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
	putSignatureInCookies(recorder, req, "sig")

	setCookies := recorder.Header().Values("Set-Cookie")
	if len(setCookies) != 1 {
		t.Fatalf("got %d Set-Cookie headers, want one auth cookie without legacy expiry", len(setCookies))
	}
	if !strings.Contains(setCookies[0], "Path=/;") || strings.Contains(setCookies[0], "Domain=") {
		t.Errorf("auth Set-Cookie = %q, want Path=/ and no Domain", setCookies[0])
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
		{"parent domain", "GlobalPref", true, "http://magic.mtgban.com/auth", "https",
			[]string{"GlobalPref=sig; Path=/; Domain=mtgban.com; " + exp + "; Secure"}},
		{"bare domain", "GlobalPref", true, "http://mtgban.com/auth", "https",
			[]string{"GlobalPref=sig; Path=/; Domain=mtgban.com; " + exp + "; Secure"}},
		{"untrusted host", "GlobalPref", true, "http://raw.example.invalid/auth", "",
			[]string{
				"GlobalPref=sig; Path=/auth; " + exp + "; SameSite=Strict",
				"GlobalPref=sig; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; SameSite=Strict",
			}},
		{"localhost", "GlobalPref", true, "http://localhost:8080/auth", "",
			[]string{"GlobalPref=sig; Path=/; " + exp}},
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

func TestSessionCookieHeaders(t *testing.T) {
	const maxAge = 31 * 24 * time.Hour
	for _, tc := range []struct {
		name      string
		target    string
		proto     string
		wantSet   string
		wantClear string
	}{
		{"parent domain", "http://magic.mtgban.com/auth", "https",
			"BAN_SESSION=id; Path=/; Domain=mtgban.com; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax",
			"BAN_SESSION=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"bare domain", "http://mtgban.com/auth", "https",
			"BAN_SESSION=id; Path=/; Domain=mtgban.com; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax",
			"BAN_SESSION=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"plain http", "http://magic.mtgban.com/auth", "",
			"BAN_SESSION=id; Path=/; Domain=mtgban.com; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax",
			"BAN_SESSION=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"untrusted host", "http://raw.example.invalid/auth", "https",
			"BAN_SESSION=id; Path=/; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax",
			"BAN_SESSION=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"localhost", "http://localhost:8080/auth", "",
			"BAN_SESSION=id; Path=/; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax",
			"BAN_SESSION=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := cookieTestRequest(tc.target, tc.proto)

			recorder := httptest.NewRecorder()
			setSessionCookie(recorder, req, "id", maxAge)
			got := recorder.Header().Values("Set-Cookie")
			if len(got) != 1 || got[0] != tc.wantSet {
				t.Errorf("set Set-Cookie = %q, want %q", got, tc.wantSet)
			}

			recorder = httptest.NewRecorder()
			clearSessionCookie(recorder, req)
			got = recorder.Header().Values("Set-Cookie")
			if len(got) != 1 || got[0] != tc.wantClear {
				t.Errorf("clear Set-Cookie = %q, want %q", got, tc.wantClear)
			}
			cleared := recorder.Result().Cookies()
			if len(cleared) != 1 || cleared[0].Name != sessionCookie || cleared[0].MaxAge != -1 {
				t.Errorf("clear parsed as %v, want %s with MaxAge -1", cleared, sessionCookie)
			}
		})
	}
}

func TestSignatureCookieHeaders(t *testing.T) {
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	const exp = "Expires=Wed, 02 Jan 2030 03:04:05 GMT"
	for _, tc := range []struct {
		name      string
		target    string
		proto     string
		wantSet   string
		wantClear string
	}{
		{"parent domain", "http://magic.mtgban.com/auth", "https",
			"BAN_SIG=sig; Path=/; Domain=mtgban.com; " + exp + "; HttpOnly; Secure; SameSite=Lax",
			"BAN_SIG=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"bare domain", "http://mtgban.com/auth", "https",
			"BAN_SIG=sig; Path=/; Domain=mtgban.com; " + exp + "; HttpOnly; Secure; SameSite=Lax",
			"BAN_SIG=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"plain http", "http://magic.mtgban.com/auth", "",
			"BAN_SIG=sig; Path=/; Domain=mtgban.com; " + exp + "; HttpOnly; Secure; SameSite=Lax",
			"BAN_SIG=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"untrusted host", "http://raw.example.invalid/auth", "https",
			"BAN_SIG=sig; Path=/; " + exp + "; HttpOnly; Secure; SameSite=Lax",
			"BAN_SIG=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
		{"localhost", "http://localhost:8080/auth", "",
			"BAN_SIG=sig; Path=/; " + exp + "; HttpOnly; Secure; SameSite=Lax",
			"BAN_SIG=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := cookieTestRequest(tc.target, tc.proto)

			recorder := httptest.NewRecorder()
			http.SetCookie(recorder, signatureCookieFor(req, signatureCookie, "sig", expires))
			got := recorder.Header().Values("Set-Cookie")
			if len(got) != 1 || got[0] != tc.wantSet {
				t.Errorf("set Set-Cookie = %q, want %q", got, tc.wantSet)
			}
			set := recorder.Result().Cookies()

			wantLegacy := strings.Replace(tc.wantClear, signatureCookie+"=", legacySignatureCookie+"=", 1)
			for name, want := range map[string]string{signatureCookie: tc.wantClear, legacySignatureCookie: wantLegacy} {
				recorder = httptest.NewRecorder()
				clearSignatureCookie(recorder, req, name)
				got = recorder.Header().Values("Set-Cookie")
				if len(got) != 1 || got[0] != want {
					t.Errorf("clear %s Set-Cookie = %q, want %q", name, got, want)
				}
				cleared := recorder.Result().Cookies()
				if len(cleared) != 1 || cleared[0].Name != name || cleared[0].MaxAge != -1 {
					t.Errorf("clear parsed as %v, want %s with MaxAge -1", cleared, name)
					continue
				}
				// A browser drops a cookie only when Domain and Path match
				if len(set) != 1 || cleared[0].Domain != set[0].Domain || cleared[0].Path != set[0].Path {
					t.Errorf("clear of %s scoped %q %q, the set %v", name, cleared[0].Domain, cleared[0].Path, set)
				}
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
