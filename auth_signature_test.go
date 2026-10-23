package main

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/ratelimit"
)

// signedAs mints a signature the way sign() does, over the fields given.
//
// Only SignedFields may appear: the verifier rebuilds what it hashes from
// that list alone, so anything else here is signed by this function and
// ignored by the check, which reads as a mismatch.
func signedAs(t *testing.T, fields url.Values, expires time.Time) string {
	t.Helper()
	data := fmt.Sprintf("GET%d%s%s", expires.Unix(), signatureLink(), fields.Encode())
	fields.Set("Expires", fmt.Sprint(expires.Unix()))
	fields.Set("Signature", signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data)))
	return base64.StdEncoding.EncodeToString([]byte(fields.Encode()))
}

// signingEnabled turns the check on, since whether anything is verified at
// all is a global. dev keeps DevMode where the caller needs it: the link
// being signed for is read off it too, so minting and checking agree
// either way - but render() only reparses templates from disk while it is
// set, which is the only template cache a test binary has.
func signingEnabled(t *testing.T, dev bool) {
	t.Helper()
	withSigMode(t, dev, true)
	// The runtime puts this one back itself, including unsetting it again
	// where it was never set to begin with.
	t.Setenv("BAN_SECRET", "test-secret")
}

// A grant is only worth reading off a signature this host wrote. The point
// of the check is the tampered case: the whole of what a handler is allowed
// to believe travels in a cookie the reader holds, so a page asking "may
// this person upload" has to ask whether the answer was written here.
func TestSignatureIsValid(t *testing.T) {
	signingEnabled(t, false)

	granted := func() url.Values {
		return url.Values{"Upload": {"true"}, "UserTier": {"Pro"}}
	}

	t.Run("one this host wrote", func(t *testing.T) {
		v, ok := signatureIsValid(signedAs(t, granted(), time.Now().Add(time.Hour)))
		if !ok {
			t.Fatal("refused a signature it had just written")
		}
		if v.Get("Upload") != "true" {
			t.Errorf("Upload = %q, want true", v.Get("Upload"))
		}
	})

	t.Run("the same one, after it expires", func(t *testing.T) {
		if _, ok := signatureIsValid(signedAs(t, granted(), time.Now().Add(-time.Hour))); ok {
			t.Error("accepted an expired signature")
		}
	})

	t.Run("a grant added after the signing", func(t *testing.T) {
		// What somebody without the grant would do: take the signature
		// they were given and write the grant into it.
		raw, _ := base64.StdEncoding.DecodeString(
			signedAs(t, url.Values{"UserTier": {"Free"}}, time.Now().Add(time.Hour)),
		)
		v, _ := url.ParseQuery(string(raw))
		v.Set("Upload", "true")
		forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		values, ok := signatureIsValid(forged)
		if ok {
			t.Error("accepted a signature with a grant written into it")
		}
		// Readable, and not to be believed. A caller is handed these so it
		// can name who is being turned away, not so it can ask what they
		// are allowed to do.
		if values.Get("Upload") != "true" {
			t.Error("the values of a refused signature should still come back")
		}
	})

	t.Run("nothing at all", func(t *testing.T) {
		for _, sig := range []string{"", "not base64", "Zm9vPSUlJQ=="} {
			if _, ok := signatureIsValid(sig); ok {
				t.Errorf("accepted %q as a signature", sig)
			}
		}
	})
}

// emailFromCookie asks signedUserEmail about a request carrying sig, the
// way a browser would carry it.
func emailFromCookie(t *testing.T, sig string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/upload/handoff", nil)
	req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
	return signedUserEmail(req)
}

// signedUserEmail is the other caller, and carried its own copy of the
// check until now. It answers only for a signature that passes.
func TestSignedUserEmailNeedsAValidSignature(t *testing.T) {
	signingEnabled(t, false)

	sig := signedAs(t, url.Values{"UserEmail": {"someone@example.test"}}, time.Now().Add(time.Hour))
	if got := emailFromCookie(t, sig); got != "someone@example.test" {
		t.Errorf("email = %q, want someone@example.test", got)
	}

	// A name written into somebody else's signature. It decodes and it has
	// not expired, so nothing but the HMAC tells the two apart.
	raw, _ := base64.StdEncoding.DecodeString(sig)
	v, _ := url.ParseQuery(string(raw))
	v.Set("UserEmail", "elsewhere@example.test")
	forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	if got := emailFromCookie(t, forged); got != "" {
		t.Errorf("email = %q for a rewritten signature, want empty", got)
	}
}

// A signature this host wrote that has run out is told it was logged out,
// with the way back in; one it never wrote is not.
func TestEnforceSigningTellsExpiredFromForged(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)
	handler := enforceSigning(testSite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	expired := signedAs(t, url.Values{"UserEmail": {"sub@example.com"}}, time.Now().Add(-time.Hour))
	v := parseSig(expired)
	v.Set("Signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	for name, sig := range map[string]string{"expired": expired, "forged": forged} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?sig="+url.QueryEscape(sig), nil))
		// The page escapes the apostrophe in the message.
		loggedOut := strings.Contains(rec.Body.String(), html.EscapeString(ErrMsgExpired))
		if loggedOut != (name == "expired") {
			t.Errorf("%s: told it was logged out: %v", name, loggedOut)
		}
	}
}

// A ?sig= is kept as the cookie only once it checks out, by either wrapper:
// a forged one is refused or ignored, and has no business in the browser.
func TestOnlyACheckedSignatureIsKeptAsTheCookie(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

	valid := signedAs(t, url.Values{"UserEmail": {"sub@example.com"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	v := parseSig(valid)
	v.Set("Signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	nothing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for name, wrapper := range map[string]http.Handler{
		"noSigning":      noSigning(nothing),
		"enforceSigning": enforceSigning(testSite, nothing),
	} {
		for sig, want := range map[string]bool{valid: true, forged: false} {
			rec := httptest.NewRecorder()
			wrapper.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/limited?sig="+url.QueryEscape(sig), nil))
			kept := false
			for _, c := range rec.Result().Cookies() {
				if c.Name != "BAN_SIG" {
					continue
				}
				kept = true
				if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
					t.Errorf("%s: kept the cookie with HttpOnly %v and SameSite %v, want HttpOnly and Lax", name, c.HttpOnly, c.SameSite)
				}
			}
			if kept != want {
				t.Errorf("%s: kept the cookie %v for a signature that checks out %v", name, kept, want)
			}
		}
	}
}

// cookieExpires is the date a cookie lasts to, which comes off the clock.
var cookieExpires = regexp.MustCompile(`Expires=[^;]+`)

// navigationAccept is what a browser asks for when it loads a page.
const navigationAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// A reader still holding the signature under its old cookie name is served
// as before and moved over, by either wrapper: the signature is written
// under the new name and the old cookie expired with the scope it was set
// in. With both names there the new one wins, and the old is only expired,
// unless the new one has run out.
func TestLegacySignatureCookieMovesToTheNewName(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })

	mint := func(email string, expires time.Time) string {
		return signedAs(t, url.Values{"UserEmail": {email}, "UserTier": {"Test"}}, expires)
	}
	valid := mint("a@example.com", time.Now().Add(time.Hour))
	other := mint("b@example.com", time.Now().Add(time.Hour))
	expired := mint("a@example.com", time.Now().Add(-time.Hour))
	v := parseSig(valid)
	v.Set("Signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	stored := func(sig string) string {
		return "BAN_SIG=" + sig + "; Path=/; Domain=mtgban.com; Expires=DATE; HttpOnly; Secure; SameSite=Lax"
	}
	const expiredOld = "MTGBAN=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"

	for _, tc := range []struct {
		name    string
		cookies []*http.Cookie
		query   string
		want    []string
		seen    string
	}{
		{"only the old cookie", []*http.Cookie{{Name: "MTGBAN", Value: valid}},
			"", []string{stored(valid), expiredOld}, valid},
		{"both names, the new one wins", []*http.Cookie{{Name: "BAN_SIG", Value: valid}, {Name: "MTGBAN", Value: other}},
			"", []string{expiredOld}, valid},
		{"only the new cookie", []*http.Cookie{{Name: "BAN_SIG", Value: valid}},
			"", nil, valid},
		{"a new cookie that has run out beside a good old one", []*http.Cookie{{Name: "BAN_SIG", Value: expired}, {Name: "MTGBAN", Value: valid}},
			"", []string{stored(valid), expiredOld}, valid},
		{"an old cookie that does not check out", []*http.Cookie{{Name: "MTGBAN", Value: forged}},
			"", nil, ""},
		{"an old cookie that has run out", []*http.Cookie{{Name: "MTGBAN", Value: expired}},
			"", nil, ""},
		{"a link's signature beside an old cookie", []*http.Cookie{{Name: "MTGBAN", Value: other}},
			valid, []string{stored(valid)}, valid},
		{"a link's signature and nothing else", nil,
			valid, []string{stored(valid)}, valid},
	} {
		for wrapperName, wrap := range map[string]func(http.Handler) http.Handler{
			"noSigning":      noSigning,
			"enforceSigning": func(next http.Handler) http.Handler { return enforceSigning(testSite, next) },
		} {
			t.Run(wrapperName+"/"+tc.name, func(t *testing.T) {
				UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)
				seen := ""
				handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen = verifiedRequestSignature(r)
				}))

				target := "http://magic.mtgban.com/data/prices/"
				if tc.query != "" {
					target += "?sig=" + url.QueryEscape(tc.query)
				}
				req := cookieTestRequest(target, "https")
				req.Header.Set("Accept", navigationAccept)
				for _, c := range tc.cookies {
					req.AddCookie(c)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				var got []string
				for _, line := range rec.Header().Values("Set-Cookie") {
					got = append(got, cookieExpires.ReplaceAllString(line, "Expires=DATE"))
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("Set-Cookie = %q, want %q", got, tc.want)
				}
				if seen != tc.seen {
					t.Errorf("the handler read %q, want %q", seen, tc.seen)
				}
				for _, c := range rec.Result().Cookies() {
					if c.Name != "BAN_SIG" {
						continue
					}
					left := time.Until(c.Expires)
					if left < 31*24*time.Hour-time.Minute || left > 31*24*time.Hour+time.Minute {
						t.Errorf("BAN_SIG lasts %v, want 31 days", left)
					}
				}
			})
		}
	}
}

// Only a page navigation moves the cookie. A script's fetch for JSON may be
// answered from a shared cache, which must not be handed a Set-Cookie
// carrying a reader's signature; it is served through the old cookie as is.
func TestLegacySignatureCookieMovesOnlyOnANavigation(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })

	valid := signedAs(t, url.Values{"UserEmail": {"a@example.com"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	moved := []string{
		"BAN_SIG=" + valid + "; Path=/; Domain=mtgban.com; Expires=DATE; HttpOnly; Secure; SameSite=Lax",
		"MTGBAN=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
	}

	for _, tc := range []struct {
		name   string
		method string
		accept string
		want   []string
	}{
		{"a page navigation", http.MethodGet, navigationAccept, moved},
		{"a script's fetch for JSON", http.MethodGet, "application/json", nil},
		{"a script's fetch for anything", http.MethodGet, "*/*", nil},
		{"a form posted from a page", http.MethodPost, navigationAccept, nil},
	} {
		for wrapperName, wrap := range map[string]func(http.Handler) http.Handler{
			"noSigning":      noSigning,
			"enforceSigning": func(next http.Handler) http.Handler { return enforceSigning(testSite, next) },
		} {
			t.Run(wrapperName+"/"+tc.name, func(t *testing.T) {
				UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)
				seen := ""
				handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen = verifiedSignature(r)
				}))

				req := cookieTestRequest("http://magic.mtgban.com/data/prices/", "https")
				req.Method = tc.method
				req.Header.Set("Accept", tc.accept)
				req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: valid})
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				var got []string
				for _, line := range rec.Header().Values("Set-Cookie") {
					got = append(got, cookieExpires.ReplaceAllString(line, "Expires=DATE"))
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("Set-Cookie = %q, want %q", got, tc.want)
				}
				if tc.method == http.MethodGet && seen != valid {
					t.Errorf("the handler read %q, want the old cookie's signature", seen)
				}
			})
		}
	}
}

// Logging out drops the signature under both names, whatever the same
// request's migration just wrote: the last word on each is a clear, with the
// scope the cookie was set in.
func TestLogoutClearsBothSignatureCookies(t *testing.T) {
	signingEnabled(t, true)
	valid := signedAs(t, url.Values{"UserEmail": {"a@example.com"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	const (
		clearNew = "BAN_SIG=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
		clearOld = "MTGBAN=; Path=/; Domain=mtgban.com; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
	)

	for name, cookies := range map[string][]*http.Cookie{
		"no cookie":  nil,
		"new name":   {{Name: "BAN_SIG", Value: valid}},
		"old name":   {{Name: "MTGBAN", Value: valid}},
		"both names": {{Name: "BAN_SIG", Value: valid}, {Name: "MTGBAN", Value: valid}},
	} {
		t.Run(name, func(t *testing.T) {
			req := cookieTestRequest("http://magic.mtgban.com/?errmsg=logout", "https")
			req.Header.Set("Accept", navigationAccept)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			noSigning(http.HandlerFunc(testSite.Home)).ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want a redirect", rec.Code)
			}

			last := map[string]string{}
			for _, line := range rec.Header().Values("Set-Cookie") {
				cookieName, _, _ := strings.Cut(line, "=")
				last[cookieName] = line
			}
			if last["BAN_SIG"] != clearNew || last["MTGBAN"] != clearOld {
				t.Errorf("last Set-Cookie per name = %q, want %q and %q", last, clearNew, clearOld)
			}
			if cookies == nil && !slices.Equal(rec.Header().Values("Set-Cookie"), []string{clearNew, clearOld}) {
				t.Errorf("Set-Cookie = %q, want both clears and nothing else", rec.Header().Values("Set-Cookie"))
			}
		})
	}
}

// An unconfirmed email is flagged inside the signature: the pricing page and
// alerts read the flag, and deleting it breaks the HMAC like any other edit.
func TestTheUnconfirmedFlagIsSigned(t *testing.T) {
	signingEnabled(t, true)
	flagged := sign("Legacy", &pledge.User{Email: "victim@example.com", FullName: "Mallory"}, nil, DefaultSignatureDuration)
	v := parseSig(flagged)
	if v.Get("UserEmailUnverified") != "true" {
		t.Fatal("an unconfirmed email was not flagged")
	}
	v.Del("UserEmailUnverified")
	_, flaggedOK := signatureIsValid(flagged)
	_, strippedOK := signatureIsValid(base64.StdEncoding.EncodeToString([]byte(v.Encode())))
	if !flaggedOK || strippedOK {
		t.Errorf("flagged signature verifies: %v, with the flag deleted: %v", flaggedOK, strippedOK)
	}
}

// A /data/ route answers a refusal with a status and a JSON error a script
// can test; a page given the same refusal renders the error page.
func TestEnforceDataSigningRefusesWithAStatus(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	reached := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.URL.Path
	})
	serve := func(h http.Handler, target string) *httptest.ResponseRecorder {
		reached = ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}
	data, page := enforceDataSigning(testSite, next), enforceSigning(testSite, next)
	expired := url.QueryEscape(signedAs(t, url.Values{"UserEmail": {"sub@example.com"}}, time.Now().Add(-time.Hour)))

	UserRateLimiter = ratelimit.NewLimiter(1000, 1000)
	for _, tc := range []struct {
		target, body string
	}{
		{"/data/chart/ban:1", ErrMsg},
		{"/data/chart/ban:1?sig=" + expired, "logged out"},
		{"/data/prices/x?sig=not-base64!", ErrMsg},
	} {
		rec := serve(data, tc.target)
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || !strings.Contains(rec.Body.String(), tc.body) || reached != "" {
			t.Errorf("%s: %d %q %q, reached %q; want 401 and a JSON error", tc.target, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String(), reached)
		}
	}
	rec := serve(page, "/search?sig="+expired)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), html.EscapeString(ErrMsgExpired)) || reached != "" {
		t.Errorf("an expired page = %d, want the logged-out page", rec.Code)
	}

	UserRateLimiter = ratelimit.NewLimiter(0, 0)
	rec = serve(data, "/data/chart/ban:1")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("a limited chart ask = %d %q, want 429 and a JSON error", rec.Code, rec.Body.String())
	}
	rec = serve(page, "/search")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Too Many Requests") {
		t.Errorf("a limited page = %d, want the error page", rec.Code)
	}
}

// A refused reader with no signature keeps the login button genPageNav gives
// them, whether the signature is missing or the rate limit ran out.
func TestAnUnsignedRefusalOffersTheLogin(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	page := enforceSigning(testSite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for name, limiter := range map[string]*ratelimit.Limiter{
		"unsigned":     ratelimit.NewLimiter(1000, 1000),
		"rate limited": ratelimit.NewLimiter(0, 0),
	} {
		UserRateLimiter = limiter
		rec := httptest.NewRecorder()
		page.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://mtgban.com/search", nil))
		body := rec.Body.String()
		if !strings.Contains(body, "Log in") || strings.Contains(body, "Logout") {
			t.Errorf("%s: the refusal page offers no login", name)
		}
	}
}

// Every route under /data/ is behind the one wrapper, a path it does not
// serve included, so none of them answers a refusal with the error page.
func TestEveryDataRouteRefusesWithAStatus(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(1000, 1000)
	h := enforceDataSigning(testSite, testSite.dataRoutes())
	expired := url.QueryEscape(signedAs(t, url.Values{"UserEmail": {"sub@example.com"}}, time.Now().Add(-time.Hour)))

	for _, p := range []string{"/data/chart/x", "/data/prices/x", "/data/unknown"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://mtgban.com"+p+"?sig="+expired, nil))
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %q, want 401 and a JSON error", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
