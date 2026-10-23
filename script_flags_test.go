package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The scripts that gate on the signature cookie read two flags off <html>
// instead. Every page carries them, taken from the cookie the request came
// with and neither verified nor checked for expiry, as the scripts' own
// test of the cookie was.
func TestHTMLCarriesTheScriptFlags(t *testing.T) {
	signingEnabled(t, true)
	offline := url.Values{"UserEmail": {"reader@example.com"}, "SearchOfflineMode": {"true"}}

	for _, c := range []struct {
		name              string
		cookie            string
		signedIn, offline bool
	}{
		{"no cookie", "", false, false},
		{"a signature without the flag", signedAs(t, url.Values{"UserEmail": {"reader@example.com"}}, time.Now().Add(time.Hour)), true, false},
		{"a signature with the flag", signedAs(t, offline, time.Now().Add(time.Hour)), true, true},
		{"an expired signature with the flag", signedAs(t, offline, time.Now().Add(-time.Hour)), true, true},
		{"a cookie that is not a signature", "x", true, false},
	} {
		for _, page := range []struct {
			name    string
			handler http.HandlerFunc
		}{
			{"home", testSite.Home},
			{"offline", testSite.OfflinePage},
		} {
			for _, mobile := range []bool{false, true} {
				// Neither page is behind the signing check: the flags come
				// from the request alone
				handler := noSigning(page.handler)
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "MobileView", Value: strconv.FormatBool(mobile)})
				if c.cookie != "" {
					req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: c.cookie})
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s, %s (mobile=%v): status %d", c.name, page.name, mobile, rec.Code)
				}

				rendered := rec.Body.String()
				root := rendered[strings.Index(rendered, "<html"):]
				root = root[:strings.Index(root, ">")+1]
				body := rendered[strings.Index(rendered, "<body"):]
				body = body[:strings.Index(body, ">")+1]
				for attr, want := range map[string]bool{"data-signed-in": c.signedIn, "data-offline-mode": c.offline} {
					if got := attr + `="` + strconv.FormatBool(want) + `"`; !strings.Contains(root, got) {
						t.Errorf("%s, %s (mobile=%v): <html> is %q, want it to carry %s", c.name, page.name, mobile, root, got)
					}
					if strings.Contains(body, attr) {
						t.Errorf("%s, %s (mobile=%v): <body> is %q, want it free of %s", c.name, page.name, mobile, body, attr)
					}
				}
			}
		}
	}
}
