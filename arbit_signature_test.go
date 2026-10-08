package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Arbitrage reads its grant only off a signature this host wrote: the ACL can
// open the page to everyone, and then nothing checks the cookie before it.
func TestArbitReadsGrantsOnlyOffAVerifiedSignature(t *testing.T) {
	// DevMode so render reads templates from disk; SigCheck so a grant counts
	// only when it verifies.
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Arbitrage"] == nil {
		LogPages["Arbitrage"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Arbitrage") })
	}
	seedReverseScrapers(t, "card-a")

	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}, "ArbitEnabled": {"ALL"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))
	fields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))

	page := func(sig string) string {
		req := httptest.NewRequest(http.MethodGet, "/arbit", nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		rec := httptest.NewRecorder()
		testSite.Arbit(rec, req)
		return rec.Body.String()
	}
	const seller = `<span class="store-name">Reverse Shop</span>`
	if !strings.Contains(page(signed), seller) {
		t.Fatal("a signed ArbitEnabled=ALL does not list the seller")
	}
	if strings.Contains(page(forged), seller) {
		t.Error("a forged ArbitEnabled=ALL listed the seller")
	}
}

// A valid signature in ?sig= gets a request past enforceSigning, which
// checks it first; the handler behind it reads that one, not a forged
// cookie the request carried beside it.
func TestEnforceSigningHandsOnTheSignatureItChecked(t *testing.T) {
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Arbitrage"] == nil {
		LogPages["Arbitrage"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Arbitrage") })
	}
	seedReverseScrapers(t, "card-a")

	sign := func(grants ...string) string {
		fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}}
		for i := 0; i < len(grants); i += 2 {
			fields.Set(grants[i], grants[i+1])
		}
		return signedAs(t, fields, time.Now().Add(time.Hour))
	}
	forge := func(grants ...string) string {
		fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}, "Expires": {"9999999999"}, "Signature": {"forged"}}
		for i := 0; i < len(grants); i += 2 {
			fields.Set(grants[i], grants[i+1])
		}
		return base64.StdEncoding.EncodeToString([]byte(fields.Encode()))
	}
	serve := func(h http.Handler, target, querySig, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target+"?sig="+url.QueryEscape(querySig), nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Any handler behind it, whichever getter it reads, sees the ?sig= that
	// was checked: /api/prices/ reads its blocklists with no check of its own.
	query := sign()
	var seen string
	plain := enforceSigning(testSite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = unverifiedSignature(r)
	}))
	serve(plain, "/api/prices/", query, forge("SearchDisabled", "NONE"))
	if seen != query {
		t.Error("the handler behind enforceSigning read the forged cookie, not the checked ?sig=")
	}

	// The raw card API checks the Admin grant itself too.
	raw := httptest.NewRequest(http.MethodGet, "/api/mtgmatcher/raw/card-a", nil)
	raw.AddCookie(&http.Cookie{Name: "MTGBAN", Value: forge("Admin", "true")})
	rawRec := httptest.NewRecorder()
	testSite.RawCardAPI(rawRec, raw)
	if rawRec.Code != http.StatusForbidden {
		t.Errorf("a forged Admin cookie on the raw card API: status %d, want 403", rawRec.Code)
	}

	reached := false
	debug := enforceSigning(testSite, adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})))
	serve(debug, "/debug/pprof/", sign(), forge("Admin", "true"))
	if reached {
		t.Error("a forged Admin cookie beside a valid ?sig= reached /debug")
	}
	serve(debug, "/debug/pprof/", sign("Admin", "true"), "")
	if !reached {
		t.Error("an admin's ?sig= did not reach /debug")
	}

	arbit := enforceSigning(testSite, http.HandlerFunc(testSite.Arbit))
	const seller = `<span class="store-name">Reverse Shop</span>`
	rec := serve(arbit, "/arbit", sign("Arbit", "true", "ArbitEnabled", "ALL"), "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), seller) {
		t.Fatalf("a signed ArbitEnabled=ALL: status %d, seller listed %v", rec.Code, strings.Contains(rec.Body.String(), seller))
	}
	rec = serve(arbit, "/arbit", sign("Arbit", "true"), forge("Arbit", "true", "ArbitEnabled", "ALL"))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), seller) {
		t.Errorf("a forged ArbitEnabled=ALL beside a valid ?sig=: status %d, seller listed %v", rec.Code, strings.Contains(rec.Body.String(), seller))
	}
}

// The open pages draw the navbar off a checked signature too: a forged
// cookie claiming Arbit does not put Arbitrage in it.
func TestOpenPagesDrawTheNavFromACheckedSignature(t *testing.T) {
	signingEnabled(t, true)
	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}, "Arbit": {"true"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))
	fields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))

	const link = `href="/arbit"`
	for path, handler := range map[string]http.HandlerFunc{
		"/":          testSite.Home,
		"/guide":     testSite.Guide,
		"/changelog": testSite.Changelog,
		"/privacy":   testSite.Privacy,
		"/offline":   testSite.OfflinePage,
	} {
		page := func(sig string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
			rec := httptest.NewRecorder()
			handler(rec, req)
			return rec
		}
		if rec := page(signed); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), link) {
			t.Fatalf("%s, a signed Arbit grant: status %d, Arbitrage in the nav %v", path, rec.Code, strings.Contains(rec.Body.String(), link))
		}
		if rec := page(forged); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), link) {
			t.Errorf("%s, a forged Arbit grant: status %d, Arbitrage in the nav %v", path, rec.Code, strings.Contains(rec.Body.String(), link))
		}
	}
}
