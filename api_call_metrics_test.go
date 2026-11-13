package main

import (
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

func TestAPITier(t *testing.T) {
	for _, c := range []struct {
		email    string
		verified bool
		tier     string
		signed   bool
	}{
		{apiGatewayUser, true, "api", true},
		{"partner@example.com", true, "api-legacy", true},
		{"", true, "api-legacy", true},
		{apiGatewayUser, false, "Any", false}, // claimed, not proved
		{"", false, "Any", false},
	} {
		tier, signed := apiTier(c.email, c.verified)
		if tier != c.tier || signed != c.signed {
			t.Errorf("apiTier(%q, %v) = (%q, %v), want (%q, %v)", c.email, c.verified, tier, signed, c.tier, c.signed)
		}
	}
}

func TestAPIFormat(t *testing.T) {
	for path, want := range map[string]string{
		"/api/mtgban/all.json": "json", "/api/v2/history/abc.csv": "csv", "/api/v2/stores": "other", "/api/load/x": "other",
	} {
		if got := apiFormat(path); got != want {
			t.Errorf("apiFormat(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAPIRefusal(t *testing.T) {
	if apiRefusal("", apisig.ErrInvalid) != "no_key" || apiRefusal("x", apisig.ErrExpired) != "expired" ||
		apiRefusal("x", apisig.ErrInvalid) != "bad_sig" || apiRefusal("x", errors.New("illegal base64")) != "bad_sig" {
		t.Error("apiRefusal")
	}
}

// mintAPISig publishes secret as email's API key and returns a signature
// minted with it, expiring at expires.
func mintAPISig(t *testing.T, email, secret string, expires time.Time) string {
	t.Helper()
	withAPIUserSecret(t, email, secret)
	return apisig.Mint([]byte(secret), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"UserEmail": {email}},
		Expires: expires.Unix(),
	})
}

// serveAPICall sends a GET for target through enforceAPISigning at pattern,
// wrapped as the site wraps it, with a limiter that lets every call through.
func serveAPICall(t *testing.T, pattern, target string, h http.HandlerFunc) {
	t.Helper()
	serveAPIRequest(t, pattern, httptest.NewRequest(http.MethodGet, target, nil), h)
}

// serveAPIRequest is serveAPICall for a request built by the caller.
func serveAPIRequest(t *testing.T, pattern string, req *http.Request, h http.HandlerFunc) {
	t.Helper()
	quietAPILog(t)
	prevLimiter := APIRateLimiter
	t.Cleanup(func() { APIRateLimiter = prevLimiter })
	APIRateLimiter = ratelimit.NewLimiter(1000, 1000)
	mux := http.NewServeMux()
	mux.Handle(pattern, enforceAPISigning(h))
	statusWrapper(mux, mux).ServeHTTP(httptest.NewRecorder(), req)
}

func noopHandler(http.ResponseWriter, *http.Request) {}

// quietAPILog sends the API's log lines nowhere for the rest of the test.
func quietAPILog(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// wantAPIDims fails unless every row named name carries tier and signed on device api.
func wantAPIDims(t *testing.T, got []observability.Row, name, tier string, signed bool) {
	t.Helper()
	rows := find(got, name)
	if len(rows) == 0 {
		t.Errorf("no %s rows", name)
	}
	for _, row := range rows {
		if row.Device != "api" || row.Tier != tier || row.Signed != signed {
			t.Errorf("%s row dims = %+v, want api/%s/%v", name, row.Dims, tier, signed)
		}
	}
}

// A keyed call reads device=api on its own row and on the wrapper's.
func TestAKeyedCallCountsAsAPI(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	sig := mintAPISig(t, "partner@example.com", "partner-secret", time.Now().Add(time.Hour))

	serveAPICall(t, "/api/v2/", "/api/v2/all.json?sig="+url.QueryEscape(sig), noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.call", "json", 1)
	wantAPIDims(t, got, "api.call", "api-legacy", true)
	wantAPIDims(t, got, "http.status", "api-legacy", true)
}

func TestAGatewayCallIsTierAPI(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	sig := mintAPISig(t, apiGatewayUser, "gateway-secret", time.Now().Add(time.Hour))

	serveAPICall(t, "/api/v2/", "/api/v2/all.csv?sig="+url.QueryEscape(sig), noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.call", "csv", 1)
	wantAPIDims(t, got, "api.call", "api", true)
	wantAPIDims(t, got, "http.status", "api", true)
}

func TestAnUnsignedCallIsAnonymous(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)

	serveAPICall(t, "/api/mtgban/", "/api/mtgban/stores", noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v1", "api.call", "other", 1)
	wantAPIDims(t, got, "api.call", "Any", false)
}

func TestABadSignatureIsRefusedAndNotSigned(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	withAPIUserSecret(t, "partner@example.com", "partner-secret")
	sig := apisig.Mint([]byte("wrong-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"UserEmail": {"partner@example.com"}},
		Expires: time.Now().Add(time.Hour).Unix(),
	})

	serveAPICall(t, "/api/v2/", "/api/v2/all.json?sig="+url.QueryEscape(sig), noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.refuse", "bad_sig", 1)
	wantAPIDims(t, got, "api.refuse", "Any", false)
	wantNoRow(t, got, "api.call")
}

func TestAnExpiredSignatureIsCounted(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	sig := mintAPISig(t, "partner@example.com", "partner-secret", time.Now().Add(-time.Hour))

	serveAPICall(t, "/api/v2/", "/api/v2/all.json?sig="+url.QueryEscape(sig), noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.refuse", "expired", 1)
	wantNoRow(t, got, "api.call")
}

func TestLoadWithoutAKeyIsCounted(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)

	serveAPICall(t, "/api/load/", "/api/load/x", noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.load", "api.refuse", "no_key", 1)
	wantNoRow(t, got, "api.call")
}

// The limiter's refusal reads device=api on both of its rows.
func TestARateLimitedCallIsCounted(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	prevLimiter := APIRateLimiter
	t.Cleanup(func() { APIRateLimiter = prevLimiter })
	APIRateLimiter = ratelimit.NewLimiter(0, 0)
	mux := http.NewServeMux()
	mux.Handle("/api/v2/", enforceAPISigning(http.HandlerFunc(noopHandler)))
	statusWrapper(mux, mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v2/all.json", nil))

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.refuse", "rate_limited", 1)
	wantRow(t, got, "", "ratelimit.reject", "api", 1)
	wantAPIDims(t, got, "api.refuse", "Any", false)
	wantAPIDims(t, got, "ratelimit.reject", "Any", false)
	wantNoRow(t, got, "api.call")
}

// The demo refusal is a call the handler then refused.
func TestTheDemoRefusalIsCounted(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	s := newSite()

	serveAPICall(t, "/api/mtgban/", "/api/mtgban/all.json", s.PriceAPI)

	got := rows.rows()
	wantRow(t, got, "api.v1", "api.call", "json", 1)
	wantRow(t, got, "api.v1", "api.refuse", "no_key", 1)
}

func TestThePlanRefusalIsCounted(t *testing.T) {
	s := historySite(t)
	rows := withFeatureCounter(t)
	sig := mintAPIKey(url.Values{"UserEmail": {"partner@example.com"}})

	serveAPICall(t, "/api/v2/history/", "/api/v2/history/x.json?sig="+url.QueryEscape(sig), s.HistoryAPI)

	got := rows.rows()
	wantRow(t, got, "api.v2.history", "api.refuse", "plan", 1)
	wantAPIDims(t, got, "api.refuse", "api-legacy", true)
}

// The options count where v1's output is served: v1, and v2's CSV.
func TestAPIOptionsAreCounted(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	s.ds.Store(&datastore{backend: v2Backend()})
	seedV2Scrapers(t, s)
	quietAPILog(t)

	for _, c := range []struct {
		handler http.HandlerFunc
		target  string
		counted bool
	}{
		{s.PriceAPI, "/api/mtgban/retail.json?id=mkm&vendor=CT&qty=true&conds=true", true},
		{s.PriceAPIv2, "/api/v2/retail.csv?vendor=CT&qty=true&conds=true", true},
		{s.PriceAPIv2, "/api/v2/retail.json?id=mkm&vendor=CT&qty=true&conds=true", false},
		{s.PriceAPI, "/api/mtgban/retail.json?id=mkm&vendor=CT&qty=false&conds=false", false},
	} {
		t.Run(c.target, func(t *testing.T) {
			rows := withFeatureCounter(t)
			c.handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, c.target, nil))
			got := rows.rows()
			if !c.counted {
				wantNoRow(t, got, "api.option")
				return
			}
			wantRow(t, got, "", "api.option", "quantities", 1)
			wantRow(t, got, "", "api.option", "conditions", 1)
		})
	}
}

func TestTheNewspaperPlanRefusalIsCounted(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	sig := mintAPIKey(url.Values{"APImode": {"retail"}, "UserEmail": {"n@example.com"}})

	serveAPICall(t, "/api/v2/newspaper/", "/api/v2/newspaper/reports.json?sig="+url.QueryEscape(sig), newSite().NewspaperAPI)

	got := rows.rows()
	wantRow(t, got, "api.v2.newspaper", "api.refuse", "plan", 1)
}

// A call with no key at all is a missing key, not a plan refusal.
func TestAnUnsignedAddOnCallIsNoKey(t *testing.T) {
	signingEnabled(t, false)
	s := newSite()
	for _, c := range []struct {
		pattern, target, label string
		handler                http.HandlerFunc
	}{
		{"/api/v2/history/", "/api/v2/history/x.json", "api.v2.history", s.HistoryAPI},
		{"/api/v2/newspaper/", "/api/v2/newspaper/reports.json", "api.v2.newspaper", s.NewspaperAPI},
	} {
		t.Run(c.label, func(t *testing.T) {
			rows := withFeatureCounter(t)
			serveAPICall(t, c.pattern, c.target, c.handler)
			got := rows.rows()
			wantRow(t, got, c.label, "api.call", "json", 1)
			wantRow(t, got, c.label, "api.refuse", "no_key", 1)
			for _, row := range find(got, "api.refuse") {
				if row.Value == "plan" {
					t.Errorf("an unsigned call counted plan: %+v", row)
				}
			}
		})
	}
}

func TestAnUnparsableExpiryIsABadSignature(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	v, err := apisig.Decode(mintAPISig(t, "partner@example.com", "partner-secret", time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	v.Set("Expires", "soon")
	sig := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	serveAPICall(t, "/api/v2/", "/api/v2/all.json?sig="+url.QueryEscape(sig), noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "api.refuse", "bad_sig", 1)
	wantNoRow(t, got, "api.call")
}

// A mount outside the API families counts nothing of its own.
func TestAnUnknownFamilyIsNotCounted(t *testing.T) {
	signingEnabled(t, false)
	for _, target := range []string{"/elsewhere/x.json", "/elsewhere/x.json?sig=bogus"} {
		t.Run(target, func(t *testing.T) {
			rows := withFeatureCounter(t)
			serveAPICall(t, "/elsewhere/", target, noopHandler)
			got := rows.rows()
			wantNoRow(t, got, "api.call")
			wantNoRow(t, got, "api.refuse")
			wantNoRow(t, got, "metrics.rejected")
		})
	}
}

// The address check's 500 reads device=api like every other API row.
func TestAnUnreadableAddressReadsAsAPI(t *testing.T) {
	signingEnabled(t, false)
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v2/all.json", nil)
	req.RemoteAddr = "bogus"

	serveAPIRequest(t, "/api/v2/", req, noopHandler)

	got := rows.rows()
	wantRow(t, got, "api.v2", "http.status", "5xx", 1)
	wantAPIDims(t, got, "http.status", "Any", false)
}
