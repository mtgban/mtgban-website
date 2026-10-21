package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/ratelimit"
	"golang.org/x/time/rate"
)

func TestUserRateLimitAllowsDeferredPagePair(t *testing.T) {
	// The limiter the server uses, on a key no request sends, fresh each run.
	key := fmt.Sprintf("test:deferred-page-pair:%d", time.Now().UnixNano())

	for request := 1; request <= UserRequestBurst; request++ {
		if !UserRateLimiter.Allow(key) {
			t.Fatalf("request %d was rate limited", request)
		}
	}
	if UserRateLimiter.Allow(key) {
		t.Errorf("request %d was allowed, want burst limit %d", UserRequestBurst+1, UserRequestBurst)
	}
}

// An invite link names nobody, so it is limited by its own signature rather
// than in the bucket every request with no signature shares - and not by the
// address, which a client can rotate through X-Forwarded-For.
func TestUserRateLimitGivesAnInviteItsOwnBucket(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

	reached := 0
	handler := enforceSigning(testSite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
	}))

	for range UserRequestBurst + 1 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/limited", nil))
	}

	invite := sign("Pioneer", nil, nil, time.Hour)
	for i := range UserRequestBurst + 2 {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: invite})
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	if reached != UserRequestBurst {
		t.Errorf("an invite reached the page %d times in one burst, want %d", reached, UserRequestBurst)
	}
}

// A forged cookie naming a subscriber's email is limited in the shared bucket,
// not theirs: however many such requests arrive, the subscriber's own burst is
// still whole.
func TestUserRateLimitKeepsAForgedEmailOutOfItsOwnersBucket(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

	reached := 0
	handler := enforceSigning(testSite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
	}))
	serve := func(sig string) {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	ann := &PatreonUserData{Email: "ann@example.com", FullName: "Ann", EmailVerified: true}
	forged := url.Values{"UserEmail": {"ann@example.com"}, "Expires": {"99999999999"}, "Signature": {"forged"}}
	for range UserRequestBurst + 1 {
		serve(base64.StdEncoding.EncodeToString([]byte(forged.Encode())))
	}
	for range UserRequestBurst {
		serve(sign("Pioneer", ann, nil, time.Hour))
	}
	if reached != UserRequestBurst {
		t.Errorf("ann reached the page %d times after forged requests in her name, want %d", reached, UserRequestBurst)
	}
}

// apiLimited serves the API middleware a fresh one-request limiter and reports,
// for each request, whether it got through.
func apiLimited(t *testing.T, reqs ...*http.Request) []bool {
	t.Helper()
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevLimiter := APIRateLimiter
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		APIRateLimiter = prevLimiter
	})
	sellers := []mtgban.Seller{nil}
	vendors := []mtgban.Vendor{nil}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
	APIRateLimiter = ratelimit.NewLimiter(rate.Every(time.Hour), 1)

	h := enforceAPISigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var got []bool
	for _, req := range reqs {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got = append(got, rec.Code != http.StatusTooManyRequests)
	}
	return got
}

// What nginx hands the site: the client's own X-Forwarded-For with the peer
// it saw appended, and the socket on loopback.
func viaNginx(target, clientXFF, peer string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = "127.0.0.1:40000"
	xff := peer
	if clientXFF != "" {
		xff = clientXFF + ", " + peer
	}
	req.Header.Set("X-Forwarded-For", xff)
	req.Header.Set("X-Real-Ip", peer)
	return req
}

// A caller who writes a new X-Forwarded-For on each request still spends
// one bucket: the key is the peer nginx appended.
func TestAPIRateLimitIgnoresASpoofedForwardedFor(t *testing.T) {
	withSigMode(t, false, true)
	got := apiLimited(t,
		viaNginx("/api/mtgban/stores.json", "203.0.113.1", "198.51.100.7"),
		viaNginx("/api/mtgban/stores.json", "203.0.113.2", "198.51.100.7"),
	)
	if !got[0] || got[1] {
		t.Errorf("allowed %v, want the second spoofed request limited", got)
	}
}

// The API gateway replaces X-Forwarded-For with the client it resolved, so
// a request it signed is keyed on that first entry, not on the gateway's
// own address, and its customers keep a bucket each.
func TestAPIRateLimitKeysGatewayRequestsOnTheirClient(t *testing.T) {
	withSigMode(t, false, true)
	withAPIUserSecret(t, apiGatewayUser, "gateway-secret")
	sig := url.QueryEscape(apisig.Mint([]byte("gateway-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"UserEmail": {apiGatewayUser}},
		Expires: time.Now().Add(time.Hour).Unix(),
	}))
	target := "/api/mtgban/stores.json?sig=" + sig
	const gateway = "198.51.100.50"
	got := apiLimited(t,
		viaNginx(target, "203.0.113.1", gateway),
		viaNginx(target, "203.0.113.2", gateway),
		viaNginx(target, "203.0.113.2", gateway),
	)
	if !got[0] || !got[1] || got[2] {
		t.Errorf("allowed %v, want one request per gateway client", got)
	}

	// A signature the gateway did not make keeps the peer's key.
	forged := url.QueryEscape(apisig.Mint([]byte("not-the-secret"), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"UserEmail": {apiGatewayUser}},
		Expires: time.Now().Add(time.Hour).Unix(),
	}))
	got = apiLimited(t,
		viaNginx("/api/mtgban/stores.json?sig="+forged, "203.0.113.1", "198.51.100.7"),
		viaNginx("/api/mtgban/stores.json?sig="+forged, "203.0.113.2", "198.51.100.7"),
	)
	if !got[0] || got[1] {
		t.Errorf("forged gateway signature: allowed %v, want the second limited", got)
	}
}
