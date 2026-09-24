package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/ratelimit"
)

func TestUserRateLimitAllowsDeferredPagePair(t *testing.T) {
	limiter := ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)
	key := "ip:192.0.2.10"

	for request := 1; request <= UserRequestBurst; request++ {
		if !limiter.Allow(key) {
			t.Fatalf("request %d was rate limited", request)
		}
	}
	if limiter.Allow(key) {
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
