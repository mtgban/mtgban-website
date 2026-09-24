package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

// An invite link names nobody, and used to share one bucket with every
// request carrying no signature, so a handful of anonymous hits locked every
// invite holder out. It is limited by its own signature instead - not by the
// address, which a client can rotate through X-Forwarded-For.
func TestUserRateLimitGivesAnInviteItsOwnBucket(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

	reached := 0
	handler := enforceSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
