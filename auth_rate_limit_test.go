package main

import (
	"testing"

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
