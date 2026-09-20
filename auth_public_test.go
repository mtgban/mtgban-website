package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/ratelimit"
)

// publicNav installs one public and one gated page and returns the handler
// enforceSigning wraps, whose body carries marker.
func publicNav(t *testing.T, marker string) http.Handler {
	t.Helper()
	savedNavs, savedOrder := ExtraNavs, OrderNav
	savedDev, savedSig := DevMode, SigCheck
	savedLimiter := UserRateLimiter
	t.Cleanup(func() {
		ExtraNavs, OrderNav = savedNavs, savedOrder
		DevMode, SigCheck = savedDev, savedSig
		UserRateLimiter = savedLimiter
	})
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, 1)
	DevMode, SigCheck = true, true
	ExtraNavs = map[string]*NavElem{
		"Open":  {Name: "Open", Link: "/open", Page: "home.html", Public: true},
		"Gated": {Name: "Gated", Link: "/gated", Page: "home.html"},
	}
	OrderNav = []string{"Open", "Gated"}
	return enforceSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(marker))
	}))
}

func TestPublicPageNeedsNoSignature(t *testing.T) {
	const marker = "PUBLIC-BODY"
	handler := publicNav(t, marker)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/open", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), marker) {
		t.Errorf("public page: %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/gated", nil))
	if strings.Contains(rec.Body.String(), marker) {
		t.Error("gated page served without a signature")
	}
}

func TestPublicPageIsInNavForEveryone(t *testing.T) {
	publicNav(t, "")
	pageVars := genPageNav(httptest.NewRequest("GET", "/open", nil), "Open", "")
	var names []string
	for _, n := range pageVars.Nav {
		names = append(names, n.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "Open") {
		t.Errorf("nav %s lacks the public page", joined)
	}
	if strings.Contains(joined, "Gated") {
		t.Errorf("nav %s shows a gated page to an anonymous reader", joined)
	}
}
