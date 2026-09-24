package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/ratelimit"
)

// anyTierNav installs one page granted to the ACL "Any" tier (with a
// sub-page) and one gated page, and returns the handler enforceSigning
// wraps, whose body carries marker.
func anyTierNav(t *testing.T, marker string) http.Handler {
	t.Helper()
	savedNavs, savedOrder := ExtraNavs, OrderNav
	savedDev, savedSig := DevMode, SigCheck
	savedLimiter, savedAccess := UserRateLimiter, Access
	t.Cleanup(func() {
		ExtraNavs, OrderNav = savedNavs, savedOrder
		DevMode, SigCheck = savedDev, savedSig
		UserRateLimiter, Access = savedLimiter, savedAccess
	})
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, 1)
	DevMode, SigCheck = true, true
	ExtraNavs = map[string]*NavElem{
		"Open": {Name: "Open", Link: "/open", Page: "home.html", SubPages: []NavElem{
			{Name: "OpenSub", Link: "/open-sub", ShouldHide: func() bool { return true }},
		}},
		"Gated": {Name: "Gated", Link: "/gated", Page: "home.html"},
	}
	OrderNav = []string{"Open", "Gated"}

	files := map[string]string{
		"acl":    `{"Any": {"Open": {}}, "Legacy": {"Open": {}, "Gated": {}}}`,
		"grants": `[]`,
	}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	if err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"}); err != nil {
		t.Fatal(err)
	}
	return enforceSigning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(marker))
	}))
}

func TestAnyTierPageNeedsNoSignature(t *testing.T) {
	const marker = "ANY-BODY"
	handler := anyTierNav(t, marker)

	for _, path := range []string{"/open", "/open-sub"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), marker) {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/gated", nil))
	if strings.Contains(rec.Body.String(), marker) {
		t.Error("gated page served without a signature")
	}
}

func TestAnyTierPageIsInNavForEveryone(t *testing.T) {
	anyTierNav(t, "")
	pageVars := genPageNav(httptest.NewRequest("GET", "/open", nil), "Open", "")
	var names []string
	for _, n := range pageVars.Nav {
		names = append(names, n.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "Open") {
		t.Errorf("nav %s lacks the Any-tier page", joined)
	}
	if strings.Contains(joined, "OpenSub") || strings.Contains(joined, "Gated") {
		t.Errorf("nav %s shows a hidden sub-page or a gated page to an anonymous reader", joined)
	}
}

// A grant is matched on the Patreon email, which a Patreon account can set to
// anybody's until Patreon has confirmed it; an unconfirmed one claims nothing.
func TestGrantNeedsAConfirmedEmail(t *testing.T) {
	savedAccess := Access
	t.Cleanup(func() { Access = savedAccess })
	files := map[string]string{
		"acl":    `{}`,
		"grants": `[{"email": "Granted@Example.com", "tier": "Vintage"}]`,
	}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}

	grant, ok := grantFor(&PatreonUserData{Email: "granted@example.com", EmailVerified: true})
	if !ok || grant.Tier != "Vintage" {
		t.Errorf("the grantee was not granted: %+v %v", grant, ok)
	}
	_, ok = grantFor(&PatreonUserData{Email: "granted@example.com"})
	if ok {
		t.Error("an unconfirmed email claimed the grant made to its owner")
	}
}
