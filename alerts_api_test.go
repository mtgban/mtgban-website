package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/userstate"
)

// devSig is an unsigned dev-mode cookie; Legacy carries the page flag and an allowance of 2.
func devSig(email, tier string) string {
	v := "UserEmail=" + email + "&UserTier=" + tier + "&Expires=9999999999"
	if tier == "Legacy" {
		v += "&Alerts=true&AlertsMax=2"
	}
	return base64.StdEncoding.EncodeToString([]byte(v))
}

func alertsRequest(method, path, sig string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if sig != "" {
		r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	}
	return r
}

// alertsIdentity reads the real signature cookie, and the API built on it
// refuses or admits the caller before reaching the store.
func TestAlertsIdentityReadsSignature(t *testing.T) {
	withSigMode(t, true, false)

	c, status, _ := alertsIdentity(alertsRequest("GET", "/api/alerts/", devSig("a@b.com", "Legacy")))
	if status != http.StatusOK || c.UserHash != userstate.HashEmail("a@b.com") || c.Tier != "Legacy" ||
		allowanceFromValues(c.Values) != 2 || c.Origin != "" {
		t.Fatalf("identity = %d %+v", status, c)
	}
	r := alertsRequest("GET", "/api/alerts/", devSig("a@b.com", "Legacy"))
	r.Host = "lorcana.mtgban.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	c, _, _ = alertsIdentity(r)
	if c.Origin != "https://lorcana.mtgban.com" {
		t.Fatalf("origin = %q, want the site the request came to", c.Origin)
	}

	api := alerts.NewAPI(alerts.APIDeps{Identity: alertsIdentity, Allowance: alertAllowance})
	unverified := base64.StdEncoding.EncodeToString([]byte("UserEmail=a@b.com&UserTier=Legacy&UserEmailUnverified=true&Expires=9999999999"))
	for _, tc := range []struct {
		name, sig string
		want      int
	}{
		{"unsigned", "", http.StatusUnauthorized},
		{"unverified", unverified, http.StatusForbidden},
		{"signed, no store", devSig("a@b.com", "Legacy"), http.StatusServiceUnavailable},
	} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", tc.sig))
		if w.Code != tc.want {
			t.Fatalf("%s = %d %s", tc.name, w.Code, w.Body)
		}
		if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), alertsUnverifiedMsg) {
			t.Fatalf("%s body = %s", tc.name, w.Body)
		}
	}
}

// The Alerts page hides on a site whose service has no store.
func TestAlertsNavHiddenWithoutStore(t *testing.T) {
	s := newSite()
	hide := ExtraNavs["Alerts"].ShouldHide
	if hide == nil || !hide(s) {
		t.Fatal("Alerts shown without a store")
	}
	s.alerts.SetStore(&alerts.Store{})
	if hide(s) {
		t.Fatal("Alerts hidden with a store")
	}
}
