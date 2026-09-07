package main

import (
	"encoding/base64"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tierSig is a signature carrying one tier and nothing else that matters here.
func tierSig(tier string) string {
	v := url.Values{}
	v.Set("Expires", strconv.FormatInt(time.Now().AddDate(1, 0, 0).Unix(), 10))
	v.Set("UserEmail", "someone@example.com")
	v.Set("UserTier", tier)
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

// The bar wears the tier of whoever is reading, so the tier has to reach the
// page - lowercased, since it is a CSS selector by the time it is used.
func TestPageNavCarriesTheTier(t *testing.T) {
	for _, tt := range []struct {
		sig, want string
	}{
		{tierSig("Vintage"), "vintage"},
		{tierSig("Pioneer"), "pioneer"},
		// A reader who is not signed in has no tier to wear.
		{"", ""},
	} {
		if got := genPageNav("Search", tt.sig).UserTier; got != tt.want {
			t.Errorf("tier %q, want %q", got, tt.want)
		}
	}
}

// Both bars carry it, and neither draws anything for a reader without one.
func TestNavbarWearsTheTier(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, PageVars{
			BetaNav: &NavElem{}, IsMobile: mobile, UserTier: "legacy",
		})
		if !strings.Contains(out, `data-tier="legacy"`) {
			t.Errorf("mobile=%v: the bar does not say which tier is reading", mobile)
		}

		out = renderPage(t, "search.html", mobile, PageVars{
			BetaNav: &NavElem{}, IsMobile: mobile,
		})
		if strings.Contains(out, "data-tier") {
			t.Errorf("mobile=%v: a signed-out reader is given a tier", mobile)
		}
	}
}

// Every tier has its colour, and the wash is drawn per tier rather than for
// anything carrying the attribute - a tier named nowhere would otherwise wash
// the bar in whatever the fallback is.
func TestEveryPickedTierHasItsColour(t *testing.T) {
	for _, file := range []string{"css/navbar.css", "css/mobile.css"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		css := string(body)

		for tier, tint := range map[string]string{
			"vintage": "155, 89, 182",
			"legacy":  "52, 152, 219",
			"modern":  "231, 76, 60",
			"pioneer": "26, 188, 156",
			// Not tiers the issue picked: nobody subscribes to them, and they
			// share gold from the same family the other four come from.
			"admin":     "241, 196, 15",
			"root":      "241, 196, 15",
			"mods":      "241, 196, 15",
			"lost boys": "241, 196, 15",
		} {
			var declared bool
			for _, line := range strings.Split(css, "\n") {
				if strings.Contains(line, `[data-tier="`+tier+`"]`) &&
					strings.Contains(line, "--tier-tint: "+tint) {
					declared = true
					break
				}
			}
			if !declared {
				t.Errorf("%s: %s is missing its colour", file, tier)
			}
		}

		// The gradient names its tiers; a bare [data-tier] would catch the rest.
		for _, line := range strings.Split(css, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "[data-tier] {" ||
				strings.HasSuffix(trimmed, " [data-tier] {") && strings.Contains(trimmed, "nav") {
				t.Errorf("%s: %q would tint a tier that has no colour", file, trimmed)
			}
		}
	}
}

// One tier still carries its own strength, and only in one theme: the light
// bar's pale blue turns the red mauve at the strength the others take. The
// dark bar carries all six the same, which is what "the red is too strong and
// the others too muted" was.
func TestTheRedIsCarriedHarderOnlyOnTheLightBar(t *testing.T) {
	body, err := os.ReadFile("css/navbar.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(body)

	if !strings.Contains(css, `body.light-theme .navbar-v2[data-tier="modern"] {`) {
		t.Error("the light bar no longer carries the red harder")
	}
	// Nothing outside that rule singles the red out, so the dark bar keeps all
	// six at one strength.
	if strings.Count(css, `[data-tier="modern"] {`) != 1 {
		t.Error("the red carries its own strength somewhere else too")
	}
}
