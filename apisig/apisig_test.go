package apisig

import (
	"net/url"
	"testing"
)

const goldenSecret = "golden-secret"

func goldenClaimsWithExpiry() Claims {
	return Claims{
		API:     "BASE_ACCESS",
		Fields:  url.Values{"APImode": {"retail,buylist"}, "UserEmail": {"golden@example.com"}},
		Expires: 1800000000,
	}
}

func goldenClaimsNoExpiry() Claims {
	return Claims{
		API:    "ALL_ACCESS",
		Fields: url.Values{"APImode": {"all"}, "UserEmail": {"golden@example.com"}},
	}
}

func TestSignGolden(t *testing.T) {
	data := "GET1800000000http://www.mtgban.comAPI=BASE_ACCESS&APImode=retail%2Cbuylist&Expires=1800000000&UserEmail=golden%40example.com"
	if got := Sign([]byte(goldenSecret), []byte(data)); got != "u/Ep9NoOIBriYtarJXp5WYSlkQM=" {
		t.Errorf("Sign = %q", got)
	}
}

func TestPayload(t *testing.T) {
	cases := []struct {
		name string
		c    Claims
		want string
	}{
		{"with expiry", goldenClaimsWithExpiry(),
			"GET1800000000http://www.mtgban.comAPI=BASE_ACCESS&APImode=retail%2Cbuylist&Expires=1800000000&UserEmail=golden%40example.com"},
		{"no expiry", goldenClaimsNoExpiry(),
			"GEThttp://www.mtgban.comAPI=ALL_ACCESS&APImode=all&UserEmail=golden%40example.com"},
	}
	for _, c := range cases {
		if got := Payload("GET", DefaultLink, c.c); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestPayloadSkipsEmptyFields(t *testing.T) {
	c := Claims{API: "ALL_ACCESS", Fields: url.Values{"APImode": {""}, "UserEmail": {"a@b.c"}}}
	want := "GEThttp://www.mtgban.comAPI=ALL_ACCESS&UserEmail=a%40b.c"
	if got := Payload("GET", DefaultLink, c); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
