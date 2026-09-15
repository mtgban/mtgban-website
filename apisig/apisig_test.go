package apisig

import (
	"encoding/base64"
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

func TestMintGolden(t *testing.T) {
	cases := []struct {
		name string
		c    Claims
		want string
	}{
		{"with expiry", goldenClaimsWithExpiry(),
			"QVBJPUJBU0VfQUNDRVNTJkFQSW1vZGU9cmV0YWlsJTJDYnV5bGlzdCZFeHBpcmVzPTE4MDAwMDAwMDAmU2lnbmF0dXJlPXUlMkZFcDlOb09JQnJpWXRhckpYcDVXWVNsa1FNJTNEJlVzZXJFbWFpbD1nb2xkZW4lNDBleGFtcGxlLmNvbQ=="},
		{"no expiry", goldenClaimsNoExpiry(),
			"QVBJPUFMTF9BQ0NFU1MmQVBJbW9kZT1hbGwmU2lnbmF0dXJlPU1tY0ZWZjBOMlBySzNvOHprOU81WWREcXo0ZyUzRCZVc2VyRW1haWw9Z29sZGVuJTQwZXhhbXBsZS5jb20="},
	}
	for _, c := range cases {
		if got := Mint([]byte(goldenSecret), DefaultLink, c.c); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestDecode(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v.Get("API") != "BASE_ACCESS" || v.Get("APImode") != "retail,buylist" ||
		v.Get("UserEmail") != "golden@example.com" || v.Get("Expires") != "1800000000" ||
		v.Get("Signature") != "u/Ep9NoOIBriYtarJXp5WYSlkQM=" {
		t.Errorf("decoded values wrong: %v", v)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode("not base64!"); err == nil {
		t.Error("expected error for bad base64")
	}
	if _, err := Decode(base64.StdEncoding.EncodeToString([]byte("a=%zz"))); err == nil {
		t.Error("expected error for bad query")
	}
}
