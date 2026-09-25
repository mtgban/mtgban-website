package apisig

import (
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"
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
	v, err := Decode("not base64!")
	if err == nil {
		t.Error("expected error for bad base64")
	}
	if v == nil || v.Get("API") != "" {
		t.Errorf("bad base64 should yield an empty non-nil map, got %v", v)
	}
	if _, err := Decode(base64.StdEncoding.EncodeToString([]byte("a=%zz"))); err == nil {
		t.Error("expected error for bad query")
	}
}

func TestAPIFieldsAreVerified(t *testing.T) {
	// A field minted but not listed by the verifier fails closed, so the
	// list these tests verify with has to name every one.
	for _, name := range APIFields {
		if !slices.Contains(testOptionalFields, name) {
			t.Errorf("APIFields entry %q missing from the verifier's field list", name)
		}
	}
}

// testOptionalFields stands in for main.go's OptionalFields, which the root
// package's TestOptionalFieldsCoverAPIFields holds to APIFields.
var testOptionalFields = []string{"UserName", "UserEmail", "APImode", "SearchDownloadCSV"}

func mustDecode(t *testing.T, blob string) url.Values {
	t.Helper()
	v, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyRoundTrip(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if err != nil {
		t.Errorf("valid blob rejected: %v", err)
	}
}

func TestVerifyNoExpiryNeverExpires(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsNoExpiry())
	v := mustDecode(t, blob)
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(4000000000, 0))
	if err != nil {
		t.Errorf("no-expiry blob rejected: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1800000001, 0))
	if !errors.Is(err, ErrExpired) {
		t.Errorf("got %v want ErrExpired", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	v.Set("API", "DEV_ACCESS")
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v want ErrInvalid", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	err := Verify([]byte("other"), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v want ErrInvalid", err)
	}
}

func TestVerifyIgnoresUnlistedFields(t *testing.T) {
	// A field not in optionalFields is not part of the payload, so adding
	// one after minting must not break verification. This mirrors how the
	// website skips unknown keys today.
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	v.Set("Unrelated", "x")
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if err != nil {
		t.Errorf("unlisted field broke verification: %v", err)
	}
}

func TestVerifyBadExpires(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	// Re-sign so only the ParseInt guard can reject this blob.
	q := url.Values{}
	q.Set("API", v.Get("API"))
	for _, name := range testOptionalFields {
		if val := v.Get(name); val != "" {
			q.Set(name, val)
		}
	}
	q.Set("Expires", "soon")
	v.Set("Expires", "soon")
	v.Set("Signature", Sign([]byte(goldenSecret), []byte(payloadRaw("GET", "soon", DefaultLink, q))))
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v want ErrInvalid", err)
	}
	if errors.Is(err, ErrExpired) {
		t.Error("got ErrExpired, want ErrInvalid only")
	}
}

func TestVerifyTamperedListedField(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	v.Set("UserEmail", "attacker@example.com")
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v want ErrInvalid", err)
	}
}

func TestVerifyExpiresZeroRejects(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsNoExpiry())
	v := mustDecode(t, blob)
	q := url.Values{}
	q.Set("API", v.Get("API"))
	for _, name := range testOptionalFields {
		if val := v.Get(name); val != "" {
			q.Set(name, val)
		}
	}
	q.Set("Expires", "0")
	v.Set("Expires", "0")
	v.Set("Signature", Sign([]byte(goldenSecret), []byte(payloadRaw("GET", "0", DefaultLink, q))))
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrExpired) {
		t.Errorf("got %v want ErrExpired", err)
	}
}

func TestVerifyNonCanonicalExpiresRejects(t *testing.T) {
	blob := Mint([]byte(goldenSecret), DefaultLink, goldenClaimsWithExpiry())
	v := mustDecode(t, blob)
	v.Set("Expires", "+1800000000")
	err := Verify([]byte(goldenSecret), "GET", DefaultLink, v, testOptionalFields, time.Unix(1700000000, 0))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v want ErrInvalid", err)
	}
}
