package main

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// benchSig builds a signature shaped like production ones: every nav
// permission, the optional fields, expiry, and the HMAC blob.
func benchSig(seed string) string {
	v := url.Values{}
	for _, opt := range OptionalFields {
		v.Set(opt, "some,option,values")
	}
	for _, feat := range OrderNav {
		v.Set(feat, "true")
	}
	// After the loops: UserEmail and UserTier are themselves OptionalFields.
	// Expiry must stay in the future or genPageNav skips its feature loop.
	v.Set("Expires", strconv.FormatInt(time.Now().AddDate(1, 0, 0).Unix(), 10))
	v.Set("UserEmail", "someone"+seed+"@example.com")
	v.Set("UserTier", "Vintage")
	v.Set("Signature", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGZha2UgaG1hYyBzaWduYXR1cmU=")
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

func TestGetParamFromSig(t *testing.T) {
	sig := benchSig("")
	if got := GetParamFromSig(sig, "UserTier"); got != "Vintage" {
		t.Errorf("UserTier = %q, want Vintage", got)
	}
	if got := GetParamFromSig(sig, "Search"); got != "true" {
		t.Errorf("Search = %q, want true", got)
	}
	if got := GetParamFromSig(sig, "NoSuchParam"); got != "" {
		t.Errorf("NoSuchParam = %q, want empty", got)
	}
	if got := GetParamFromSig("", "UserTier"); got != "" {
		t.Errorf("empty sig = %q, want empty", got)
	}
	if got := GetParamFromSig("not!!base64", "UserTier"); got != "" {
		t.Errorf("invalid sig = %q, want empty", got)
	}
	// Many distinct sigs (settings changes, many users) must all read back
	// correctly, whatever reuse the parsing path may employ.
	for i := range 600 {
		s := benchSig(strconv.Itoa(i))
		want := "someone" + strconv.Itoa(i) + "@example.com"
		if got := GetParamFromSig(s, "UserEmail"); got != want {
			t.Fatalf("sig %d: UserEmail = %q, want %q", i, got, want)
		}
	}
}

// Meaningful under -race: page requests read the same sig from the handler
// goroutine while API calls with other sigs run alongside.
func TestGetParamFromSigConcurrent(t *testing.T) {
	shared := benchSig("shared")
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i := range 500 {
				GetParamFromSig(shared, "UserTier")
				GetParamFromSig(benchSig(strconv.Itoa(g*1000+i)), "UserEmail")
			}
		})
	}
	wg.Wait()
	if got := GetParamFromSig(shared, "UserTier"); got != "Vintage" {
		t.Errorf("shared sig after churn = %q, want Vintage", got)
	}
}

// One sig-param read, as handlers do for their feature flags.
func BenchmarkGetParamFromSig(b *testing.B) {
	sig := benchSig("")
	b.ReportAllocs()
	for b.Loop() {
		GetParamFromSig(sig, "UserEmail")
	}
}

// The full nav build for a signed-in user, as every handler runs it (and as
// the signing middleware ran it a second time).
func BenchmarkGenPageNav(b *testing.B) {
	sig := benchSig("")
	b.ReportAllocs()
	for b.Loop() {
		genPageNav("Search", sig)
	}
}
