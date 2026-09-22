package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// signedAs mints a signature the way sign() does, over the fields given.
//
// Only SignedFields may appear: the verifier rebuilds what it hashes from
// that list alone, so anything else here is signed by this function and
// ignored by the check, which reads as a mismatch.
func signedAs(t *testing.T, fields url.Values, expires time.Time) string {
	t.Helper()
	data := fmt.Sprintf("GET%d%s%s", expires.Unix(), signatureLink(), fields.Encode())
	fields.Set("Expires", fmt.Sprint(expires.Unix()))
	fields.Set("Signature", signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data)))
	return base64.StdEncoding.EncodeToString([]byte(fields.Encode()))
}

// signingEnabled puts the globals where production keeps them, since both
// the link being signed for and whether anything is checked at all are read
// off them.
func signingEnabled(t *testing.T) {
	t.Helper()
	savedDev, savedCheck := DevMode, SigCheck
	DevMode, SigCheck = false, true
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedCheck })
	// The runtime puts this one back itself, including unsetting it again
	// where it was never set to begin with.
	t.Setenv("BAN_SECRET", "test-secret")
}

// A grant is only worth reading off a signature this host wrote. The point
// of the check is the tampered case: the whole of what a handler is allowed
// to believe travels in a cookie the reader holds, so a page asking "may
// this person upload" has to ask whether the answer was written here.
func TestSignatureIsValid(t *testing.T) {
	signingEnabled(t)

	granted := func() url.Values {
		return url.Values{"Upload": {"true"}, "UserTier": {"Pro"}}
	}

	t.Run("one this host wrote", func(t *testing.T) {
		v, ok := signatureIsValid(signedAs(t, granted(), time.Now().Add(time.Hour)))
		if !ok {
			t.Fatal("refused a signature it had just written")
		}
		if v.Get("Upload") != "true" {
			t.Errorf("Upload = %q, want true", v.Get("Upload"))
		}
	})

	t.Run("the same one, after it expires", func(t *testing.T) {
		if _, ok := signatureIsValid(signedAs(t, granted(), time.Now().Add(-time.Hour))); ok {
			t.Error("accepted an expired signature")
		}
	})

	t.Run("a grant added after the signing", func(t *testing.T) {
		// What somebody without the grant would do: take the signature
		// they were given and write the grant into it.
		raw, _ := base64.StdEncoding.DecodeString(
			signedAs(t, url.Values{"UserTier": {"Free"}}, time.Now().Add(time.Hour)),
		)
		v, _ := url.ParseQuery(string(raw))
		v.Set("Upload", "true")
		forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

		values, ok := signatureIsValid(forged)
		if ok {
			t.Error("accepted a signature with a grant written into it")
		}
		// Readable, and not to be believed. A caller is handed these so it
		// can name who is being turned away, not so it can ask what they
		// are allowed to do.
		if values.Get("Upload") != "true" {
			t.Error("the values of a refused signature should still come back")
		}
	})

	t.Run("nothing at all", func(t *testing.T) {
		for _, sig := range []string{"", "not base64", "Zm9vPSUlJQ=="} {
			if _, ok := signatureIsValid(sig); ok {
				t.Errorf("accepted %q as a signature", sig)
			}
		}
	})
}

// emailFromCookie asks signedUserEmail about a request carrying sig, the
// way a browser would carry it.
func emailFromCookie(t *testing.T, sig string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/upload/handoff", nil)
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	return signedUserEmail(req)
}

// signedUserEmail is the other caller, and carried its own copy of the
// check until now. It answers only for a signature that passes.
func TestSignedUserEmailNeedsAValidSignature(t *testing.T) {
	signingEnabled(t)

	sig := signedAs(t, url.Values{"UserEmail": {"someone@example.test"}}, time.Now().Add(time.Hour))
	if got := emailFromCookie(t, sig); got != "someone@example.test" {
		t.Errorf("email = %q, want someone@example.test", got)
	}

	// A name written into somebody else's signature. It decodes and it has
	// not expired, so nothing but the HMAC tells the two apart.
	raw, _ := base64.StdEncoding.DecodeString(sig)
	v, _ := url.ParseQuery(string(raw))
	v.Set("UserEmail", "elsewhere@example.test")
	forged := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	if got := emailFromCookie(t, forged); got != "" {
		t.Errorf("email = %q for a rewritten signature, want empty", got)
	}
}
