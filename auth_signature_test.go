package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/ratelimit"
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

// signingEnabled turns the check on, since whether anything is verified at
// all is a global. dev keeps DevMode where the caller needs it: the link
// being signed for is read off it too, so minting and checking agree
// either way - but render() only reparses templates from disk while it is
// set, which is the only template cache a test binary has.
func signingEnabled(t *testing.T, dev bool) {
	t.Helper()
	savedDev, savedCheck := DevMode, SigCheck
	DevMode, SigCheck = dev, true
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
	signingEnabled(t, false)

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
	signingEnabled(t, false)

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

// enforceSigning checks the ?sig= whenever a request carries one, so that is
// the signature a handler has to read as well. A cookie sent beside it is
// never checked, and grants it claims must not be what adminOnly believes.
func TestHandlersActOnTheSignatureTheMiddlewareChecked(t *testing.T) {
	signingEnabled(t, true)
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

	reached := false
	handler := enforceSigning(adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})))

	valid := signedAs(t, url.Values{"UserEmail": {"sub@example.com"}}, time.Now().Add(time.Hour))
	forged := base64.StdEncoding.EncodeToString([]byte("Admin=true&Expires=99999999999"))

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/?sig="+url.QueryEscape(valid), nil)
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: forged})
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if reached {
		t.Error("a forged cookie beside a valid ?sig= reached an admin-only handler")
	}
}

// The API middleware lets a request with no ?sig= through as the demo, and
// checks nothing else about it. A cookie sent with it is unchecked too, and
// may lift it out of the demo stores only once its signature holds.
func TestSearchAPITakesNoUncheckedCookie(t *testing.T) {
	var uuid, name string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err != nil || co.Sealed || strings.ContainsAny(co.Name, ":,/'\"") {
			continue
		}
		uuid, name = id, co.Name
		break
	}
	if uuid == "" {
		t.Skip("no datastore loaded")
	}

	signingEnabled(t, false)
	prevDemo := Config.APIDemoStores
	t.Cleanup(func() { Config.APIDemoStores = prevDemo })
	Config.APIDemoStores = []string{"DEMO"}
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prevSellers); vendorsPtr.Store(prevVendors) })
	stock := mtgban.InventoryRecord{}
	stock.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 12.34, Quantity: 1})
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{Name: "Card Kingdom", Shorthand: "CK"})}
	vendors := []mtgban.Vendor{mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Name: "V", Shorthand: "V"})}
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)

	search := func(cookie string) string {
		req := httptest.NewRequest(http.MethodGet, "/api/mtgban/search/retail/"+url.PathEscape(name)+".json", nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: cookie})
		rec := httptest.NewRecorder()
		enforceAPISigning(http.HandlerFunc(SearchAPI)).ServeHTTP(rec, req)
		return rec.Body.String()
	}

	valid := sign("Pioneer", &PatreonUserData{Email: "sub@example.com", FullName: "Sub", EmailVerified: true}, nil, time.Hour)
	if !strings.Contains(search(valid), "12.34") {
		t.Fatal("a checked cookie did not reach the stores it grants")
	}
	forged := base64.StdEncoding.EncodeToString([]byte("Expires=99999999999"))
	if strings.Contains(search(forged), "12.34") {
		t.Error("a hand-written cookie lifted a sig-less API search out of the demo stores")
	}
}
