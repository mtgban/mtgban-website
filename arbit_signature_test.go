package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Arbitrage reads its grant only off a signature this host wrote: the ACL can
// open the page to everyone, and then nothing checks the cookie before it.
func TestArbitReadsGrantsOnlyOffAVerifiedSignature(t *testing.T) {
	// DevMode so render reads templates from disk; SigCheck so a grant counts
	// only when it verifies.
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Arbitrage"] == nil {
		LogPages["Arbitrage"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Arbitrage") })
	}
	seedReverseScrapers(t, "card-a")

	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}, "ArbitEnabled": {"ALL"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))
	fields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))

	page := func(sig string) string {
		req := httptest.NewRequest(http.MethodGet, "/arbit", nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		rec := httptest.NewRecorder()
		testSite.Arbit(rec, req)
		return rec.Body.String()
	}
	const seller = `<span class="store-name">Reverse Shop</span>`
	if !strings.Contains(page(signed), seller) {
		t.Fatal("a signed ArbitEnabled=ALL does not list the seller")
	}
	if strings.Contains(page(forged), seller) {
		t.Error("a forged ArbitEnabled=ALL listed the seller")
	}
}
