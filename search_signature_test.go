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

// Search is open to everyone, so a store the tiers hide stays hidden from a
// cookie that only claims a grant lifting the block.
func TestSearchKeepsBlockedStoresFromAForgedGrant(t *testing.T) {
	name := searchStores(t)
	signingEnabled(t, true)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Search") })
	}
	prev := Config().SearchRetailBlockList
	t.Cleanup(func() { Config().SearchRetailBlockList = prev })
	Config().SearchRetailBlockList = []string{"SCG"}

	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Test"}, "SearchDisabled": {"NONE"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))
	fields.Set("Signature", "forged")
	forged := base64.StdEncoding.EncodeToString([]byte(fields.Encode()))

	search := func(sig string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(name), nil)
		req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
		rec := httptest.NewRecorder()
		testSite.Search(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Card Kingdom") {
			t.Fatalf("no results page: status %d", rec.Code)
		}
		return rec.Body.String()
	}
	if !strings.Contains(search(signed), "Star City Games") {
		t.Fatal("a signed SearchDisabled=NONE does not show the blocked store")
	}
	if strings.Contains(search(forged), "Star City Games") {
		t.Error("a forged SearchDisabled=NONE showed the blocked store")
	}
}
