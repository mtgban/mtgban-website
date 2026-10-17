package main

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A body past MaxUploadBodySize is cut off at the limit rather than spilled
// to disk whole, and the page says why nothing loaded. It goes through
// enforceSigning, whose FormValue is the first to read the body.
func TestUploadRefusesABodyPastTheLimit(t *testing.T) {
	quietUploadLog(t)
	savedDev, savedSig := DevMode, SigCheck
	DevMode, SigCheck = true, false // render the page from disk, unsigned
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("cardListFile", "list.csv")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("Name,Quantity\n"))
	line := []byte("Lightning Bolt,1\n")
	part.Write(bytes.Repeat(line, MaxUploadBodySize/len(line)+1))
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	enforceSigning(testSite, http.HandlerFunc(testSite.Upload)).ServeHTTP(rec, req)

	if page := rec.Body.String(); !strings.Contains(page, "request body too large") {
		t.Error("the page does not say the upload was too large")
	}
}

// The custom buylist is the reader's own rule over a store's retail list, so
// pricing the list in store credit leaves its offers as the rule sets them,
// while every store's own buylist is scaled by its credit rate.
func TestCustomBuylistKeepsItsOffersInCredit(t *testing.T) {
	cards := closeVendors(t)
	ref := mtgban.InventoryRecord{}
	for k, card := range cards {
		ref[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 10 + float64(k)}}
	}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA"))}
	sellersPtr.Store(&sellers)

	var rows strings.Builder
	for _, card := range cards {
		fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
	}
	for _, source := range []string{"", "credit", "marketCredit"} {
		form := url.Values{
			"mode":          {"true"},
			"stores":        {"ZZV", "ZZW"},
			"rows":          {rows.String()},
			"custombuylist": {"true"},
			"customseller":  {"ZZA"},
			"customrate":    {"0.5"},
			"pricesource":   {source},
		}
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		testSite.Upload(rec, req)
		page := rec.Body.String()

		for k, card := range cards {
			offer := regexp.MustCompile(`/go/b/CUSTOM/` + regexp.QuoteMeta(card) + `" target="_blank">\$ ([0-9.]+)</a>`)
			want := fmt.Sprintf("%.2f", (10+float64(k))*0.5)
			m := offer.FindStringSubmatch(page)
			if m == nil {
				t.Errorf("price source %q: no custom offer for %s, want $%s", source, card, want)
			} else if m[1] != want {
				t.Errorf("price source %q: custom offer for %s is $%s, want $%s", source, card, m[1], want)
			}
		}
	}
}
