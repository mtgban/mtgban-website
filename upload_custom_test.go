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
	withPrices(t, sellers, currentPrices().vendors)

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

// On upload a rate that is not a positive finite number leaves out the
// custom buylist, as on search and arbit, and an infinite minimum price is
// ignored, hiding no offer.
func TestUploadCustomBuylistIgnoresABadSetting(t *testing.T) {
	cards := closeVendors(t)
	ref := mtgban.InventoryRecord{}
	for k, card := range cards {
		ref[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 10 + float64(k)}}
	}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA"))}
	withPrices(t, sellers, currentPrices().vendors)

	var rows strings.Builder
	for _, card := range cards {
		fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
	}
	for _, tt := range []struct {
		rate, minPrice string
		factor         float64
	}{
		{"Inf", "", 0},
		{"0", "", 0},
		{"abc", "", 0},
		{"", "", 0},
		{"0.5", "Inf", 0.5},
	} {
		form := url.Values{
			"mode":           {"true"},
			"stores":         {"ZZV", "ZZW"},
			"rows":           {rows.String()},
			"custombuylist":  {"true"},
			"customseller":   {"ZZA"},
			"customrate":     {tt.rate},
			"customminprice": {tt.minPrice},
		}
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		testSite.Upload(rec, req)
		page := rec.Body.String()

		if tt.factor == 0 {
			if strings.Contains(page, "/go/b/CUSTOM/") {
				t.Errorf("rate %q: the page has a custom buylist", tt.rate)
			}
			continue
		}
		for k, card := range cards {
			offer := regexp.MustCompile(`/go/b/CUSTOM/` + regexp.QuoteMeta(card) + `" target="_blank">\$ ([^<]+)</a>`)
			want := fmt.Sprintf("%.2f", (10+float64(k))*tt.factor)
			m := offer.FindStringSubmatch(page)
			if m == nil {
				t.Errorf("rate %q, minimum %q: no custom offer for %s, want $%s", tt.rate, tt.minPrice, card, want)
			} else if m[1] != want {
				t.Errorf("rate %q, minimum %q: custom offer for %s is $%s, want $%s", tt.rate, tt.minPrice, card, m[1], want)
			}
		}
	}
}

// On upload a row's grade the reference lacks is priced off the fallback at
// the rule's rate when the request names one; without it the row keeps the
// reference's flat price. The form speaks for a re-post, the cookies otherwise.
func TestUploadCustomBuylistFallback(t *testing.T) {
	cards := closeVendors(t)
	card := cards[0]
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			card: {{Conditions: "NM", Price: 10, Quantity: 1}},
		}, sessionInfo("ZZA")),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			card: {{Conditions: "NM", Price: 4, Quantity: 1}},
		}, sessionInfo("TCGLow")),
	}
	withPrices(t, sellers, currentPrices().vendors)

	offer := func(form url.Values, cookies map[string]string) string {
		t.Helper()
		form.Set("mode", "true")
		form.Set("stores", "ZZV")
		form.Set("rows", card+"\t1\tSP\t0\t\n")
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, value := range cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		rec := httptest.NewRecorder()
		testSite.Upload(rec, req)
		m := regexp.MustCompile(`/go/b/CUSTOM/` + regexp.QuoteMeta(card) + `" target="_blank">\$ ([0-9.]+)</a>`).FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no custom offer for %s", card)
		}
		return m[1]
	}

	base := url.Values{"custombuylist": {"true"}, "customseller": {"ZZA"}, "customrate": {"0.5"}}
	if got := offer(base, map[string]string{"UploadCustomSinglesFallback": "TCGLow"}); got != "5.00" {
		t.Errorf("no fallback on the form: SP offer is $%s, want the flat $5.00", got)
	}
	on := url.Values{"customfallback": {"TCGLow"}}
	for k, v := range base {
		on[k] = v
	}
	if got := offer(on, nil); got != "2.00" {
		t.Errorf("fallback on: SP offer is $%s, want $2.00", got)
	}
	got := offer(url.Values{}, map[string]string{
		"UploadCustomOpts": "enabled,", "UploadCustomBuyer": "ZZA",
		"UploadCustomRate": "0.5", "UploadCustomSinglesFallback": "TCGLow",
	})
	if got != "2.00" {
		t.Errorf("fallback on by cookie: SP offer is $%s, want $2.00", got)
	}
	got = offer(url.Values{}, map[string]string{
		"UploadCustomOpts": "enabled,", "UploadCustomBuyer": "ZZA", "UploadCustomRate": "0.5",
		"UploadCustomFallback": "TCGLow",
	})
	if got != "5.00" {
		t.Errorf("the old toggle's cookie alone: SP offer is $%s, want the flat $5.00", got)
	}
}

// The custom buylist's column, totals and optimizer section all say its rule,
// and no other store's does.
func TestUploadSpellsTheCustomBuylistRule(t *testing.T) {
	cards := closeVendors(t)
	ref := mtgban.InventoryRecord{}
	for _, card := range cards {
		ref[card] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 10}}
	}
	withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(ref, sessionInfo("ZZA"))}, currentPrices().vendors)
	withConfigCopy(t)
	Config().ScraperConfig.NameOverride = map[string]string{customStore: "Custom Buylist"}

	var rows strings.Builder
	for _, card := range cards {
		fmt.Fprintf(&rows, "%s\t1\t\t0\t\n", card)
	}
	form := url.Values{
		"mode":           {"true"},
		"stores":         {"ZZV"},
		"rows":           {rows.String()},
		"custombuylist":  {"true"},
		"customseller":   {"ZZA"},
		"customrate":     {"0.5"},
		"customminprice": {"2"},
		"optimizer":      {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	testSite.Upload(rec, req)
	page := rec.Body.String()

	const title = ` title="50% of ZZA if ≥ $2.00">Custom Buylist<`
	for _, tag := range []string{`<th class="r" data-sort-method="number" data-sort-descending`, `<span class="label"`, `<span class="toc-store"`, `<h3`} {
		if !strings.Contains(page, tag+title) {
			t.Errorf("no rule on %s in the %d byte page", tag, len(page))
		}
	}
	if !strings.Contains(page, `<th class="r" data-sort-method="number" data-sort-descending>Session ZZV<`) {
		t.Error("another store's column has lost its plain header")
	}
}
