package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

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
