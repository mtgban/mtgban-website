package collectr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

func TestParseShowcaseURL(t *testing.T) {
	for _, tc := range []struct {
		link   string
		handle string
		ok     bool
	}{
		{"https://app.getcollectr.com/showcase/profile/@handle", "@handle", true},
		{"https://app.getcollectr.com/showcase/profile/@handle?category=1&cardType=cards", "@handle", true},
		{"https://app.getcollectr.com/showcase/profile/handle", "", false},
		{"https://app.getcollectr.com/profile/@handle", "", false},
		{"https://evil.example.com/showcase/profile/@handle", "", false},
	} {
		handle, err := ParseShowcaseURL(tc.link)
		if tc.ok && (err != nil || handle != tc.handle) {
			t.Errorf("%s: handle=%q err=%v, want %q", tc.link, handle, err, tc.handle)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error", tc.link)
		}
	}
}

const productJSON = `{"product_id":"12345","product_name":"Lightning Bolt ","catalog_group":"Magic 2011","card_number":"146","rarity":"Common","quantity":"3","market_price":"1.50","card_condition":"Lightly Played","product_sub_type":"Foil","is_card":true,"catalog_category_name":"Magic: The Gathering"}`

// The same products array arrives in two encodings: plain JSON in the RSC
// stream, and JS-escaped inside the SSR HTML script chunks.
func TestParseProductsBothEncodings(t *testing.T) {
	plain := `garbage{"products":[` + productJSON + `]}garbage`
	escaped := `<script>self.__next_f.push("` +
		strings.ReplaceAll(strings.ReplaceAll(`{"products":[`+productJSON+`]}`, `\`, `\\`), `"`, `\"`) +
		`")</script>`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"rsc plain", plain},
		{"html escaped", escaped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, err := parseProducts(tc.body, "Magic: The Gathering", 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 {
				t.Fatalf("items = %d, want 1", len(items))
			}
			item := items[0]
			if item.Name != "Lightning Bolt" || item.SetName != "Magic 2011" ||
				item.Number != "146" || item.Quantity != 3 || !item.IsFoil ||
				item.IsSealed || item.Condition != "SP" || item.Price != 1.50 ||
				item.ProductID != "12345" {
				t.Errorf("item = %+v", item)
			}
		})
	}
}

func TestParseProductsFiltersCategory(t *testing.T) {
	body := `{"products":[` + productJSON + `]}`
	if _, err := parseProducts(body, "Lorcana", 0); err == nil {
		t.Error("wrong category should yield no products")
	}
}

// stalledServer sends its headers and the start of a body, then holds the
// request open until the client gives up.
func stalledServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>`))
		err := http.NewResponseController(w).Flush()
		if err != nil {
			t.Error(err)
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A page that stalls mid-body is cut off by the client's timeout.
func TestFetchPageStalledBodyTimesOut(t *testing.T) {
	srv := stalledServer(t)

	saved := client
	client = mtgban.NewHTTPClient(mtgban.WithHTTPTimeout(200*time.Millisecond), mtgban.WithHTTPRetries(0))
	t.Cleanup(func() { client = saved })

	start := time.Now()
	_, err := fetchPage(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a stalled body read without error")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("stalled body took %v to fail, want about the 200ms timeout", elapsed)
	}
}

func TestFetchPageOversizeBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("a", maxBody+1)))
	}))
	defer srv.Close()

	_, err := fetchPage(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a body past maxBody read without error")
	}
}

// Every page of a walk shares the one deadline, so a showcase whose pages
// all stall fails once it passes, not after each page's own timeout.
func TestLoadWalkSharesOneDeadline(t *testing.T) {
	srv := stalledServer(t)

	saved := loadTimeout
	loadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { loadTimeout = saved })

	start := time.Now()
	_, err := Load(context.Background(), srv.URL, "https://app.getcollectr.com/showcase/profile/@handle", matcher.GameMagic, 0)
	if err == nil {
		t.Fatal("a stalled showcase loaded without error")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("walk took %v to fail, want about the 200ms deadline", elapsed)
	}
}
