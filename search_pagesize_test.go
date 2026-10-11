package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// A phone pages search results at 25: the 100-result page was 2.6 MB of
// HTML with 3,871 vendor rows, and the phone profile spent two seconds
// laying it out.
func TestSearchPageSizeFollowsTheLayout(t *testing.T) {
	desktop := httptest.NewRequest(http.MethodGet, "/search?q=s:LEB", nil)
	if got := searchPageSize(desktop); got != MaxSearchResults {
		t.Errorf("desktop page size %d, want %d", got, MaxSearchResults)
	}
	phone := httptest.NewRequest(http.MethodGet, "/search?q=s:LEB", nil)
	phone.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	if got := searchPageSize(phone); got != MaxSearchResultsMobile {
		t.Errorf("phone page size %d, want %d", got, MaxSearchResultsMobile)
	}
}

// One link shows one slice of the results on a phone, on a desktop and in
// its unfurl: a page index reads at the size the link names, and at 100
// when it names none, as every link without one was written.
func TestOrderSearchKeysPagesOneSliceEverywhere(t *testing.T) {
	ds := &datastore{backend: &mtgmatcher.Backend{}}
	for _, tc := range []struct {
		query      string
		start, end int
		pageSize   int
	}{
		{"", 0, 25, 25},
		{"?p=3&ps=25", 50, 75, 25},
		{"?p=3", 200, 300, 0},
		{"?p=3&ps=100", 200, 300, 0},
		{"?p=3&ps=7", 200, 300, 0},
	} {
		for _, mobile := range []bool{true, false} {
			if tc.query == "" && !mobile {
				continue
			}
			r := httptest.NewRequest(http.MethodGet, "/search"+tc.query, nil)
			if mobile {
				r.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
			}
			var result searchResults
			for i := range 400 {
				result.keys = append(result.keys, fmt.Sprintf("k%03d", i))
			}
			shown := orderSearchKeys(r, ds, result, "chrono")
			if !slices.Equal(shown.keys, result.keys[tc.start:tc.end]) {
				t.Errorf("%q mobile=%v: shows %d cards, want %d-%d", tc.query, mobile, len(shown.keys), tc.start+1, tc.end)
			}
			if shown.pageSize != tc.pageSize {
				t.Errorf("%q mobile=%v: links name size %d, want %d", tc.query, mobile, shown.pageSize, tc.pageSize)
			}
		}
	}

	// The links carry the size the page was cut at, on either layout
	for _, mobile := range []bool{false, true} {
		pv := PageVars{
			UserNav:    &NavElem{Short: "b"},
			Pagination: Pagination{TotalIndex: 16, CurrentIndex: 3, PrevIndex: 2, NextIndex: 4},
			SearchVars: SearchVars{AllKeys: []string{"a"}, SearchRan: true, SearchQuery: "x", SearchSort: "chrono", TotalUnique: 400, PageSize: 25},
		}
		if !strings.Contains(renderPage(t, "search.html", mobile, pv), "&p=4&ps=25&") {
			t.Errorf("mobile=%v: the next page link does not name its size", mobile)
		}
	}
}
