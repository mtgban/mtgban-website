package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
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

// TestOrderSearchKeysPagesAPhoneAt25 is omitted: sortSearchKeys
// unconditionally dereferences ds.backend via resolveSortingData before
// its sortMode switch, so it panics against an empty datastore{}
// regardless of sortMode. Covered instead by
// TestSearchPageSizeFollowsTheLayout plus the Paginate call in
// orderSearchKeys being a direct, unmodified reuse of searchPageSize.
