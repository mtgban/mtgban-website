package main

import (
	"net/url"
	"testing"
)

func TestBlocklistsFromValues(t *testing.T) {
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"TCG"}

	retail, buylist := blocklistsFromValues(url.Values{})
	if len(retail) != 1 || retail[0] != "TCG" || len(buylist) != 0 {
		t.Fatalf("defaults: retail=%v buylist=%v", retail, buylist)
	}
	retail, buylist = blocklistsFromValues(url.Values{"SearchDisabled": {"NONE"}, "SearchBuylistDisabled": {"CK,SCG"}})
	if len(retail) != 0 || len(buylist) != 2 {
		t.Fatalf("explicit: retail=%v buylist=%v", retail, buylist)
	}
	r, _ := blocklistsFromValues(nil)
	if len(r) != 1 {
		t.Fatalf("nil values should read the defaults, got %v", r)
	}
}

// Paginate reaches a last page holding fewer than a page's worth, whether
// the total it may show is the slice's length or a cap past it, and stops at
// a cap shorter than the slice.
func TestPaginateReachesThePartialLastPage(t *testing.T) {
	items := make([]int, 77433)
	for _, tc := range []struct {
		name     string
		maxTotal int
		pages    int
		last     int
	}{
		{"every item", len(items), 775, 33},
		{"a cap past them", 100000, 775, 33},
		{"a cap short of them", 1000, 10, 100},
	} {
		page, pagination := Paginate(items, tc.pages+1, 100, tc.maxTotal)
		if pagination.TotalIndex != tc.pages || pagination.CurrentIndex != tc.pages || len(page) != tc.last {
			t.Errorf("%s: %d pages, on page %d of %d items, want %d pages, the last of %d", tc.name, pagination.TotalIndex, pagination.CurrentIndex, len(page), tc.pages, tc.last)
		}
	}
}
