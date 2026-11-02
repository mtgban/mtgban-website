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
