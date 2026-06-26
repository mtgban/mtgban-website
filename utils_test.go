package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestTCGSKU2UUID(t *testing.T) {
	// Swap in a known infos snapshot, restore the real one afterwards.
	prev := infosPtr.Load()
	t.Cleanup(func() { infosPtr.Store(prev) })

	infos := map[string]mtgban.InventoryRecord{
		"tcgskuid": {
			"12345": {{OriginalId: "uuid-aaa"}},
			// Multiple entries for one SKU: the first one wins.
			"67890": {{OriginalId: "uuid-bbb"}, {OriginalId: "uuid-ccc"}},
		},
	}
	infosPtr.Store(&infos)

	cases := []struct {
		name string
		sku  string
		want string
	}{
		{"known sku", "12345", "uuid-aaa"},
		{"first entry wins", "67890", "uuid-bbb"},
		{"unknown sku", "99999", ""},
		{"empty sku", "", ""},
		{"unavailable sentinel", "Unavailable", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcgSKU2UUID(tc.sku); got != tc.want {
				t.Errorf("tcgSKU2UUID(%q) = %q, want %q", tc.sku, got, tc.want)
			}
		})
	}
}

func TestTCGSKU2UUIDNoInfos(t *testing.T) {
	prev := infosPtr.Load()
	t.Cleanup(func() { infosPtr.Store(prev) })

	// No snapshot published yet: must not panic and returns "".
	infosPtr.Store(nil)
	if got := tcgSKU2UUID("12345"); got != "" {
		t.Errorf("tcgSKU2UUID with no infos = %q, want empty string", got)
	}
}
