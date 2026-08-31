package docparse

import (
	"errors"
	"reflect"
	"testing"
)

func TestPartitionEntries(t *testing.T) {
	errEntry := Entry{MismatchError: errors.New("not found")}
	s1 := Entry{CardID: "single1"}
	s2 := Entry{CardID: "single2"}
	sealed1 := Entry{CardID: "sealed1"}
	sealedIDs := []string{"sealed1", "sealed2"}

	tests := []struct {
		name         string
		entries      []Entry
		wantSingles  []Entry
		wantSealed   []Entry
		wantNotFound []Entry
	}{
		{
			name:        "mixed splits by membership",
			entries:     []Entry{s1, sealed1},
			wantSingles: []Entry{s1},
			wantSealed:  []Entry{sealed1},
		},
		{
			name:        "singles only",
			entries:     []Entry{s1, s2},
			wantSingles: []Entry{s1, s2},
		},
		{
			name:         "errors go to notFound with sealed",
			entries:      []Entry{sealed1, errEntry},
			wantSealed:   []Entry{sealed1},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "errors go to notFound with singles",
			entries:      []Entry{s1, errEntry},
			wantSingles:  []Entry{s1},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "only errors go to notFound",
			entries:      []Entry{errEntry},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "mixed with errors",
			entries:      []Entry{s1, sealed1, errEntry},
			wantSingles:  []Entry{s1},
			wantSealed:   []Entry{sealed1},
			wantNotFound: []Entry{errEntry},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSingles, gotSealed, gotNotFound := PartitionEntries(tc.entries, sealedIDs)
			if !reflect.DeepEqual(gotSingles, tc.wantSingles) {
				t.Errorf("singles = %v, want %v", gotSingles, tc.wantSingles)
			}
			if !reflect.DeepEqual(gotSealed, tc.wantSealed) {
				t.Errorf("sealed = %v, want %v", gotSealed, tc.wantSealed)
			}
			if !reflect.DeepEqual(gotNotFound, tc.wantNotFound) {
				t.Errorf("notFound = %v, want %v", gotNotFound, tc.wantNotFound)
			}
		})
	}
}

func TestParseHeaderMtgbanExport(t *testing.T) {
	p := &Parser{}
	header := []string{"Key", "Name", "Edition", "Finish", "Number", "Rarity", "Conditions", "Price", "Quantity", "URL", "Seller", "Bundle", "Original Id", "Instance Id"}
	indexMap, err := p.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	want := map[string]int{
		"id": 0, "cardName": 1, "edition": 2, "printing": 3,
		"variant": 4, "conditions": 6, "price": 7, "quantity": 8,
	}
	for field, idx := range want {
		if got, found := indexMap[field]; !found || got != idx {
			t.Errorf("%s = %d (found %v), want %d", field, got, found, idx)
		}
	}
}

func TestGetQuantity(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"4", 4, true},
		{"4x", 4, true},
		{" 12x ", 0, false}, // suffix strip happens before trim
		{"12 ", 12, true},
		{"x", 0, false},
		{"", 0, false},
	} {
		got, err := GetQuantity(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("GetQuantity(%q) = %d, %v; want %d, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParseRowInfersConditionFromSKU(t *testing.T) {
	p := &Parser{
		TCGSkuToUUID: func(sku string) string { return "uuid-" + sku },
		TCGSkuToCondition: func(sku string) string {
			if sku == "SKU-SP" {
				return "SP"
			}
			return ""
		},
	}

	tests := []struct {
		name     string
		indexMap map[string]int
		record   []string
		want     string
	}{
		{
			"inferred from SKU when no condition column",
			map[string]int{"cardName": 0, "tcgSku": 1},
			[]string{"Some Card", "SKU-SP"},
			"SP",
		},
		{
			"explicit condition column wins over the SKU",
			map[string]int{"cardName": 0, "tcgSku": 1, "conditions": 2},
			[]string{"Some Card", "SKU-SP", "Heavily Played"},
			"HP",
		},
		{
			"unknown SKU leaves the condition blank",
			map[string]int{"cardName": 0, "tcgSku": 1},
			[]string{"Some Card", "SKU-UNKNOWN"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Card matching needs the datastore (not loaded here); the condition
			// is inferred before Match, so the resolution error is irrelevant.
			res, _ := p.ParseRow(tt.indexMap, tt.record)
			if res.OriginalCondition != tt.want {
				t.Errorf("OriginalCondition = %q, want %q", res.OriginalCondition, tt.want)
			}
		})
	}
}
