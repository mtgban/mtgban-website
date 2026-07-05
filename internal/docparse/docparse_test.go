package docparse

import (
	"errors"
	"reflect"
	"testing"
)

func TestPartitionEntries(t *testing.T) {
	errEntry := Entry{MismatchError: errors.New("not found")}
	s1 := Entry{CardId: "single1"}
	s2 := Entry{CardId: "single2"}
	sealed1 := Entry{CardId: "sealed1"}
	sealedIds := []string{"sealed1", "sealed2"}

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
			gotSingles, gotSealed, gotNotFound := PartitionEntries(tc.entries, sealedIds)
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
