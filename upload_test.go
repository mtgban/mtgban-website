package main

import (
	"errors"
	"io"
	"log"
	"reflect"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestPartitionEntries(t *testing.T) {
	errEntry := UploadEntry{MismatchError: errors.New("not found")}
	s1 := UploadEntry{CardId: "single1"}
	s2 := UploadEntry{CardId: "single2"}
	sealed1 := UploadEntry{CardId: "sealed1"}
	sealedIds := []string{"sealed1", "sealed2"}

	tests := []struct {
		name         string
		entries      []UploadEntry
		wantSingles  []UploadEntry
		wantSealed   []UploadEntry
		wantNotFound []UploadEntry
	}{
		{
			name:        "mixed splits by membership",
			entries:     []UploadEntry{s1, sealed1},
			wantSingles: []UploadEntry{s1},
			wantSealed:  []UploadEntry{sealed1},
		},
		{
			name:        "singles only",
			entries:     []UploadEntry{s1, s2},
			wantSingles: []UploadEntry{s1, s2},
		},
		{
			name:         "errors go to notFound with sealed",
			entries:      []UploadEntry{sealed1, errEntry},
			wantSealed:   []UploadEntry{sealed1},
			wantNotFound: []UploadEntry{errEntry},
		},
		{
			name:         "errors go to notFound with singles",
			entries:      []UploadEntry{s1, errEntry},
			wantSingles:  []UploadEntry{s1},
			wantNotFound: []UploadEntry{errEntry},
		},
		{
			name:         "only errors go to notFound",
			entries:      []UploadEntry{errEntry},
			wantNotFound: []UploadEntry{errEntry},
		},
		{
			name:         "mixed with errors",
			entries:      []UploadEntry{s1, sealed1, errEntry},
			wantSingles:  []UploadEntry{s1},
			wantSealed:   []UploadEntry{sealed1},
			wantNotFound: []UploadEntry{errEntry},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSingles, gotSealed, gotNotFound := partitionEntries(tc.entries, sealedIds)
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

// The mtgban inventory/cart CSV export must round-trip through the uploader:
// the Key column resolves directly by uuid, and with no usable id the sealed
// name fallback must handle punctuation loss and parenthesized variants.
func TestUploadSealedCSV(t *testing.T) {
	if len(mtgmatcher.GetSealedUUIDs()) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
	}

	header := []string{"Key", "Name", "Edition", "Finish", "Number", "Rarity", "Conditions", "Price", "Quantity", "URL", "Seller", "Bundle", "Original Id", "Instance Id"}
	indexMap, err := parseHeader(header)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if idx, found := indexMap["id"]; !found || idx != 0 {
		t.Fatalf("Key column not mapped to id: %v", indexMap)
	}

	rows := [][]string{
		{"9e295ba4-a378-5259-8ba9-5a67ead6d17f", "Champions of Kamigawa Fat Pack", "Champions of Kamigawa", "sealed", "", "product", "NM", "368.58", "4", "url", "", "", "116082", "750831"},
		{"48ff4766-9d88-5426-800a-1613c990011b", "Mystery Booster Booster Box (Convention Edition)", "Mystery Booster", "sealed", "", "product", "NM", "15.36", "150", "url", "", "", "101685", "659571"},
		{"96772e6d-0aba-5362-ab10-d5f3f6d23634", "Urzas Saga Tournament Pack", "Urza's Saga", "sealed", "", "product", "NM", "645.01", "70", "url", "", "", "23679", "159742"},
	}

	// Path 1: resolve via the Key uuid
	for _, row := range rows {
		if _, err := mtgmatcher.GetUUID(row[0]); err != nil {
			t.Logf("uuid %s not in local datastore, skipping id check", row[0])
			continue
		}
		res, err := parseRow(indexMap, append([]string{}, row...))
		if err != nil {
			t.Fatalf("parseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("id path %q: MismatchError = %v", row[1], res.MismatchError)
		}
		if res.CardId == "" {
			t.Errorf("id path %q: empty CardId", row[1])
		}
	}

	// Path 2: blank the Key so the sealed-name fallback has to do the work
	for _, row := range rows {
		nameOnly := append([]string{}, row...)
		nameOnly[0] = ""
		res, err := parseRow(indexMap, nameOnly)
		if err != nil {
			t.Fatalf("parseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("name path %q: MismatchError = %v", row[1], res.MismatchError)
			continue
		}
		if res.CardId == "" {
			t.Errorf("name path %q: empty CardId", row[1])
			continue
		}
		co, err := mtgmatcher.GetUUID(res.CardId)
		if err != nil || !co.Sealed {
			t.Errorf("name path %q: resolved to non-sealed %q", row[1], res.CardId)
		}
		t.Logf("name path %q -> %s (%s)", row[1], res.CardId, co.Name)
	}
}
