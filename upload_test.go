package main

import (
	"errors"
	"reflect"
	"testing"
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

func TestFilterEnabledStores(t *testing.T) {
	allowed := []string{"a", "b", "c"}

	tests := []struct {
		name      string
		submitted []string
		canChange bool
		want      []string
	}{
		{"locked returns all", []string{"a"}, false, allowed},
		{"empty submit falls back to all", nil, true, allowed},
		{"filters to valid subset", []string{"a", "c", "x"}, true, []string{"a", "c"}},
		{"all invalid falls back to all", []string{"x", "y"}, true, allowed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterEnabledStores(tc.submitted, allowed, tc.canChange)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("filterEnabledStores(%v, %v, %v) = %v, want %v",
					tc.submitted, allowed, tc.canChange, got, tc.want)
			}
		})
	}
}
