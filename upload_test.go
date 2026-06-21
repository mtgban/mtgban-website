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

