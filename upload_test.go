package main

import (
	"reflect"
	"testing"
)

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
