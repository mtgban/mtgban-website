package main

import "testing"

// A cap equal to the slice length must still reach the last partial page,
// and a cap below it must still floor at one page and never pass the chop.
func TestPaginateCountsAPartialLastPage(t *testing.T) {
	rows := make([]int, 30)
	for i := range rows {
		rows[i] = i + 1
	}
	tests := []struct {
		name             string
		index, size, cap int
		wantTotal        int
		wantFirst        int
		wantLen          int
	}{
		{"page 1 of 30 by 25", 1, 25, 30, 2, 1, 25},
		{"page 2 of 30 by 25", 2, 25, 30, 2, 26, 5},
		{"index past the end clamps", 9, 25, 30, 2, 26, 5},
		{"exact multiple", 2, 15, 30, 2, 16, 15},
		{"cap below the slice", 2, 25, 10, 1, 1, 25},
		{"cap below one page", 1, 25, 3, 1, 1, 25},
	}
	for _, tt := range tests {
		got, page := Paginate(rows, tt.index, tt.size, tt.cap)
		if page.TotalIndex != tt.wantTotal || len(got) != tt.wantLen || (len(got) > 0 && got[0] != tt.wantFirst) {
			t.Errorf("%s: total %d len %d first %v, want %d %d %d", tt.name, page.TotalIndex, len(got), got, tt.wantTotal, tt.wantLen, tt.wantFirst)
		}
	}
}
