package timeseries

import "testing"

func TestClampBatchSize(t *testing.T) {
	const max = 100
	cases := []struct{ in, want int }{
		{0, max},
		{-5, max},
		{50, 50},
		{max, max},
		{max + 1, max},
		{1_000_000, max},
	}
	for _, tc := range cases {
		if got := clampBatchSize(tc.in, max); got != tc.want {
			t.Errorf("clampBatchSize(%d, %d) = %d, want %d", tc.in, max, got, tc.want)
		}
	}
}

func TestBatchBounds(t *testing.T) {
	const max = 100

	if b := batchBounds(0, 0, max); b != nil {
		t.Errorf("expected nil bounds for 0 rows, got %v", b)
	}

	// Fewer rows than a batch collapse to a single batch.
	if b := batchBounds(50, 0, max); len(b) != 1 || b[0] != [2]int{0, 50} {
		t.Errorf("unexpected bounds for 50 rows: %v", b)
	}

	// More than one max batch must split, covering every row exactly once and
	// never exceeding the batch size.
	total := max*2 + 37
	bounds := batchBounds(total, 0, max)
	if len(bounds) != 3 {
		t.Fatalf("expected 3 batches for %d rows, got %d: %v", total, len(bounds), bounds)
	}
	prevEnd := 0
	for i, b := range bounds {
		if b[0] != prevEnd {
			t.Errorf("batch %d starts at %d, expected %d", i, b[0], prevEnd)
		}
		if size := b[1] - b[0]; size > max {
			t.Errorf("batch %d has %d rows, exceeds max %d", i, size, max)
		}
		prevEnd = b[1]
	}
	if prevEnd != total {
		t.Errorf("batches cover %d rows, expected %d", prevEnd, total)
	}

	// An explicit small batch size is honored.
	if b := batchBounds(10, 4, max); len(b) != 3 || b[0] != [2]int{0, 4} || b[2] != [2]int{8, 10} {
		t.Errorf("unexpected bounds for batchSize 4 over 10 rows: %v", b)
	}
}

// The per-table batch caps must keep a full batch under Postgres's parameter
// limit, since staying under it is the whole reason the upserts split at all.
func TestTCGBatchConstantsUnderParamLimit(t *testing.T) {
	if tcgMaxBatch*tcgColsPerRow > pgMaxParams {
		t.Errorf("tcgMaxBatch %d * %d cols = %d exceeds %d",
			tcgMaxBatch, tcgColsPerRow, tcgMaxBatch*tcgColsPerRow, pgMaxParams)
	}
	if tcgProductMaxBatch*tcgProductColsPerRow > pgMaxParams {
		t.Errorf("tcgProductMaxBatch %d * %d cols = %d exceeds %d",
			tcgProductMaxBatch, tcgProductColsPerRow, tcgProductMaxBatch*tcgProductColsPerRow, pgMaxParams)
	}
}
