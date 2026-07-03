package timeseries

// pgMaxParams is Postgres's hard limit on bind parameters in a single statement
// (the wire protocol encodes the count as an int16). Bulk upserts split their
// rows into batches so that batchRows * columnsPerRow stays under it.
const pgMaxParams = 65535

// clampBatchSize resolves a requested batch size to a safe one: a non-positive
// or oversized request falls back to maxBatch (the parameter-limited maximum).
func clampBatchSize(batchSize, maxBatch int) int {
	if batchSize <= 0 || batchSize > maxBatch {
		return maxBatch
	}
	return batchSize
}

// batchBounds splits total rows into contiguous [start, end) ranges, each no
// larger than the resolved batch size. Returns nil for zero rows.
func batchBounds(total, batchSize, maxBatch int) [][2]int {
	if total <= 0 {
		return nil
	}
	batchSize = clampBatchSize(batchSize, maxBatch)
	var bounds [][2]int
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		bounds = append(bounds, [2]int{start, end})
	}
	return bounds
}
