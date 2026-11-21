// Package natcmp compares strings naturally: runs of digits by their value,
// everything else byte by byte.
package natcmp

import (
	"cmp"
	"strings"
)

// Compare orders collector numbers as a reader does: runs of digits by
// their value and everything else as written, so 800 < 1553 < 1553★ and
// 12 < A-5. Readings that tie fall back to the strings, keeping it total.
func Compare(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if !isDigit(a[i]) || !isDigit(b[j]) {
			if a[i] != b[j] {
				return cmp.Compare(a[i], b[j])
			}
			i++
			j++
			continue
		}
		startI, startJ := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		runI := strings.TrimLeft(a[startI:i], "0")
		runJ := strings.TrimLeft(b[startJ:j], "0")
		if len(runI) != len(runJ) {
			return cmp.Compare(len(runI), len(runJ))
		}
		c := strings.Compare(runI, runJ)
		if c != 0 {
			return c
		}
	}
	c := cmp.Compare(len(a)-i, len(b)-j)
	if c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
