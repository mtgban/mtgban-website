// Package fuzzy provides small string-similarity helpers used to power
// "did you mean..." style suggestions.
package fuzzy

import "strings"

// Distance returns the edit distance between a and b, counting an
// insertion, a deletion, a substitution or a swap of two adjacent letters
// as one edit each (optimal string alignment), so a typo like "swapm"
// sits one edit from "swamp" rather than two. It stops early and returns
// limit+1 as soon as the distance is guaranteed to exceed limit.
// Comparison is byte-wise, which is enough for typo detection.
func Distance(a, b string, limit int) int {
	la, lb := len(a), len(b)
	if la-lb > limit || lb-la > limit {
		return limit + 1
	}

	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				curr[j] = min(curr[j], prev2[j-2]+1)
			}
			if curr[j] < rowMin {
				rowMin = curr[j]
			}
		}
		// Whole row already past the budget, no point continuing
		if rowMin > limit {
			return limit + 1
		}
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[lb]
}

// Closest returns the candidate closest to query under a tolerance that
// scales with the query length. It returns an empty string when no
// candidate is close enough, or when query exactly matches one of them
// (a valid value needs no suggestion). Matching is case-insensitive.
func Closest(query string, candidates []string) string {
	query = strings.ToLower(strings.TrimSpace(query))
	if len(query) < 3 {
		return ""
	}

	limit := len(query) / 4
	if limit < 2 {
		limit = 2
	}

	best := ""
	bestDist := limit + 1
	for _, candidate := range candidates {
		lower := strings.ToLower(candidate)
		if lower == query {
			return ""
		}
		if dist := Distance(query, lower, limit); dist < bestDist {
			bestDist = dist
			best = candidate
		}
	}
	return best
}
