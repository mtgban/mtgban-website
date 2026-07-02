// observability/event.go
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/mileusna/useragent"
)

// Event is one recorded page hit. Ts is left zero and filled by the DB default.
type Event struct {
	Ts      time.Time
	Path    string
	Tier    string
	Device  string // "mobile" | "desktop"
	Visitor string // sha256 of email, or "" for anonymous (stored NULL)
	IsBot   bool
}

// pageSubviews lists the recognized ?page= values per route. Anything else
// buckets to "<route>/other" so cardinality stays bounded.
var pageSubviews = map[string]map[string]bool{
	"newspaper": {
		"combined_spike_score": true, "spike_score": true,
		"greatest_increase_listings": true, "greatest_decrease_listings": true,
		"greatest_increase_buylist": true, "greatest_decrease_buylist": true,
		"syp": true, "options": true,
	},
	"sleepers": {
		"bulk": true, "reprint": true, "mismatch": true,
		"gap": true, "hotlist": true, "options": true,
	},
}

// NormalizePath maps a request path plus its page param to a low-cardinality key.
func NormalizePath(base, page string) string {
	base = strings.Trim(base, "/")
	if base == "" {
		return "home"
	}
	subs, ok := pageSubviews[base]
	if !ok {
		return base
	}
	if page == "" {
		return base + "/index"
	}
	if subs[page] {
		return base + "/" + page
	}
	return base + "/other"
}

// HashVisitor returns sha256(lowercased trimmed email) hex, or "" for empty input.
func HashVisitor(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(email))
	return hex.EncodeToString(sum[:])
}

// IsBot reports whether the user-agent string looks like a crawler.
func IsBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	return useragent.Parse(userAgent).Bot
}
