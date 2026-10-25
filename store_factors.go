package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// storeFactor is a user's adjustment for one store, both in percent and
// zero when unset: a discount off retail, and what its credit is worth.
type storeFactor struct {
	Discount int
	Credit   int
}

const (
	minDiscount, maxDiscount   = 1, 90
	minCreditPct, maxCreditPct = 10, 300
	storeFactorsCookie         = "SearchStoreFactors"
	maxStoreFactors            = 256
)

// readStoreFactors reads the SearchStoreFactors cookie, which js/store-factors.js
// keeps equal to the synced preference.
func readStoreFactors(r *http.Request) map[string]storeFactor {
	return parseStoreFactors(readCookie(r, storeFactorsCookie))
}

// parseStoreFactors reads SHORTHAND:DISCOUNT:CREDIT items joined by commas.
// A malformed or out-of-range item is dropped on its own; nil when none apply.
// Items past maxStoreFactors are ignored.
func parseStoreFactors(raw string) map[string]storeFactor {
	var out map[string]storeFactor
	items := strings.SplitN(raw, ",", maxStoreFactors+1)
	if len(items) > maxStoreFactors {
		items = items[:maxStoreFactors]
	}
	for _, item := range items {
		parts := strings.Split(item, ":")
		if len(parts) != 3 || !validStoreShorthand(parts[0]) {
			continue
		}
		discount, okD := percentIn(parts[1], minDiscount, maxDiscount)
		credit, okC := percentIn(parts[2], minCreditPct, maxCreditPct)
		if !okD || !okC {
			continue
		}
		if credit == 100 {
			credit = 0
		}
		if discount == 0 && credit == 0 {
			continue
		}
		if out == nil {
			out = map[string]storeFactor{}
		}
		out[parts[0]] = storeFactor{Discount: discount, Credit: credit}
	}
	return out
}

// percentIn reads an integer in [lo, hi]; empty is zero, meaning unset.
func percentIn(s string, lo, hi int) (int, bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

func validStoreShorthand(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		alnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// applyStoreFactors rewrites the offers of the stores in factors, in place
// on the entries runSearch built, keeping the quoted numbers beside them.
// It runs before sortOfferRows so the ranking sees the adjusted numbers.
func applyStoreFactors(result searchResults, factors map[string]storeFactor) {
	if len(factors) == 0 {
		return
	}
	for _, conds := range result.sellers {
		for cond, entries := range conds {
			if cond == "INDEX" {
				continue
			}
			for i := range entries {
				if f, ok := factors[entries[i].Shorthand]; ok {
					entries[i].discount(f.Discount)
				}
			}
		}
	}
	for _, conds := range result.vendors {
		for cond, entries := range conds {
			if cond == "INDEX" {
				continue
			}
			for i := range entries {
				if f, ok := factors[entries[i].Shorthand]; ok {
					entries[i].scaleCredit(f.Credit)
				}
			}
		}
	}
}

// adjustable says whether the row is an offer a factor may rewrite.
// Locked is set later by gateNonAffiliates and renders no price: defensive.
func (e *SearchEntry) adjustable() bool {
	return e.IsOffer() && !e.Locked && e.Shorthand != "CUSTOM" && e.Price > 0
}

// discount takes pct percent off a seller's price; its credit equivalent
// keeps the store's ratio.
func (e *SearchEntry) discount(pct int) {
	if pct <= 0 || !e.adjustable() {
		return
	}
	e.OrigPrice = e.Price
	e.DiscountPct = pct
	e.Price = round2(e.OrigPrice * float64(100-pct) / 100)
	if e.Price < 0.01 {
		e.Price = 0.01
	}
	if e.Credit > 0 {
		e.Credit = round2(e.Credit * float64(100-pct) / 100)
	}
}

// scaleCredit values a vendor's credit at pct percent of face; cash stays.
func (e *SearchEntry) scaleCredit(pct int) {
	if pct <= 0 || e.Credit <= 0 || !e.adjustable() {
		return
	}
	e.OrigCredit = e.Credit
	e.Credit = math.Max(round2(e.Credit*float64(pct)/100), 0.01)
	// Zero market credit means the store has no market rate
	if e.MarketCredit > 0 {
		e.MarketCredit = math.Max(round2(e.MarketCredit*float64(pct)/100), 0.01)
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// Adjusted says whether a store adjustment rewrote this row.
func (e SearchEntry) Adjusted() bool {
	return e.OrigPrice > 0 || e.OrigCredit > 0
}

// AdjustTip quotes the store's own number beside an adjusted one.
func (e SearchEntry) AdjustTip() string {
	switch {
	case e.OrigPrice > 0:
		return fmt.Sprintf("Store price $ %.2f, your %d%% discount applied", e.OrigPrice, e.DiscountPct)
	case e.OrigCredit > 0:
		return fmt.Sprintf("Credit at face $ %.2f", e.OrigCredit)
	}
	return ""
}

// RetailTip is the retail price's one tooltip: its credit equivalent, the
// adjustment, or both on two lines.
func (e SearchEntry) RetailTip() string {
	var lines []string
	if e.Credit > 0 {
		lines = append(lines, fmt.Sprintf("Equivalent price if paid with credit: $ %.2f", e.Credit))
	}
	if tip := e.AdjustTip(); tip != "" {
		lines = append(lines, tip)
	}
	return strings.Join(lines, "\n")
}

// storeFactorOptions lists the stores the adjustments editor offers, each
// with its name, the sides it has and whether it is a sealed store, singles
// stores first, as JSON for a data attribute.
func storeFactorOptions(sellers, vendors []string) string {
	type option struct {
		Key    string `json:"k"`
		Name   string `json:"n"`
		Sells  bool   `json:"r"`
		Buys   bool   `json:"b"`
		Sealed bool   `json:"s,omitempty"`
	}
	byKey := map[string]*option{}
	var keys []string
	add := func(shorthand string, sells bool) {
		o, ok := byKey[shorthand]
		if !ok {
			name := scraperName(shorthand)
			if name == "" {
				name = shorthand
			}
			o = &option{Key: shorthand, Name: name, Sealed: isSealedScraper(shorthand)}
			byKey[shorthand] = o
			keys = append(keys, shorthand)
		}
		if sells {
			o.Sells = true
		} else {
			o.Buys = true
		}
	}
	for _, s := range sellers {
		if metadataOnly(s) {
			continue
		}
		add(s, true)
	}
	for _, v := range vendors {
		add(v, false)
	}
	list := make([]option, 0, len(keys))
	for _, k := range keys {
		list = append(list, *byKey[k])
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Sealed != list[j].Sealed {
			return !list[i].Sealed
		}
		a, b := strings.ToLower(list[i].Name), strings.ToLower(list[j].Name)
		if a != b {
			return a < b
		}
		return list[i].Key < list[j].Key
	})
	out, _ := json.Marshal(list)
	return string(out)
}

// metadataOnly says whether a loaded seller is a reference index, not a
// store a user buys from.
func metadataOnly(shorthand string) bool {
	seller, found := currentStoreIndex().seller[shorthand]
	return found && seller.Info().MetadataOnly
}
