package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestCollectorNumberPadded pins the padded catalog against the number query.
// Pokemon writes 8,531 of its numbers with the padding the card face carries,
// "021", where the query has always been folded to "21", so the two never met
// and a number search answered nothing for the game.
func TestCollectorNumberPadded(t *testing.T) {
	for _, tt := range []struct {
		desc, query, number string
		want                bool
	}{
		{"the bare number reaches the padded printing", "cn:21", "021", true},
		{"and the number as the card pads it reaches it too", "cn:021", "021", true},
		{"a different number in the same set is still refused", "cn:22", "021", false},
		{
			// The padding is not a digit of its own: "21" and "021" are one
			// number, where "121" is another.
			desc:  "padding does not make one number another",
			query: "cn:121", number: "021", want: false,
		},
		{"a lettered number folds the same way", "cn:51a", "051a", true},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = tt.number
			co.OriginalNumber = tt.number

			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			elem := findNumberFilter(t, config, "number")
			if skip := applyCardFilter("number", elem.Values, co); skip == tt.want {
				t.Errorf("%s against %q: matched=%v, want %v",
					tt.query, tt.number, !skip, tt.want)
			}
		})
	}
}

// TestCollectorNumberUppercaseMark pins the four Secret Lair slivers numbered
// with a capital phi. The mark is trimmed from a lowercased number, so a
// cutset spelling it capital finds nothing to trim and the query keeps a mark
// the card no longer carries.
func TestCollectorNumberUppercaseMark(t *testing.T) {
	for _, tt := range []struct {
		query, filter, number, original string
	}{
		{"cn:635Φ", "number", "635Φ", "635"},
		{"cn:635φ", "number", "635Φ", "635"},
		{"cn:635", "number", "635Φ", "635"},
		{"cns:635Φ", "number_strict", "635Φ", "635"},
	} {
		t.Run(tt.query, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = tt.number
			co.OriginalNumber = tt.original

			config := parseSearchOptionsNG(tt.query, nil, nil, nil)
			elem := findNumberFilter(t, config, tt.filter)
			if skip := applyCardFilter(tt.filter, elem.Values, co); skip {
				t.Errorf("%s should reach the card numbered %s", tt.query, tt.number)
			}
		})
	}
}

// TestCollectorNumberComposite pins the numbers a game writes with a slash of
// its own. Flesh and Blood numbers 296 printings "AAZ030//AAZ031", and the
// set total no longer stands in a collector number at all, so nothing may be
// cut there.
func TestCollectorNumberComposite(t *testing.T) {
	co := &mtgmatcher.CardObject{}
	co.Number = "AAZ030//AAZ031"
	co.OriginalNumber = "AAZ030//AAZ031"

	config := parseSearchOptionsNG("cn:AAZ030//AAZ031", nil, nil, nil)
	elem := findNumberFilter(t, config, "number")
	if skip := applyCardFilter("number", elem.Values, co); skip {
		t.Error("a composite number should reach the card that prints it")
	}

	config = parseSearchOptionsNG("cn:AAZ030", nil, nil, nil)
	elem = findNumberFilter(t, config, "number")
	if skip := applyCardFilter("number", elem.Values, co); !skip {
		t.Error("the head of a composite number is another card's number")
	}
}
