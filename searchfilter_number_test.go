package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestCollectorNumberPlainForm pins a loose number query to the plain number
// the loaded game reduces to. The query was folded by the search itself out
// of the Magic suffix constants, which is a game's vocabulary in a filter
// serving nine of them, and which spelled the phi in a case no number carries
// so that "cn:635Φ" reached nothing.
func TestCollectorNumberPlainForm(t *testing.T) {
	skipWithoutDatastore(t)
	for _, tt := range []struct {
		desc, query, number, original string
		want                          bool
	}{
		{
			desc:  "the number the card prints reaches it",
			query: "cn:635Φ", number: "635Φ", original: "635", want: true,
		},
		{
			desc:  "and so does the plain number behind the mark",
			query: "cn:635", number: "635Φ", original: "635", want: true,
		},
		{
			desc:  "the letters that name a printing read the same way",
			query: "cn:139s", number: "139s", original: "139", want: true,
		},
		{
			desc:  "a number a game writes with a slash of its own is not cut",
			query: "cn:AAZ030//AAZ031", number: "AAZ030//AAZ031",
			original: "AAZ030//AAZ031", want: true,
		},
		{
			desc:  "and another number is still refused",
			query: "cn:636", number: "635Φ", original: "635", want: false,
		},
		{
			desc:  "a number written with its set code reaches that printing",
			query: "cn:hnt222", number: "HNT222", original: "222", want: true,
		},
		{
			desc:  "and not the same ordinal in another set",
			query: "cn:hnt222", number: "MST222", original: "222", want: false,
		},
		{
			desc:  "nor does a letter tail reach the printing without it",
			query: "cn:139s", number: "139", original: "139", want: false,
		},
		{
			desc:  "a lettered number still reaches the plain form the game keeps",
			query: "cn:ogn-001", number: "OGN-001*", original: "OGN-001", want: true,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = tt.number
			co.PlainNumber = tt.original

			config := parseSearchOptionsNG(backend(), tt.query, nil, nil, nil)
			elem := findNumberFilter(t, config, "number")
			skip := applyCardFilter(backend(), "number", elem.Values, co)
			if skip == tt.want {
				t.Errorf("%s against %q: matched=%v, want %v",
					tt.query, tt.number, !skip, tt.want)
			}
		})
	}
}

// TestCollectorNumberStrictIsVerbatim pins the strict query to the number as
// the catalog writes it. It used to have its padding trimmed like a loose
// one, so "cns:021" asked for 21 and reached no card of the 8,531 Pokemon
// numbers written with the padding their face carries.
func TestCollectorNumberStrictIsVerbatim(t *testing.T) {
	for _, tt := range []struct {
		desc, query, number string
		want                bool
	}{
		{"the number as written reaches the printing", "cns:021", "021", true},
		{"and the plain number does not", "cns:21", "021", false},
		{"a mark is kept rather than trimmed", "cns:107★", "107★", true},
		{"so the plain number misses the marked printing", "cns:107", "107★", false},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = tt.number
			co.PlainNumber = tt.number

			config := parseSearchOptionsNG(backend(), tt.query, nil, nil, nil)
			elem := findNumberFilter(t, config, "number_strict")
			skip := applyCardFilter(backend(), "number_strict", elem.Values, co)
			if skip == tt.want {
				t.Errorf("%s against %q: matched=%v, want %v",
					tt.query, tt.number, !skip, tt.want)
			}
		})
	}
}
