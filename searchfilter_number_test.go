package main

import (
	"slices"
	"strings"
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

// TestCollectorNumberWithTotal pins a number written with the set total its
// card prints, "222/236", to cards carrying both. Pokemon and Lorcana print
// no set code on their cards, so the total is what tells one 222 from
// another.
func TestCollectorNumberWithTotal(t *testing.T) {
	skipWithoutDatastore(t)
	for _, tt := range []struct {
		desc, query, number, total string
		want                       bool
	}{
		{"the number and total reach the card", "cn:222/236", "222", "236", true},
		{"and so does the bare query", "222/236", "222", "236", true},
		{"or the bare query after a name", "Mewtwo 222/236", "222", "236", true},
		{"padding on either side is dropped", "cn:#0222/0236", "222", "236", true},
		{"a total with letters is compared folded", "cn:TG01/tg30", "TG01", "TG30", true},
		{"another total is refused", "222/236", "222", "214", false},
		{"so is a card printing no total", "222/236", "222", "", false},
		{"a number in the list without one still matches", "cn:1/102,222", "222", "214", true},
		{"a number written with a slash matches whole", "cn:MON219/MON220", "MON219/MON220", "", true},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Number = tt.number
			co.PlainNumber = tt.number
			co.SetTotal = tt.total

			config := parseSearchOptionsNG(backend(), tt.query, nil, nil, nil)
			elem := findNumberFilter(t, config, "number_total")
			skip := applyCardFilter(backend(), "number_total", elem.Values, co)
			if skip == tt.want {
				t.Errorf("%s against %s/%s: matched=%v, want %v",
					tt.query, tt.number, tt.total, !skip, tt.want)
			}
		})
	}
}

// TestBareNumberAgreesWithTheSeed checks bareNumberFilters against Magic's
// catalog; TestBareNumberInEveryGame does the same for the other games.
func TestBareNumberAgreesWithTheSeed(t *testing.T) {
	skipWithoutDatastore(t)
	checkBareNumbersAgreeWithSeed(t, testSite.datastore())
}

// checkBareNumbersAgreeWithSeed reads every number the catalog carries alone
// and checks that bareNumberFilters takes it as its cn:/cns: term parses, and
// exactly when searchAndFilter's number seed finds a card for that term.
func checkBareNumbersAgreeWithSeed(t *testing.T, ds *datastore) {
	t.Helper()
	b := ds.backend
	var checked, failed int
	for _, index := range []map[string][]string{ds.numbers.loose, ds.numbers.strict} {
		for number := range index {
			if !writtenAsNumber(number) || typesSetTotal(number) {
				continue
			}
			checked++
			got := bareNumberFilters(b, ds.numbers, number)
			var want []FilterElem
			term := numberTerm(b, number)
			_, named := b.SearchEquals(number)
			if term != "" && named != nil {
				parsed := parseSearchOptionsNG(b, term, nil, nil, nil).CardFilters
				uuids, _ := numberSeedUUIDs(ds.numbers, parsed)
				if len(uuids) != 0 {
					want = parsed
				}
			}
			same := len(got) == len(want) && (len(got) == 0 ||
				got[0].Name == want[0].Name && slices.Equal(got[0].Values, want[0].Values))
			if !same {
				failed++
				if failed <= 10 {
					t.Errorf("%q reads as %+v, its term %q as %+v", number, got, term, want)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no numbers checked")
	}
	if failed > 0 {
		t.Errorf("%d of %d numbers disagree", failed, checked)
	}
}

// A number typed alone is a collector number: "123" reaches what cn:123
// does, though 123 is a TCGplayer product id too, which id:123 still reaches.
// A number no card carries is still read as the id it can be.
func TestBareNumberIsACollectorNumber(t *testing.T) {
	skipWithoutDatastore(t)
	ds := testSite.datastore()
	search := func(config SearchConfig) []string {
		t.Helper()
		keys, err := searchAndFilter(ds, config)
		if err != nil {
			t.Fatalf("%q: %v", config.CleanQuery, err)
		}
		slices.Sort(keys)
		return keys
	}
	typed := func(query, scope string) []string {
		t.Helper()
		config := parseSearchQuery(ds, query, nil, nil, nil)
		applySearchScope(&config, scopeFilters(ds, scope, false))
		return search(config)
	}

	for _, tt := range []struct{ query, scope, as string }{
		{"123", "", "cn:123"},
		{"#123", "", "cn:123"},
		{"0123", "", "cn:123"},
		{"17a", "", "cns:17a"},
		{"1★", "", "cns:1★"},
		{"123*", "", "cn:123 f:foil"},
		{"s:mmq 123", "", "s:mmq cn:123"},
		{"123", "s:LTR", "s:ltr cn:123"},
		{"", "123", "cn:123"},
	} {
		want := typed(tt.as, "")
		if len(want) == 0 {
			t.Fatalf("%q reaches nothing", tt.as)
		}
		if got := typed(tt.query, tt.scope); !slices.Equal(got, want) {
			t.Errorf("%q pinned %q reaches %d cards, %q reaches %d", tt.query, tt.scope, len(got), tt.as, len(want))
		}
	}

	// A pinned number no card carries is no filter, which the bar reports.
	if len(ds.numbers.loose["99999"]) != 0 {
		t.Fatal("a card carries 99999")
	}
	if pinned := scopeFilters(ds, "99999", false); pinned != nil {
		t.Errorf("pinned 99999 is %+v, want no filter", pinned)
	}

	// A TCGplayer id that is also a collector number, and one that is not.
	var carried, uncarried string
	for _, uuid := range ds.backend.GetUUIDs() {
		co, err := ds.backend.GetUUID(uuid)
		if err != nil || slices.Contains(filteredEditions, co.SetCode) {
			continue
		}
		id := co.Identifiers["tcgplayerProductId"]
		if id == "" || ds.backend.ConvertID(mtgmatcher.IDSpaceTCGplayer, id) != uuid {
			continue
		}
		numbered := len(ds.numbers.loose[id]) != 0 || len(ds.numbers.strict[id]) != 0
		if numbered && carried == "" {
			carried = id
		} else if !numbered && uncarried == "" {
			uncarried = id
		}
	}
	if carried == "" || uncarried == "" {
		t.Fatalf("no TCGplayer ids to check: %q %q", carried, uncarried)
	}

	if config := parseSearchQuery(ds, carried, nil, nil, nil); config.SearchMode == "hashing" {
		t.Errorf("%q is read as a TCGplayer id, not a collector number", carried)
	}
	idlookup := parseSearchQuery(ds, "id:"+carried, nil, nil, nil)
	if len(idlookup.CardFilters) != 1 || idlookup.CardFilters[0].Name != "idlookup" {
		t.Errorf("id:%s is not an id lookup: %+v", carried, idlookup.CardFilters)
	}
	uuid := ds.backend.ConvertID(mtgmatcher.IDSpaceTCGplayer, uncarried)
	if config := parseSearchQuery(ds, uncarried, nil, nil, nil); !slices.Equal(config.UUIDs, []string{uuid}) {
		t.Errorf("%q reaches %v, want the TCGplayer id's %s", uncarried, config.UUIDs, uuid)
	}

	// A sealed search reads a number that is no id as words of a product's
	// name, though cards carry it as their collector number.
	var word string
	for _, uuid := range ds.backend.GetSealedUUIDs() {
		co, err := ds.backend.GetUUID(uuid)
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(co.Name) {
			if word == "" && writtenAsNumber(field) && len(ds.numbers.loose[field]) != 0 &&
				externalUUID(ds.backend, field) == "" {
				word = field
			}
		}
	}
	if word == "" {
		t.Fatal("no sealed product names a number a card carries")
	}
	sealed := parseSearchPage(ds, word, true, nil, nil, nil)
	sealed.SearchMode = "sealed"
	if keys, err := searchAndFilter(ds, sealed); err != nil || len(keys) == 0 {
		t.Errorf("sealed %q reaches no product: %v", word, err)
	}
	if pinned := scopeFilters(ds, word, true); pinned != nil {
		t.Errorf("sealed pinned %q is %+v, want no filter", word, pinned)
	}

	// Without the snapshot a number is an id or a name, and the bot embeds
	// the product its id names.
	carriedUUID := ds.backend.ConvertID(mtgmatcher.IDSpaceTCGplayer, carried)
	if config := parseSearchOptionsNG(ds.backend, carried, nil, nil, nil); !slices.Equal(config.UUIDs, []string{carriedUUID}) {
		t.Errorf("%q without the snapshot reaches %v, want the TCGplayer id's %s", carried, config.UUIDs, carriedUUID)
	}
	if config := parseSearchOptionsNG(ds.backend, "17a", nil, nil, nil); config.CleanQuery != "17a" || len(config.CardFilters) != 0 {
		t.Errorf("17a without the snapshot is %q %+v, want a name", config.CleanQuery, config.CardFilters)
	}
	if res, msg := parseMessage(ds, carried, false); res == nil || res.Invalid || res.CardID != carriedUUID {
		t.Errorf("the bot reads %q as %+v %q, want its product %s", carried, res, msg, carriedUUID)
	}
}
