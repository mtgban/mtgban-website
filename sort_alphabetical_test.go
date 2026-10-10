package main

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestAlphabeticalSortUsesEnglishNames is the SOA case from the site: a
// search for the Japanese Mystical Archive scrolls sorted alphabetically
// has to read A-to-Z off the English names, not off whatever order the
// kanji of the printed names happen to fall in.
func TestAlphabeticalSortUsesEnglishNames(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

	var keys []string
	for _, uuid := range uuids {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.SetCode != "SOA" || co.Language != "Japanese" {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) == 0 {
		t.Skip("no Japanese SOA printings in the datastore")
	}

	sortData := resolveSortingData(backend(), keys)
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabetical(sortData[keys[i]], sortData[keys[j]])
	})

	prev := ""
	for _, uuid := range keys {
		co := sortData[uuid].co
		if co.FlavorName == "" {
			t.Errorf("%s has no localized name, so this set no longer covers the case", co.Name)
		}
		if prev != "" && sortData[uuid].nameLower < prev {
			t.Errorf("%q sorts after %q: the order is not following the English names", co.Name, prev)
		}
		prev = sortData[uuid].nameLower
	}
}

// TestAlphabeticalSortGroupsLocalizedReprints checks the other half of
// keying on the English name: a localized printing lands next to the
// English one it reprints, instead of filing itself under its own name.
func TestAlphabeticalSortGroupsLocalizedReprints(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

	var keys []string
	for _, uuid := range uuids {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Name != "Akroma's Will" {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) < 2 {
		t.Skip("not enough printings of the test card")
	}

	sortData := resolveSortingData(backend(), keys)
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabetical(sortData[keys[i]], sortData[keys[j]])
	})

	var localized int
	for _, uuid := range keys {
		co := sortData[uuid].co
		if co.Name != "Akroma's Will" {
			t.Fatalf("unrelated card %q in the group", co.Name)
		}
		if allLanguageFlags[co.Language] != "" {
			localized++
		}
	}
	if localized == 0 {
		t.Skip("no foreign printing of the test card to group")
	}
}

func wrathOfGodKeys(t *testing.T) []string {
	t.Helper()
	skipWithoutDatastore(t)
	var keys []string
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Name != "Wrath of God" || co.Sealed {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) < 2 {
		t.Skip("not enough printings of the test card")
	}
	return keys
}

// TestHybridSortFilesReprintsUnderParent checks that Alternate Fourth
// Edition and Foreign Black Border sort right after the set they reprint,
// not under A and F.
func TestHybridSortFilesReprintsUnderParent(t *testing.T) {
	keys := wrathOfGodKeys(t)
	sortData := resolveSortingData(backend(), keys)
	fileReprintsUnderParent(sortData, getReprintParents(backend()))
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabeticalSet(sortData[keys[i]], sortData[keys[j]])
	})

	var sets []string
	for _, uuid := range keys {
		code := sortData[uuid].co.SetCode
		if len(sets) == 0 || sets[len(sets)-1] != code {
			sets = append(sets, code)
		}
	}
	for want, after := range map[string]string{"4EDALT": "4ED", "4BB": "4EDALT", "FBB": "3ED"} {
		i := slices.Index(sets, want)
		if i < 1 || sets[i-1] != after {
			t.Errorf("%s does not follow %s: %v", want, after, sets)
		}
	}
}

// TestAlphabeticalSortBreaksSameDateTies checks that printings sharing a
// name, date and number (4ED, 4EDALT, 4BB) sort the same way every time.
func TestAlphabeticalSortBreaksSameDateTies(t *testing.T) {
	keys := wrathOfGodKeys(t)
	sortData := resolveSortingData(backend(), keys)
	less := func(k []string) func(i, j int) bool {
		return func(i, j int) bool {
			return cmpSetsAlphabetical(sortData[k[i]], sortData[k[j]])
		}
	}
	sort.Slice(keys, less(keys))
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := slices.Clone(keys)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		sort.Slice(shuffled, less(shuffled))
		if !slices.Equal(keys, shuffled) {
			t.Fatal("order depends on the input order")
		}
	}
}

// TestNumberOrderIsOneOrder sorts Secret Lair's printings, whose numbers mix
// plain digits with marked ones (1553, 1553★, 800), into one order whatever
// order they arrive in, stripped or not: a comparison that reads some
// numbers by value and others as strings loops, and the sort then depends
// on its input.
func TestNumberOrderIsOneOrder(t *testing.T) {
	skipWithoutDatastore(t)
	set, err := backend().GetSet("SLD")
	if err != nil {
		t.Skip("no Secret Lair in this datastore")
	}
	var keys []string
	for _, card := range set.Cards {
		keys = append(keys, card.UUID)
	}
	sortData := resolveSortingData(backend(), keys)

	rng := rand.New(rand.NewPCG(3, 4))
	for _, strip := range []bool{false, true} {
		var first []string
		for range 10 {
			rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
			sorted := slices.Clone(keys)
			sort.SliceStable(sorted, func(i, j int) bool {
				return cmpNumberAndFinish(sortData[sorted[i]], sortData[sorted[j]], strip)
			})
			if first == nil {
				first = sorted
				continue
			}
			if !slices.Equal(first, sorted) {
				t.Fatalf("strip %v: the order depends on the input", strip)
			}
		}
	}

	for _, tc := range []struct{ a, b string }{
		{"800", "1553"}, {"1553", "1553★"}, {"800", "1553★"}, {"12", "A-5"}, {"9", "12a"},
	} {
		if cmpNaturally(tc.a, tc.b) >= 0 || cmpNaturally(tc.b, tc.a) <= 0 {
			t.Errorf("%s should come before %s", tc.a, tc.b)
		}
	}
}

// TestCmpNumberAndFinishReadsEachShape pins both readings on the shapes a set
// may or may not hold: stripped, the digits' value first, a number without
// digits last and an equal value read on as written; unstripped, the number
// as a reader goes through it.
func TestCmpNumberAndFinishReadsEachShape(t *testing.T) {
	numbered := func(number string) *SortingData {
		return &SortingData{co: &mtgmatcher.CardObject{Card: mtgmatcher.Card{Number: number}}}
	}
	for _, tc := range []struct {
		first, second string
		strip         bool
	}{
		{"800", "1553", true},
		{"1553", "1553★", true},
		{"12a", "12b", true},
		{"A-5", "12", true},
		{"999", "S", true},
		{"800", "1553", false},
		{"1553", "1553★", false},
		{"12", "A-5", false},
		{"9", "12a", false},
	} {
		a, b := numbered(tc.first), numbered(tc.second)
		if !cmpNumberAndFinish(a, b, tc.strip) || cmpNumberAndFinish(b, a, tc.strip) {
			t.Errorf("strip %v: %s should come before %s", tc.strip, tc.first, tc.second)
		}
	}
}

// TestSetCodePrefix reads a set code before the last dash only with a
// letter in it and a digit after it.
func TestSetCodePrefix(t *testing.T) {
	for number, want := range map[string]string{
		"OP01-016": "OP01", "10E-105": "10E", "LOB-EN001": "LOB", "T-001": "T", "IFIYW-1": "IFIYW",
		"MP25-EN001": "MP25", "2024-10": "", "2J-b": "", "LGS360-FUN001": "", "1553★": "", "DON": "", "12a": "",
	} {
		if got := setCodePrefix(number); got != want {
			t.Errorf("setCodePrefix(%q) = %q, want %q", number, got, want)
		}
	}
}

// TestPrefixedNumbersSortByPrefixFirst orders numbers with a set code
// prefix by prefix within each release date, after the plain numbers.
func TestPrefixedNumbersSortByPrefixFirst(t *testing.T) {
	skipWithoutDatastore(t)
	for _, code := range []string{"SLD", "PLST"} {
		var keys []string
		seen := map[string]bool{}
		for _, card := range backend().Sets[code].Cards {
			if !seen[card.Number] {
				seen[card.Number] = true
				keys = append(keys, card.UUID)
			}
		}
		sortData := resolveSortingData(backend(), keys)
		sort.Slice(keys, func(i, j int) bool { return cmpSets(sortData[keys[i]], sortData[keys[j]]) })
		for i := 1; i < len(keys); i++ {
			previous, current := sortData[keys[i-1]], sortData[keys[i]]
			if !previous.releaseDate.Equal(current.releaseDate) {
				continue
			}
			if cmpNaturally(previous.numberPrefix, current.numberPrefix) > 0 {
				t.Errorf("%s: %s sorts before %s on one date", code, previous.co.Number, current.co.Number)
			}
		}
	}
}

// Printings sharing a number order one way whatever their promo types:
// three that differ in promos and finish, and two that differ only in a
// finish the flags read alike, form a strict order, never a loop or a tie.
func TestNumberOrderIsTotalWithinANumber(t *testing.T) {
	printing := func(uuid, finish string, foil, etched bool, promos ...string) *SortingData {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: uuid, Number: "1", PromoTypes: promos}, Foil: foil, Etched: etched}
		co.Finish = finish
		return &SortingData{co: co}
	}
	all := []*SortingData{
		printing("x", "foil", true, false),
		printing("y", "etched", false, true, "a"),
		printing("z", "nonfoil", false, false, "b"),
		printing("h", "holofoil", true, false, "a"),
		printing("r", "reverseHolofoil", true, false, "a"),
	}
	for _, strip := range []bool{false, true} {
		less := func(a, b *SortingData) bool { return cmpNumberAndFinish(a, b, strip) }
		for _, a := range all {
			for _, b := range all {
				if a != b && less(a, b) == less(b, a) {
					t.Errorf("strip %v: %s and %s tie or loop", strip, a.co.UUID, b.co.UUID)
				}
				for _, c := range all {
					if less(a, b) && less(b, c) && !less(a, c) {
						t.Errorf("strip %v: %s < %s < %s but not %s < %s", strip, a.co.UUID, b.co.UUID, c.co.UUID, a.co.UUID, c.co.UUID)
					}
				}
			}
		}
	}
}

// A saved default grouped by set is what the Alphabetical button asks for, and
// the page sorts as the URL says: sort=alpha is plain alpha whatever is saved.
func TestAlphabeticalButtonAsksForTheGroupedDefault(t *testing.T) {
	request := func(saved string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/search?q=x&sort=alpha", nil)
		if saved != "" {
			r.AddCookie(&http.Cookie{Name: "SearchDefaultSort", Value: saved})
		}
		return r
	}

	if got := readSearchSort(request("hybrid"), SearchConfig{}); got != "alpha" {
		t.Errorf("sort=alpha with a grouped default sorted %q, want alpha", got)
	}

	for saved, want := range map[string]string{"": "alpha", "hybrid": "hybrid", "retail": "alpha"} {
		var vars SearchVars
		fillSearchPrefs(&vars, request(saved))
		if vars.AlphaSort != want {
			t.Errorf("default %q: the button asks for %q, want %q", saved, vars.AlphaSort, want)
		}
	}

	for _, mobile := range []bool{false, true} {
		pv := PageVars{
			UserNav: &NavElem{Short: "b"},
			SearchVars: SearchVars{
				AllKeys:     []string{"a"},
				SearchRan:   true,
				SearchQuery: "x",
				SearchSort:  "chrono",
				AlphaSort:   "hybrid",
				TotalUnique: 1,
			},
		}
		if !strings.Contains(renderPage(t, "search.html", mobile, pv), "sort=hybrid") {
			t.Errorf("mobile=%v: the Alphabetical button does not link to its AlphaSort", mobile)
		}

		// Plain alpha on screen, as a shared link opens it, only reverses
		pv.SearchSort = "alpha"
		out := renderPage(t, "search.html", mobile, pv)
		if strings.Contains(out, "sort=hybrid") || !strings.Contains(out, "sort=alpha&reverse=true") {
			t.Errorf("mobile=%v: the Alphabetical button on plain alpha does not just reverse it", mobile)
		}
	}
}
