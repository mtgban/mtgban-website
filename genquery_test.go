package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The query genQuery builds is what a uuid search is rebuilt into, what the
// recent list shows, and what a favorite links to. It names one printing, so
// it has to find that printing and no other.
func TestTheRebuiltQueryFindsThePrintingItNames(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}

	uuids := mtgmatcher.GetUUIDs()
	var checked, missed int
	for i, uuid := range uuids {
		// A spread sample: the whole datastore would run the search engine
		// 37,000 times for a property every printing shares.
		if i%211 != 0 {
			continue
		}
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		checked++

		found, err := searchAndFilter(parseSearchOptionsWrapper(genQuery(co)))
		if err != nil {
			missed++
			if missed < 5 {
				t.Errorf("%q found nothing: %s", genQuery(co), err)
			}
			continue
		}
		var hit bool
		for _, u := range found {
			if u == uuid {
				hit = true
				break
			}
		}
		if !hit {
			missed++
			if missed < 5 {
				t.Errorf("%q does not find %s (number %q, plain %q)",
					genQuery(co), co.Name, co.Number, co.OriginalNumber)
			}
		}
	}
	if checked == 0 {
		t.Skip("no printings in this datastore")
	}
	if missed != 0 {
		t.Errorf("%d of %d rebuilt queries cannot find their own printing", missed, checked)
	}
	t.Logf("%d printings, every rebuilt query finds its own", checked)
}

// The marks a printing prints are the point of the strict form: a starred or
// language-tagged number is what genQuery puts in the query, and cn: would
// strip it back to the plain number and find the wrong printings.
func TestTheRebuiltQueryKeepsTheMarksTheNumberCarries(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}

	var tagged *mtgmatcher.CardObject
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed || co.Number == co.OriginalNumber {
			continue
		}
		tagged = co
		break
	}
	if tagged == nil {
		t.Skip("this datastore has no printing whose number carries a mark")
	}

	query := genQuery(tagged)
	found, err := searchAndFilter(parseSearchOptionsWrapper(query))
	if err != nil {
		t.Fatalf("%q found nothing: %s", query, err)
	}
	for _, uuid := range found {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if co.Number != tagged.Number {
			t.Errorf("%q also found %s, whose number is %q not %q",
				query, co.Name, co.Number, tagged.Number)
		}
	}
}
