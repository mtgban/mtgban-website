package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/docparse"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// sealedProducts finds one product the datastore can open and one it cannot,
// so the tests name neither by uuid: a pinned product would make them fail for
// having been reprinted rather than for being wrong.
func sealedProducts(t *testing.T) (withDeck, withoutDeck string) {
	t.Helper()
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if mtgmatcher.SealedHasDecklist(code, product.UUID) {
				if withDeck == "" {
					withDeck = product.UUID
				}
			} else if withoutDeck == "" {
				withoutDeck = product.UUID
			}
			if withDeck != "" && withoutDeck != "" {
				return withDeck, withoutDeck
			}
		}
	}
	return withDeck, withoutDeck
}

func quantityOf(entries []UploadEntry, cardID string) int {
	for _, entry := range entries {
		if entry.CardID == cardID {
			return entry.Quantity
		}
	}
	return 0
}

// The quantity travels into the contents: two of a precon is two of every card
// in it.
func TestUnpackSealedCarriesTheQuantityInside(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}

	out := unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 3, HasQuantity: true}})
	for _, entry := range out {
		if entry.Unpacked {
			continue
		}
		if entry.Quantity != 3 {
			t.Fatalf("%s came out at %d, want 3", entry.CardID, entry.Quantity)
		}
	}
}

// The view holds what came out of the boxes and nothing else: the products
// that opened, marked as opened, and their contents. A loose card, a product
// with nothing to open, and a row that never matched are all left out - they
// say nothing about what is inside a box, and keeping them is what would make
// a card held both loose and inside one read as two.
func TestUnpackSealedHoldsOnlyWhatCameOutOfTheBoxes(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, booster := sealedProducts(t)
	if sealed == "" || booster == "" {
		t.Skip("this datastore lacks one of the two product kinds")
	}
	loose := mtgmatcher.GetUUIDs()[0]

	out := unpackSealed([]UploadEntry{
		{CardID: loose, Quantity: 1, HasQuantity: true},
		{CardID: booster, Quantity: 1, HasQuantity: true},
		{CardID: "", Quantity: 1},
		{CardID: sealed, Quantity: 1, HasQuantity: true},
	})

	if len(out) < 2 {
		t.Fatalf("got %d rows, want the opened product and its contents", len(out))
	}
	for _, entry := range out {
		switch entry.CardID {
		case loose:
			t.Error("a loose card is in a view that is meant to hold box contents")
		case booster:
			t.Error("a product that could not be opened is in the view")
		case "":
			t.Error("an unmatched row is in the view")
		}
	}

	// What is left is the product, marked as opened, and what it held.
	if out[0].CardID != sealed || !out[0].Unpacked {
		t.Errorf("the view starts with %q (unpacked=%v), want the opened product",
			out[0].CardID, out[0].Unpacked)
	}
	for _, entry := range out[1:] {
		if entry.Unpacked {
			t.Errorf("%s is marked as opened, but it is one of the contents", entry.CardID)
			break
		}
	}
}

// The opened product keeps its row, ahead of what it became, and is marked so
// nothing counts it: it is not one of the cards, it is where they came from.
func TestUnpackSealedKeepsTheProductAsAGhost(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}

	out := unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}})
	if len(out) < 2 {
		t.Fatalf("got %d rows, want the product and its contents", len(out))
	}
	if out[0].CardID != sealed || !out[0].Unpacked {
		t.Errorf("the list starts with %q (unpacked=%v), want the opened product",
			out[0].CardID, out[0].Unpacked)
	}
	for _, entry := range out[1:] {
		if entry.Unpacked {
			t.Errorf("%s is marked as opened, but it is one of the contents", entry.CardID)
			break
		}
	}
}

// Adding up is the merge's job, and the handler runs it next - so two of a
// product is two of every card in it, and a card the decklist holds twice is
// held twice again.
func TestUnpackSealedAddsUpThroughTheMerge(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	co, err := mtgmatcher.GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	picks, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil || len(picks) == 0 {
		t.Skipf("the chosen product does not open: %v", err)
	}

	merged := docparse.MergeIdenticalEntries(unpackSealed([]UploadEntry{
		{CardID: sealed, Quantity: 2, HasQuantity: true},
	}))

	// Two of the product is two of everything in it, however the decklist
	// spreads them across rows.
	var total int
	var ghosts int
	for _, entry := range merged {
		if entry.Unpacked {
			ghosts++
			continue
		}
		total += entry.Quantity
	}
	if want := 2 * len(picks); total != want {
		t.Errorf("the contents add up to %d, want %d", total, want)
	}
	if ghosts != 1 {
		t.Errorf("the opened product appears %d times after the merge, want 1", ghosts)
	}
}

// The count is what decides whether the offer is made, and it counts only what
// can actually be opened.
func TestUnpackableSealedCountsOnlyDecklists(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, booster := sealedProducts(t)
	if sealed == "" || booster == "" {
		t.Skip("this datastore lacks one of the two product kinds")
	}
	loose := mtgmatcher.GetUUIDs()[0]

	got := unpackableSealed([]UploadEntry{
		{CardID: loose}, {CardID: booster}, {CardID: sealed}, {CardID: ""},
	})
	if got != 1 {
		t.Errorf("counted %d openable rows, want 1", got)
	}
}

// renderUpload runs the upload page the way the server does, so the action is
// exercised rather than only parsed.
func renderUpload(t *testing.T, pageVars PageVars) string {
	t.Helper()
	baseName, files := renderTemplateFiles("upload.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing upload.html: %v", err)
	}
	pageVars.BetaNav = &NavElem{}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, baseName, pageVars); err != nil {
		t.Fatalf("rendering upload.html: %v", err)
	}
	return b.String()
}

// The offer carries no list with it: the rows are read off the page when it is
// taken, so a reader who never asks pays nothing for it.
func TestUnpackActionShipsNoList(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	entries := []UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}}

	out := renderUpload(t, PageVars{
		UploadEntries: entries,
		UnpackSealed:  unpackableSealed(entries),
	})

	if !strings.Contains(out, `onclick="runUnpack()"`) {
		t.Fatal("the unpack action is missing from a result holding a sealed product")
	}
	if !strings.Contains(out, `id="res_unpack"`) {
		t.Error("the form has no field to carry the request")
	}

	// Whatever the deck holds, none of it is in the page.
	picks, err := mtgmatcher.GetDecklist(mustCard(t, sealed).SetCode, sealed)
	if err == nil && len(picks) > 0 {
		if strings.Contains(out, `value="`+picks[0]+`"`) {
			t.Error("the page carries the unpacked contents, which is what asking on demand avoids")
		}
	}
}

func mustCard(t *testing.T, uuid string) *mtgmatcher.CardObject {
	t.Helper()
	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		t.Fatal(err)
	}
	return co
}

// Nothing to open, nothing to offer.
func TestUnpackActionAbsentWithoutSealed(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	entries := []UploadEntry{{CardID: mtgmatcher.GetUUIDs()[0], Quantity: 1, HasQuantity: true}}
	out := renderUpload(t, PageVars{
		UploadEntries: entries,
		UnpackSealed:  unpackableSealed(entries),
	})
	if strings.Contains(out, `onclick="runUnpack()"`) {
		t.Error("an upload with no sealed rows still offered to unpack them")
	}
}

// Taking the offer retires it: the product left behind is marked as opened, so
// nothing counts it as something still to open.
func TestUnpackOfferRetiresItself(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	entries := []UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}}

	if unpackableSealed(entries) != 1 {
		t.Fatal("the offer is not made for a product that can be opened")
	}
	unpacked := unpackSealed(entries)
	if got := unpackableSealed(unpacked); got != 0 {
		t.Errorf("the offer is still made %d times after being taken", got)
	}

	// And a second pass hands the list back rather than a second helping of
	// contents: the product is marked, and the cards it became are not
	// products.
	again := unpackSealed(unpacked)
	if len(again) != len(unpacked) {
		t.Errorf("unpacking twice turned %d rows into %d", len(unpacked), len(again))
	}
}

// The setting asks for this on every upload, so a list holding nothing that
// can be opened has to come back as it went in.
func TestUnpackSealedLeavesAListWithNothingToOpen(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	_, booster := sealedProducts(t)
	entries := []UploadEntry{
		{CardID: mtgmatcher.GetUUIDs()[0], Quantity: 1, HasQuantity: true},
		{CardID: booster, Quantity: 1, HasQuantity: true},
	}

	out := unpackSealed(entries)
	if len(out) != len(entries) {
		t.Fatalf("a list with nothing to open came back with %d of its %d rows", len(out), len(entries))
	}
	for i := range out {
		if out[i].CardID != entries[i].CardID {
			t.Errorf("row %d changed from %q to %q", i, entries[i].CardID, out[i].CardID)
		}
	}
}

// The setting is where the choice lives now, and it has to reach the upload:
// the toggle writes the cookie, and the form reads it back as the field the
// handler looks for.
func TestUnpackIsOfferedInTheSettings(t *testing.T) {
	out := renderUpload(t, PageVars{})

	if !strings.Contains(out, `data-misc="unpack"`) {
		t.Fatal("the settings offer no way to unpack a list on upload")
	}
	if !strings.Contains(out, `opts.indexOf('unpack') >= 0`) {
		t.Error("the setting is never read back into the upload form")
	}
	if !strings.Contains(out, `add('unpack', 'true')`) {
		t.Error("the setting never reaches the handler as a field")
	}
	// The results page has its own field, set by the action; the setting must
	// not speak over a click that already said what it wanted.
	if !strings.Contains(out, `!form.querySelector('[name="unpack"]')`) {
		t.Error("the setting overrides the field the results page carries")
	}
}

// Every card that came out of a product says which one, so the export can
// too - the CSV already has a Notes column, and this is what fills it.
func TestUnpackSealedNamesTheProductEachCardCameFrom(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	product, err := mtgmatcher.GetUUID(sealed)
	if err != nil {
		t.Fatal(err)
	}

	out := unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}})
	for _, entry := range out {
		if entry.Unpacked {
			continue
		}
		if entry.Notes != product.Name {
			t.Fatalf("%s says it came from %q, want %q", entry.CardID, entry.Notes, product.Name)
		}
	}
}

// The provenance survives a re-submission, which is the round trip every
// export takes: the rows go back as hashes, and anything not carried with them
// is lost.
func TestLoadHashesCarriesTheNotes(t *testing.T) {
	entries, err := loadHashes(
		[]string{"card-1", "card-2"},
		[]string{"2", "1"},
		nil, nil,
		[]string{"A Precon", "A Precon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.Notes != "A Precon" {
			t.Errorf("%s lost its note: %q", entry.CardID, entry.Notes)
		}
	}
}

// A row with no note is unaffected, and a short notes list does not read past
// its end.
func TestLoadHashesToleratesMissingNotes(t *testing.T) {
	entries, err := loadHashes([]string{"card-1", "card-2"}, nil, nil, nil, []string{"only one"})
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Notes != "only one" || entries[1].Notes != "" {
		t.Errorf("got %q and %q, want the note applied to the first row only",
			entries[0].Notes, entries[1].Notes)
	}
}

// The sections are the unpacked view: one per opened product, holding the
// cards that came out of that one and nothing else.
func TestUnpackedSectionsGatherEachProduct(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	entries := unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}})

	sections := buildUnpackedSections(entries, map[string]*unpackedTally{})
	if len(sections) != 1 {
		t.Fatalf("got %d sections, want one per opened product", len(sections))
	}
	if sections[0].Product.CardID != sealed {
		t.Errorf("the section is headed by %q, want the product %q",
			sections[0].Product.CardID, sealed)
	}
	if len(sections[0].Entries) != len(entries)-1 {
		t.Errorf("the section holds %d of the %d cards that came out",
			len(sections[0].Entries), len(entries)-1)
	}
	for _, entry := range sections[0].Entries {
		if entry.Unpacked {
			t.Error("the product is in its own section as one of the cards")
		}
		if entry.UnpackedFrom != sealed {
			t.Errorf("%s is filed under %q, want %q", entry.CardID, entry.UnpackedFrom, sealed)
		}
	}
}

// Sorting reorders the whole list and the categories split it in two, so the
// only thing holding a card to its box is the uuid it carries.
func TestUnpackedSectionsSurviveAReorder(t *testing.T) {
	first := UploadEntry{CardID: "boxA", Unpacked: true}
	second := UploadEntry{CardID: "boxB", Unpacked: true}
	scrambled := []UploadEntry{
		{CardID: "card2", UnpackedFrom: "boxB"},
		first,
		{CardID: "card1", UnpackedFrom: "boxA"},
		second,
		{CardID: "card3", UnpackedFrom: "boxA"},
	}

	sections := buildUnpackedSections(scrambled, map[string]*unpackedTally{})
	if len(sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(sections))
	}
	// Ordered by the first mention, which is the sorted order the reader asked
	// for rather than the order the products were uploaded in.
	if sections[0].Product.CardID != "boxB" || sections[1].Product.CardID != "boxA" {
		t.Errorf("sections came out as %q then %q", sections[0].Product.CardID, sections[1].Product.CardID)
	}
	if len(sections[1].Entries) != 2 {
		t.Errorf("boxA kept %d of its 2 cards", len(sections[1].Entries))
	}
}

// A card in two precons is held once by each, so the merge has to stop
// collapsing across products - otherwise one of the two sections loses it.
func TestUnpackedSectionsKeepACardHeldByTwoProducts(t *testing.T) {
	merged := docparse.MergeIdenticalEntries([]UploadEntry{
		{CardID: "boxA", Unpacked: true},
		{CardID: "staple", UnpackedFrom: "boxA", Quantity: 1, HasQuantity: true},
		{CardID: "boxB", Unpacked: true},
		{CardID: "staple", UnpackedFrom: "boxB", Quantity: 1, HasQuantity: true},
	})

	sections := buildUnpackedSections(merged, map[string]*unpackedTally{})
	if len(sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(sections))
	}
	for _, section := range sections {
		if len(section.Entries) != 1 {
			t.Fatalf("%s holds %d cards, want the one staple",
				section.Product.CardID, len(section.Entries))
		}
		if got := section.Entries[0].Quantity; got != 1 {
			t.Errorf("%s holds %d of the staple, want 1", section.Product.CardID, got)
		}
	}

	// The same card twice over is still merged when it came out of the same
	// box, which is the behaviour every other upload relies on.
	same := docparse.MergeIdenticalEntries([]UploadEntry{
		{CardID: "staple", UnpackedFrom: "boxA", Quantity: 1, HasQuantity: true},
		{CardID: "staple", UnpackedFrom: "boxA", Quantity: 1, HasQuantity: true},
	})
	if len(same) != 1 || same[0].Quantity != 2 {
		t.Errorf("two of a card from one box came out as %d rows", len(same))
	}
}

// The page reads a box at a time: a section headed by the product, footed by
// what its own contents come to, and never by the page's totals.
func TestUnpackedResultsRenderASectionPerProduct(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	product := mustCard(t, sealed)
	entries := unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}})

	pageVars := PageVars{
		UploadEntries: entries,
		UnpackedFrom:  1,
		Metadata:      map[string]GenericCard{},
		TotalEntries:  map[string]float64{"TCGLow": 999},
		ResultPrices:  map[string]map[string]float64{},
		MissingCounts: map[string]int{},
		MissingPrices: map[string]float64{},
		IndexKeys:     []string{"TCGLow"},
	}
	for _, entry := range entries {
		pageVars.Metadata[entry.CardID] = uuid2card(entry.CardID, true, false, false)
	}
	pageVars.SealedIndexKeys = []string{"TCGLowEV"}
	pageVars.UnpackedSections = []UnpackedSection{{
		Product:      entries[0],
		Entries:      entries[1:],
		Quantity:     len(entries) - 1,
		Contents:     63,
		ProductPrice: 40,
		Totals:       map[string]float64{"TCGLow": 63},
		Missing:      map[string]int{},
		ProductIndex: map[string]float64{"TCGLowEV": 52},
	}}

	out := renderUpload(t, pageVars)

	if !strings.Contains(out, "ures-block-unpacked") {
		t.Fatal("the results carry no section for the opened product")
	}
	if !strings.Contains(out, product.Name) {
		t.Error("the section is not headed by the product it opened")
	}
	// The comparison the view exists for, and the section's own totals rather
	// than the page's.
	if !strings.Contains(out, "Sealed") || !strings.Contains(out, "Opened") {
		t.Error("the section does not weigh the box against its contents")
	}
	if !strings.Contains(out, "$ 63.00") || !strings.Contains(out, "$ 40.00") {
		t.Error("the section shows neither what the box cost nor what came out")
	}
	if strings.Contains(out, "$ 999.00") {
		t.Error("the section is footed with the page's totals instead of its own")
	}
	// The box's own expected value, which is the other half of the reading:
	// what it is reckoned to hold, beside what this one actually did.
	if !strings.Contains(out, "$ 52.00") {
		t.Error("the section does not carry the product's expected value")
	}
	// The product heads its section, so it is not also a row inside one.
	if strings.Contains(out, `<tr data-hash="`+sealed+`"`) {
		t.Error("the opened product is still rendered as a row of its own contents")
	}
}

// Get CSV splits an All view into two files, one per category. An unpacked
// list has no such seam - the split would be two requests for the same rows,
// the second cancelling the first mid-download, which is how the export came
// back as the uploader page instead of a file.
func TestUnpackedResultsExportAsOneFile(t *testing.T) {
	view, tabs, all := resultView(2, true, true, false)
	if view != "singles" {
		t.Errorf("an unpacked list opens on %q, want the one view it has", view)
	}
	if all {
		t.Error("an unpacked list offers an All tab, which splits the export in two")
	}
	if tabs {
		t.Error("an unpacked list offers a bar to switch between sections it does not have")
	}

	// Every other list decides as it always did.
	for _, tt := range []struct {
		name                      string
		singles, sealed, notFound bool
		wantView                  string
		wantTabs, wantAll         bool
	}{
		{"both", true, true, false, "all", true, true},
		{"singles and strays", true, false, true, "singles", true, false},
		{"sealed only", false, true, false, "sealed", false, false},
		{"nothing matched", false, false, true, "notfound", false, false},
	} {
		view, tabs, all := resultView(0, tt.singles, tt.sealed, tt.notFound)
		if view != tt.wantView || tabs != tt.wantTabs || all != tt.wantAll {
			t.Errorf("%s: got (%q, tabs=%v, all=%v), want (%q, tabs=%v, all=%v)",
				tt.name, view, tabs, all, tt.wantView, tt.wantTabs, tt.wantAll)
		}
	}
}
