package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// twoCards returns a pair of plain singles to build a list out of, so the
// tests name no uuid of their own.
func twoCards(t *testing.T) []string {
	t.Helper()
	uuids := backend().GetUUIDs()
	if len(uuids) < 2 {
		t.Skip("no datastore loaded")
	}
	return []string{uuids[0], uuids[1]}
}

// The switch offers the side the results are not on, and says so in the label:
// a button reading "Buylist" on a buylist page is the mode you are already in.
func TestModeSwitchOffersTheOtherSide(t *testing.T) {
	for _, tc := range []struct {
		buylist bool
		offers  string
		hides   string
	}{
		{false, "Switch to Buylist", "Switch to Retail"},
		{true, "Switch to Retail", "Switch to Buylist"},
	} {
		out := renderUpload(t, PageVars{
			UploadEntries: []UploadEntry{{CardID: "card-1"}},
			IsBuylist:     tc.buylist,
			CanBuylist:    true,
		})
		if !strings.Contains(out, tc.offers) {
			t.Errorf("buylist=%v: the results do not offer %q", tc.buylist, tc.offers)
		}
		if strings.Contains(out, tc.hides) {
			t.Errorf("buylist=%v: the results offer %q, which is the mode they are in", tc.buylist, tc.hides)
		}
		if !strings.Contains(out, `onclick="switchUploadMode()"`) {
			t.Errorf("buylist=%v: the switch has no action behind it", tc.buylist)
		}
		// The field the action flips, and the value the page came back as.
		want := fmt.Sprintf(`id="res_mode" name="mode" value="%v"`, tc.buylist)
		if !strings.Contains(out, want) {
			t.Errorf("buylist=%v: the form does not carry %s", tc.buylist, want)
		}
	}
}

// Flipping sides costs no upload because it costs no page weight either: the
// rows are read off the results when the switch is taken, the way the exports
// read them, so the page ships no second copy of the list to carry them.
func TestModeSwitchShipsNoSecondCopyOfTheList(t *testing.T) {
	cards := twoCards(t)

	var entries []UploadEntry
	for _, card := range cards {
		entries = append(entries, UploadEntry{CardID: card, Quantity: 1, HasQuantity: true})
	}
	out := renderUpload(t, PageVars{UploadEntries: entries, CanBuylist: true})

	for _, card := range cards {
		if strings.Count(out, card) > 1 {
			t.Errorf("%s appears %d times: once is the row itself, more is a copy to post back",
				card, strings.Count(out, card))
		}
	}
}

// Without the grant there is no switch to take, so its place says what taking
// it would show rather than going quiet about it.
func TestModeSwitchUpsellsWithoutTheGrant(t *testing.T) {
	out := renderUpload(t, PageVars{
		UploadEntries: []UploadEntry{{CardID: "card-1"}},
		CanBuylist:    false,
	})

	if strings.Contains(out, `onclick="switchUploadMode()"`) {
		t.Error("the results offer a switch to a mode the reader cannot have")
	}
	if !strings.Contains(out, "res-mode-upsell") {
		t.Fatal("the switch is gone and nothing stands in its place")
	}
	if !strings.Contains(out, "Legacy tier") {
		t.Error("the upsell does not say what buylist mode takes")
	}
	if !strings.Contains(out, "patreon.com/MTGBAN") {
		t.Error("the upsell does not say where to get it")
	}
}

// End to end: the rows the page posts back come out priced on the other side,
// with no file, no paste and no link involved - the list never left.
func TestModeSwitchPricesTheSameRowsTheOtherWay(t *testing.T) {
	cards := twoCards(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	var packed strings.Builder
	for _, card := range cards {
		fmt.Fprintf(&packed, "%s\t1\t\t0\t\n", card)
	}

	form := url.Values{}
	form.Set("mode", "true")
	form.Set("rows", packed.String())

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Upload(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, "Buylist mode") {
		t.Error("the list came back on the side it was already on")
	}
	if !strings.Contains(out, "Switch to Retail") {
		t.Error("the page back does not offer the way back")
	}
	for _, card := range cards {
		if !strings.Contains(out, card) {
			t.Errorf("%s did not survive the switch", card)
		}
	}
}

// A buylist run told to ignore conditions still posts each row back with the
// condition it came with: retail prices them, and copies of one card that
// differ only by condition must not come back merged into one row.
func TestModeSwitchKeepsIgnoredConditions(t *testing.T) {
	cards := twoCards(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	form := url.Values{}
	form.Set("mode", "true")
	form.Set("nocond", "on")
	form.Set("rows", cards[0]+"\t1\tNM\t2\t\n"+cards[0]+"\t2\tMP\t1\t\n")

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Upload(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, "Buylist mode") {
		t.Fatal("the request did not come back as a page of buylist results")
	}
	for _, cond := range []string{"NM", "MP"} {
		if !strings.Contains(out, `data-cond="`+cond+`"`) {
			t.Errorf("the %s row lost its condition, so the switch would post it back blank", cond)
		}
	}
}

// A list that was opened stays opened across the switch. The rows the page
// posts back are the cards, each naming the box it came out of, so the other
// side is priced against the same sections rather than a flat list - and
// nothing is opened a second time.
func TestModeSwitchKeepsAnOpenedListOpen(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	sealed, _ := sealedProducts(t)
	if sealed == "" {
		t.Skip("this datastore has no sealed product with a decklist")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	var packed strings.Builder
	for _, entry := range unpackSealed([]UploadEntry{{CardID: sealed, Quantity: 1, HasQuantity: true}}) {
		if entry.Unpacked {
			continue
		}
		fmt.Fprintf(&packed, "%s\t%d\t\t0\t%s\t%s\t%d\n", entry.CardID, entry.Quantity,
			entry.Notes, entry.UnpackedFrom, entry.UnpackedQuantity)
	}

	form := url.Values{}
	form.Set("mode", "true")
	form.Set("rows", packed.String())

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Upload(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, "Buylist mode") {
		t.Error("the opened list came back on the side it was already on")
	}
	if !strings.Contains(out, "ures-block-unpacked") {
		t.Error("the switch flattened the sections the unpack built")
	}
	if !strings.Contains(out, mustCard(t, sealed).Name) {
		t.Error("the rebuilt section is not headed by the product")
	}
}

// The button is a shortcut through the page, not around the grant: the same
// request from a reader without it is priced retail, as every other route to
// buylist mode is.
func TestModeSwitchCannotBuyTheGrant(t *testing.T) {
	cards := twoCards(t)
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	// Signature checks on with no signature to read: the grants are all off,
	// which is what a reader without them looks like to the handler.
	DevMode, SigCheck = true, true
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Upload")
	}

	form := url.Values{}
	form.Set("mode", "true")
	form.Set("rows", cards[0]+"\t1\t\t0\t\n")

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Upload(rec, req)

	out := rec.Body.String()
	if strings.Contains(out, "Buylist mode") {
		t.Error("a forged mode field priced the list against buylists")
	}
	if !strings.Contains(out, "Retail mode") {
		t.Fatal("the request did not come back as a page of results at all")
	}
	if !strings.Contains(out, "res-mode-upsell") {
		t.Error("the page offers no way to get what it just refused")
	}
}

// An icon fetched from a cdn cannot be on the page in the first frame: the
// button paints bare and then widens around the icon when the library lands.
// The ones this page draws as it loads are in the markup it serves, so there
// is nothing to wait for and nothing to shift.
func TestResultIconsDoNotWaitOnALibrary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pageVars   PageVars
		drawn      []string
		notWaiting []string
	}{
		{
			name: "the switch, and the actions beside it",
			pageVars: PageVars{
				UploadEntries: []UploadEntry{{CardID: "card-1"}},
				CanBuylist:    true,
				RemoteLinkURL: "https://docs.google.com/spreadsheets/d/abc",
				UnpackSealed:  1,
			},
			drawn:      []string{"arrow-left-right", "share-2", "package-open"},
			notWaiting: []string{"arrow-left-right", "share-2", "package-open"},
		},
		{
			name: "the upsell that stands in the switch's place",
			pageVars: PageVars{
				UploadEntries: []UploadEntry{{CardID: "card-1"}},
				CanBuylist:    false,
			},
			drawn:      []string{"lock"},
			notWaiting: []string{"lock"},
		},
	} {
		out := renderUpload(t, tc.pageVars)
		for _, icon := range tc.drawn {
			if !strings.Contains(out, `<svg class="lucide lucide-`+icon+`"`) {
				t.Errorf("%s: %s is not drawn into the page", tc.name, icon)
			}
		}
		for _, icon := range tc.notWaiting {
			if strings.Contains(out, `data-lucide="`+icon+`"`) {
				t.Errorf("%s: %s is left for the library to fill in", tc.name, icon)
			}
		}
	}
}
