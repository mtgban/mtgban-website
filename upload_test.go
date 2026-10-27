package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/moxfield"
)

// The mtgban inventory/cart CSV export must round-trip through the uploader:
// the Key column resolves directly by uuid, and with no usable id the sealed
// name fallback must handle punctuation loss and parenthesized variants.
// Relies on the datastore loaded in TestMain, which is why it lives here
// rather than in internal/docparse.
func TestUploadSealedCSV(t *testing.T) {
	if len(backend().GetSealedUUIDs()) == 0 {
		t.Skip("mtgmatcher data not loaded; skipping")
	}

	parser := newUploadParser(backend())
	header := []string{"Key", "Name", "Edition", "Finish", "Number", "Rarity", "Conditions", "Price", "Quantity", "URL", "Seller", "Bundle", "Original Id", "Instance Id"}
	indexMap, err := parser.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if idx, found := indexMap["id"]; !found || idx != 0 {
		t.Fatalf("Key column not mapped to id: %v", indexMap)
	}

	rows := [][]string{
		{"9e295ba4-a378-5259-8ba9-5a67ead6d17f", "Champions of Kamigawa Fat Pack", "Champions of Kamigawa", "sealed", "", "product", "NM", "368.58", "4", "url", "", "", "116082", "750831"},
		{"48ff4766-9d88-5426-800a-1613c990011b", "Mystery Booster Booster Box (Convention Edition)", "Mystery Booster", "sealed", "", "product", "NM", "15.36", "150", "url", "", "", "101685", "659571"},
		{"96772e6d-0aba-5362-ab10-d5f3f6d23634", "Urzas Saga Tournament Pack", "Urza's Saga", "sealed", "", "product", "NM", "645.01", "70", "url", "", "", "23679", "159742"},
	}

	// Path 1: resolve via the Key uuid
	for _, row := range rows {
		if _, err := backend().GetUUID(row[0]); err != nil {
			t.Logf("uuid %s not in local datastore, skipping id check", row[0])
			continue
		}
		res, err := parser.ParseRow(indexMap, append([]string{}, row...))
		if err != nil {
			t.Fatalf("ParseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("id path %q: MismatchError = %v", row[1], res.MismatchError)
		}
		if res.CardID == "" {
			t.Errorf("id path %q: empty CardId", row[1])
		}
	}

	// Path 2: blank the Key so the sealed-name fallback has to do the work
	for _, row := range rows {
		nameOnly := append([]string{}, row...)
		nameOnly[0] = ""
		res, err := parser.ParseRow(indexMap, nameOnly)
		if err != nil {
			t.Fatalf("ParseRow(%s): %v", row[1], err)
		}
		if res.MismatchError != nil {
			t.Errorf("name path %q: MismatchError = %v", row[1], res.MismatchError)
			continue
		}
		if res.CardID == "" {
			t.Errorf("name path %q: empty CardId", row[1])
			continue
		}
		co, err := backend().GetUUID(res.CardID)
		if err != nil || !co.Sealed {
			t.Errorf("name path %q: resolved to non-sealed %q", row[1], res.CardID)
		}
		t.Logf("name path %q -> %s (%s)", row[1], res.CardID, co.Name)
	}
}

// Deck per-copy printings arrive as set+number instead of a scryfall id;
// they must resolve to the exact printing with the finish applied, so
// mixed-printing decks don't collapse into one variation.
func TestResolveMoxItemPrinting(t *testing.T) {
	if _, err := backend().GetSet("UNF"); err != nil {
		t.Skip("datastore not loaded")
	}

	check := func(item moxfield.Item, wantNumber string, wantFoil bool) string {
		t.Helper()
		cardID, err := resolveMoxItem(backend(), item)
		if err != nil {
			t.Fatalf("resolve %+v: %s", item, err)
		}
		co, err := backend().GetUUID(cardID)
		if err != nil {
			t.Fatal(err)
		}
		if co.SetCode != "UNF" || co.Number != wantNumber || co.Foil != wantFoil {
			t.Errorf("resolved to %s %s foil=%v, want UNF %s foil=%v",
				co.SetCode, co.Number, co.Foil, wantNumber, wantFoil)
		}
		return cardID
	}

	// The galaxy-foil printing is its own collector number
	check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "487", IsFoil: true}, "487", true)

	// Same number, different finishes stay distinct
	regular := check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "236"}, "236", false)
	foil := check(moxfield.Item{Name: "Island", SetCode: "unf", Number: "236", IsFoil: true}, "236", true)
	if regular == foil {
		t.Error("foil and nonfoil of the same printing should resolve to different uuids")
	}

	// Unknown printings surface a mismatch error instead of a silent match
	if _, err := resolveMoxItem(backend(), moxfield.Item{Name: "Island", SetCode: "unf", Number: "9999"}); err == nil {
		t.Error("unknown collector number should error")
	}
}

// A "hide above" cap stands on its own while the floor filter is off; the
// floor's amount only overrules it once that filter is switched on.
func TestUpperBound(t *testing.T) {
	tests := []struct {
		name    string
		v       float64
		floor   float64
		floorOn bool
		want    float64
	}{
		{"cap equal to an unused floor", 0.5, 0.5, false, 0.5},
		{"cap under an unused floor", 0.5, 1, false, 0.5},
		{"cap above the floor", 0.5, 0.1, true, 0.5},
		{"cap equal to the floor", 0.5, 0.5, true, 0},
		{"cap under the floor", 0.5, 1, true, 0},
		{"no cap", 0, 0.1, false, 0},
		{"negative cap", -1, 0.1, false, 0},
	}
	for _, tt := range tests {
		got := upperBound(tt.v, tt.floor, tt.floorOn)
		if got != tt.want {
			t.Errorf("%s: upperBound(%v, %v, %v) = %v, want %v", tt.name, tt.v, tt.floor, tt.floorOn, got, tt.want)
		}
	}
}

// A Moxfield link's fetch is built from its kind and id, so a sub-page
// fetches its deck, and a path whose id is not one is refused rather than
// cleaned: "..", encoded or not, would walk the GET anywhere on the proxy.
func TestMoxfieldURL(t *testing.T) {
	for _, base := range []string{"https://proxy", "https://proxy/moxfield/"} {
		for link, want := range map[string]string{
			"https://moxfield.com/decks/Kq5j7Q8cJE2XyH3xNfZ1Xg": "/decks/Kq5j7Q8cJE2XyH3xNfZ1Xg",
			"https://www.moxfield.com/decks/abc_-123/":          "/decks/abc_-123",
			"https://moxfield.com/decks/abc123?foo=bar#x":       "/decks/abc123",
			"https://moxfield.com/decks/abc123/primer":          "/decks/abc123",
			"https://moxfield.com/decks/abc123/history/":        "/decks/abc123",
			"https://moxfield.com/binders/Zz9_-a":               "/binders/Zz9_-a",
			"https://moxfield.com/collection/Zz9_-a":            "/collection/Zz9_-a",
		} {
			u, err := url.Parse(link)
			if err != nil {
				t.Fatal(err)
			}
			got, err := moxfieldURL(base, u.Path)
			if err != nil {
				t.Errorf("moxfieldURL(%q, %q): %v", base, link, err)
				continue
			}
			// What the uploader fetched for the bare deck link before ids
			// were checked
			wantURL, _ := url.Parse(base)
			wantURL.Path = path.Join(wantURL.Path, want)
			if got != wantURL.String() {
				t.Errorf("moxfieldURL(%q, %q) = %q, want %q", base, link, got, wantURL)
			}
		}
	}

	for _, link := range []string{
		"https://moxfield.com/decks/../../../../internal/x",
		"https://moxfield.com/decks/..",
		"https://moxfield.com/decks/%2e%2e/%2e%2e/internal",
		"https://moxfield.com/decks/%2E%2E",
		"https://moxfield.com/decks/a%3Fx=1",
		"https://moxfield.com/decks/",
		"https://moxfield.com/decks",
		"https://moxfield.com/internal/abc",
		"https://moxfield.com/",
		"https://moxfield.com//evil.example/decks/abc",
	} {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := moxfieldURL("https://proxy", u.Path); err == nil {
			t.Errorf("moxfieldURL(%q) = %q, want an error", link, got)
		}
	}
}

// The sheet id goes into the Sheets API path unescaped, so it must be an id
// and nothing else: no dot segment, query or fragment.
func TestSpreadsheetID(t *testing.T) {
	for link, want := range map[string]string{
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/edit":       "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/edit#gid=0": "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/":           "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9":            "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/edit/":      "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/view":       "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/htmlview":   "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/d/1AbC_-xyz9/copy":       "1AbC_-xyz9",
		"https://docs.google.com/spreadsheets/u/1/d/1AbC_-xyz9/edit":   "1AbC_-xyz9",
	} {
		u, _ := url.Parse(link)
		got, err := spreadsheetID(u.Path)
		if err != nil || got != want {
			t.Errorf("spreadsheetID(%q) = %q, %v, want %q", link, got, err, want)
		}
	}
	for _, link := range []string{
		"https://docs.google.com/spreadsheets/d/../edit",
		"https://docs.google.com/spreadsheets/d/%2e%2e/edit",
		"https://docs.google.com/spreadsheets/d/x%3Ffields=y/edit",
		"https://docs.google.com/spreadsheets/d/x%23y/edit",
		"https://docs.google.com/",
	} {
		u, _ := url.Parse(link)
		if got, err := spreadsheetID(u.Path); err == nil {
			t.Errorf("spreadsheetID(%q) = %q, want an error", link, got)
		}
	}

	// A "Publish to web" link carries no id the Sheets API takes, and says so
	u, _ := url.Parse("https://docs.google.com/spreadsheets/d/e/2PACX-1vQ_abc/pubhtml")
	if got, err := spreadsheetID(u.Path); err == nil || !strings.Contains(err.Error(), "published") {
		t.Errorf("spreadsheetID(published link) = %q, %v, want an error naming published links", got, err)
	}
}

// An export lifts the row cap only for a reader it runs for: one it refuses
// falls through to the priced page, which keeps the tier's cap.
func TestUploadModesExportsLiftTheCapWhereTheyRun(t *testing.T) {
	for _, field := range []string{"tcgplayer_csv", "deckbox", "download"} {
		r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(field+"=true"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if got := readUploadModes(r, false, true).maxRows; got != MaxUploadEntries {
			t.Errorf("%s without buylist access: maxRows = %d, want %d", field, got, MaxUploadEntries)
		}
		if got := readUploadModes(r, true, true).maxRows; got != MaxUploadTotalEntries {
			t.Errorf("%s with buylist access: maxRows = %d, want %d", field, got, MaxUploadTotalEntries)
		}
	}
}
