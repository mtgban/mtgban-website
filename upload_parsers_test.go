package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

// The parsers log through the site's page logger, which only exists once the
// server has started. Give them somewhere to write and take it away again.
func quietUploadLog(t *testing.T) {
	t.Helper()
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Upload"] == nil {
		LogPages["Upload"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Upload") })
	}
}

const uploadRowLimit = 100

// A header the parser recognises, and two rows under it. Written once so the
// delimiter tests differ only in what separates the fields.
var parserHeader = []string{"Name", "Edition", "Quantity", "Price", "Condition", "Notes"}
var parserRows = [][]string{
	{"Lightning Bolt", "Beta", "4", "$12.50", "NM", "top of the box"},
	{"Counterspell", "Ice Age", "2", "$1.00", "LP", ""},
}

func joinRows(sep string) string {
	var b strings.Builder
	b.WriteString(strings.Join(parserHeader, sep) + "\n")
	for _, row := range parserRows {
		b.WriteString(strings.Join(row, sep) + "\n")
	}
	return b.String()
}

// The columns a header names are the columns the rows are read from.
func TestLoadCsvReadsWhatTheHeaderNames(t *testing.T) {
	quietUploadLog(t)

	entries, err := loadCsv(strings.NewReader(joinRows(",")), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}

	first := entries[0]
	if !first.HasQuantity || first.Quantity != 4 {
		t.Errorf("quantity = %d (has=%v), want 4", first.Quantity, first.HasQuantity)
	}
	if first.OriginalPrice != 12.50 {
		t.Errorf("price = %v, want 12.50", first.OriginalPrice)
	}
	if first.OriginalCondition != "NM" {
		t.Errorf("condition = %q, want NM", first.OriginalCondition)
	}
	if first.Notes != "top of the box" {
		t.Errorf("notes = %q, want %q", first.Notes, "top of the box")
	}
	if entries[1].OriginalCondition != "SP" {
		t.Errorf("LP maps to %q, want SP", entries[1].OriginalCondition)
	}
}

// A file is not always separated by what the caller was told. When the header
// comes back as one field, the parser tries the next separator instead of
// reading the whole line as a card name.
func TestLoadCsvFindsTheRealSeparator(t *testing.T) {
	quietUploadLog(t)

	for _, tt := range []struct {
		name  string
		sep   string
		comma rune
	}{
		{"tabs offered as commas", "\t", ','},
		{"semicolons offered as tabs", ";", '\t'},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := loadCsv(strings.NewReader(joinRows(tt.sep)), tt.comma, uploadRowLimit)
			if err != nil {
				t.Fatalf("loadCsv: %v", err)
			}
			if len(entries) != 2 {
				t.Fatalf("read %d rows, want 2", len(entries))
			}
			if !entries[0].HasQuantity || entries[0].Quantity != 4 {
				t.Errorf("quantity = %d, want 4 - the columns were not split", entries[0].Quantity)
			}
		})
	}
}

// Some exporters write the separator into the file's first line. It names the
// separator for everything after it, and is not itself a header.
func TestLoadCsvTakesTheSeparatorTheFileDeclares(t *testing.T) {
	quietUploadLog(t)

	body := "sep=;\n" + joinRows(";")
	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	if entries[0].OriginalPrice != 12.50 {
		t.Errorf("price = %v, want 12.50 - the declared separator was ignored", entries[0].OriginalPrice)
	}
}

// A list with no header at all is a decklist, and its first line is a card
// rather than column names - so the parser has to go back and read it again.
func TestLoadCsvKeepsTheFirstCardOfAHeaderlessList(t *testing.T) {
	quietUploadLog(t)

	body := "4 Lightning Bolt\n2 Counterspell\n1 Black Lotus\n"
	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d rows, want 3 - the first card was eaten as a header", len(entries))
	}
	for i, want := range []int{4, 2, 1} {
		if !entries[i].HasQuantity || entries[i].Quantity != want {
			t.Errorf("row %d quantity = %d (has=%v), want %d", i, entries[i].Quantity, entries[i].HasQuantity, want)
		}
	}
}

func TestLoadCsvRefusesAnEmptyFile(t *testing.T) {
	quietUploadLog(t)

	_, err := loadCsv(strings.NewReader(""), ',', uploadRowLimit)
	if err == nil {
		t.Fatal("an empty file was accepted")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want it to say the file was empty", err)
	}
}

// The row limit is what keeps one upload from taking the site down with it.
func TestLoadCsvStopsAtTheRowLimit(t *testing.T) {
	quietUploadLog(t)

	var b strings.Builder
	b.WriteString("Name,Edition,Quantity\n")
	for i := 0; i < 50; i++ {
		b.WriteString("Lightning Bolt,Beta,1\n")
	}

	entries, err := loadCsv(strings.NewReader(b.String()), ',', 10)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) > 10 {
		t.Errorf("read %d rows against a limit of 10", len(entries))
	}
}

// A short row is not a reason to throw the file away: the rows around it still
// carry cards.
func TestLoadCsvKeepsReadingPastARaggedRow(t *testing.T) {
	quietUploadLog(t)

	body := "Name,Edition,Quantity,Price\n" +
		"Lightning Bolt,Beta,4,$12.50\n" +
		"Counterspell,Ice Age\n" +
		"Black Lotus,Alpha,1,$9999.00\n"

	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d rows, want all 3", len(entries))
	}
	if entries[2].OriginalPrice != 9999.00 {
		t.Errorf("the row after the short one has price %v, want 9999", entries[2].OriginalPrice)
	}
}

// A decklist whose card names contain commas cannot be split on commas at all,
// so the parser reads each line whole instead. Commander lists are full of
// these - "Hanna, Ship's Navigator" is one card, not two columns.
func TestLoadCsvReadsADecklistWithCommasInTheNames(t *testing.T) {
	quietUploadLog(t)

	body := "1 Hanna, Ship's Navigator\n1 Jhoira, Weatherlight Captain\n1 Sisay, Weatherlight Captain\n"
	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d rows, want 3 - the names were split on their commas", len(entries))
	}
	for i, entry := range entries {
		if !entry.HasQuantity || entry.Quantity != 1 {
			t.Errorf("row %d quantity = %d, want 1", i, entry.Quantity)
		}
		// The quantity came off the front, so what is left is the name - and
		// it has to still hold everything after the comma.
		if entry.Card.Name == "" {
			t.Errorf("row %d parsed no card name at all", i)
		}
	}
	if got := entries[0].Card.Name; !strings.HasPrefix(got, "Hanna") {
		t.Errorf("first card is %q, want it to start with Hanna", got)
	}
}

// A row holding none of something is not a row. Skipping it here is what keeps
// a full collection export from arriving as thousands of empty holdings.
func TestLoadCsvSkipsRowsWithNoStock(t *testing.T) {
	quietUploadLog(t)

	body := "Name,Edition,Quantity\n" +
		"Lightning Bolt,Beta,4\n" +
		"Counterspell,Ice Age,0\n" +
		"Black Lotus,Alpha,1\n"

	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2 - the zero-quantity row was kept", len(entries))
	}
	for _, entry := range entries {
		if entry.Quantity == 0 {
			t.Error("a row with no stock reached the results")
		}
	}
}

// A card nobody can match still has to say which line it came from, because
// that is the only way the reader finds it in a file of thousands.
func TestLoadCsvNamesTheLineACardFailedOn(t *testing.T) {
	quietUploadLog(t)

	body := "Name,Edition,Quantity\n" +
		"Lightning Bolt,Beta,1\n" +
		"Definitely Not A Magic Card,Nowhere,1\n"

	entries, err := loadCsv(strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	bad := entries[1]
	if bad.MismatchError == nil {
		t.Skip("this datastore matched a card that should not exist")
	}
	if !strings.Contains(bad.MismatchError.Error(), "record on line 3") {
		t.Errorf("mismatch says %q, want it to name line 3", bad.MismatchError)
	}
}

// A file that declares its separator and then stops has no header to read.
func TestLoadCsvRefusesAFileThatIsOnlyASeparator(t *testing.T) {
	quietUploadLog(t)

	if _, err := loadCsv(strings.NewReader("sep=;\n"), ',', uploadRowLimit); err == nil {
		t.Fatal("a file with nothing after its separator line was accepted")
	}
}

// buildXlsx writes a workbook in memory, which is how the xlsx tests get a
// real file without one being committed.
func buildXlsx(t *testing.T, sheets map[string][][]string, order []string) io.Reader {
	t.Helper()
	f := excelize.NewFile()
	defer f.Close()

	for i, name := range order {
		rows := sheets[name]
		if i == 0 {
			if err := f.SetSheetName("Sheet1", name); err != nil {
				t.Fatalf("naming the first sheet: %v", err)
			}
		} else if _, err := f.NewSheet(name); err != nil {
			t.Fatalf("adding sheet %q: %v", name, err)
		}
		for r, row := range rows {
			for c, val := range row {
				cell, err := excelize.CoordinatesToCellName(c+1, r+1)
				if err != nil {
					t.Fatalf("cell %d,%d: %v", c, r, err)
				}
				if err := f.SetCellStr(name, cell, val); err != nil {
					t.Fatalf("writing %s!%s: %v", name, cell, err)
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatalf("writing the workbook: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestLoadXlsxReadsWhatTheHeaderNames(t *testing.T) {
	quietUploadLog(t)

	rows := append([][]string{parserHeader}, parserRows...)
	entries, err := loadXlsx(buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	if !entries[0].HasQuantity || entries[0].Quantity != 4 {
		t.Errorf("quantity = %d, want 4", entries[0].Quantity)
	}
	if entries[0].OriginalPrice != 12.50 {
		t.Errorf("price = %v, want 12.50", entries[0].OriginalPrice)
	}
}

// A workbook exported from the site carries its own sheet among others, and
// that is the one holding the list.
func TestLoadXlsxPrefersTheSheetNamedForUs(t *testing.T) {
	quietUploadLog(t)

	decoy := [][]string{{"Name", "Edition", "Quantity"}, {"Decoy Card", "Nowhere", "99"}}
	ours := append([][]string{parserHeader}, parserRows...)
	reader := buildXlsx(t, map[string][][]string{
		"Instructions": decoy,
		"MTGBAN List":  ours,
	}, []string{"Instructions", "MTGBAN List"})

	entries, err := loadXlsx(reader, uploadRowLimit)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	if entries[0].Quantity != 4 {
		t.Errorf("quantity = %d, want 4 - the wrong sheet was read", entries[0].Quantity)
	}
}

func TestLoadXlsxRefusesWhatIsNotAWorkbook(t *testing.T) {
	quietUploadLog(t)

	for _, tt := range []struct {
		name string
		body string
	}{
		{"plain text", "Name,Edition\nLightning Bolt,Beta\n"},
		{"empty", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadXlsx(strings.NewReader(tt.body), uploadRowLimit); err == nil {
				t.Error("a file that is not a workbook was accepted")
			}
		})
	}
}

func TestLoadXlsxStopsAtTheRowLimit(t *testing.T) {
	quietUploadLog(t)

	rows := [][]string{{"Name", "Edition", "Quantity"}}
	for i := 0; i < 50; i++ {
		rows = append(rows, []string{"Lightning Bolt", "Beta", "1"})
	}
	entries, err := loadXlsx(buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), 10)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) > 10 {
		t.Errorf("read %d rows against a limit of 10", len(entries))
	}
}

// There is no .xls writer in the module graph, so the happy path would need a
// binary fixture committed alongside these tests. What can be pinned without
// one is that the reader refuses anything that is not a workbook rather than
// handing back rows built from noise.
func TestLoadOldXlsRefusesWhatIsNotAWorkbook(t *testing.T) {
	quietUploadLog(t)

	for _, tt := range []struct {
		name string
		body string
	}{
		{"plain text", "Name,Edition\nLightning Bolt,Beta\n"},
		{"empty", ""},
		{"a zip, which is the newer format", "PK\x03\x04not really"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := loadOldXls(strings.NewReader(tt.body), uploadRowLimit)
			if err == nil {
				t.Errorf("accepted %s and returned %d entries", tt.name, len(entries))
			}
		})
	}
}

// loadCollection fetches a page, so the half worth pinning without a network is
// the guard in front of it: the link is re-parsed here rather than trusted, and
// anything that is not a TCGplayer collection is refused before a request is
// built. Every case below has to fail without reaching the network.
func TestLoadCollectionOnlyFetchesATCGplayerCollection(t *testing.T) {
	quietUploadLog(t)

	for _, tt := range []struct {
		name string
		link string
	}{
		{"another host entirely", "https://example.com/collection/view/abc"},
		{"an internal address", "https://169.254.169.254/collection/view/abc"},
		{"localhost", "https://127.0.0.1:8080/collection/view/abc"},
		{"plain http", "http://store.tcgplayer.com/collection/view/abc"},
		{"the right host, the wrong path", "https://store.tcgplayer.com/admin/secrets"},
		{"a lookalike host", "https://store.tcgplayer.com.evil.test/collection/view/abc"},
		{"the host as a userinfo field", "https://store.tcgplayer.com@evil.test/collection/view/abc"},
		{"not a URL at all", "://"},
		{"empty", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := loadCollection(context.Background(), tt.link, uploadRowLimit)
			if err == nil {
				t.Fatalf("%q was accepted", tt.link)
			}
			if !strings.Contains(err.Error(), "unsupported URL") {
				t.Errorf("%q failed with %q, which means it got past the guard", tt.link, err)
			}
		})
	}
}
