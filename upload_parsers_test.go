package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/mtgban/mtgban-website/internal/xlsread/xlstest"
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

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(joinRows(",")), ',', uploadRowLimit)
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
			entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(joinRows(tt.sep)), tt.comma, uploadRowLimit)
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
	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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
	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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

	_, err := loadCsv(newUploadParser(backend()), strings.NewReader(""), ',', uploadRowLimit)
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

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(b.String()), ',', 10)
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

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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
	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
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

	if _, err := loadCsv(newUploadParser(backend()), strings.NewReader("sep=;\n"), ',', uploadRowLimit); err == nil {
		t.Fatal("a file with nothing after its separator line was accepted")
	}
}

// "sep=" naming no separator at all is refused the same way when nothing
// follows it, and leaves the separator as it was when a header does.
func TestLoadCsvTakesABareSeparatorLineAsNone(t *testing.T) {
	quietUploadLog(t)

	if _, err := loadCsv(newUploadParser(backend()), strings.NewReader("sep=\n"), ',', uploadRowLimit); err == nil {
		t.Error("a file that is only \"sep=\" was accepted")
	}

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader("sep=\n"+joinRows(",")), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("loadCsv: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	if entries[0].OriginalPrice != 12.50 {
		t.Errorf("price = %v, want 12.50 - the columns were not split", entries[0].OriginalPrice)
	}
}

// dyingReader serves a prefix and then fails every read after it, which is how
// an uploaded file behaves when it is a temp file on a disk that goes away.
type dyingReader struct {
	data  []byte
	pos   int
	until int
}

func (d *dyingReader) Read(p []byte) (int, error) {
	if d.pos >= d.until {
		return 0, errors.New("the file went away")
	}
	end := d.until
	if end > len(d.data) {
		end = len(d.data)
	}
	n := copy(p, d.data[d.pos:end])
	d.pos += n
	return n, nil
}

func (d *dyingReader) Seek(offset int64, whence int) (int64, error) {
	d.pos = int(offset)
	return offset, nil
}

// A file that stops being readable is not a list, and it is not a long list
// either. csv.Reader answers with the same error for every row asked of it
// once the reader underneath has failed, so a loop that records the error and
// carries on fills itself to the row limit with one error repeated - and used
// to hand that back as a successful upload of 15000 rows.
func TestLoadCsvStopsWhenTheFileStopsBeingReadable(t *testing.T) {
	quietUploadLog(t)

	var b strings.Builder
	b.WriteString("Name,Edition,Quantity\n")
	for i := 0; i < 20; i++ {
		b.WriteString("Lightning Bolt,Beta,1\n")
	}

	for _, maxRows := range []int{50, MaxUploadTotalEntries} {
		reader := &dyingReader{data: []byte(b.String()), until: 60}
		entries, err := loadCsv(newUploadParser(backend()), reader, ',', maxRows)
		if err == nil {
			t.Errorf("maxRows=%d: a file that died mid-read came back as %d good entries",
				maxRows, len(entries))
			continue
		}
		if len(entries) != 0 {
			t.Errorf("maxRows=%d: %d entries came back beside the error", maxRows, len(entries))
		}
		if !strings.Contains(err.Error(), "the file went away") {
			t.Errorf("maxRows=%d: error is %q, want it to carry the read failure", maxRows, err)
		}
	}
}

// The other half of that: trouble inside the file is not the file failing.
// A stray quote is swallowed rather than ending the read - LazyQuotes is set
// for exactly that - so loadCsv still answers with rows and no error, which is
// what makes the hard stop above specific to a reader that has actually died.
func TestLoadCsvDoesNotFailAFileOverAStrayQuote(t *testing.T) {
	quietUploadLog(t)

	body := "Name,Edition,Quantity\n" +
		"Lightning Bolt,Beta,4\n" +
		"Sol\"Ring,Commander 2013,1\n"

	entries, err := loadCsv(newUploadParser(backend()), strings.NewReader(body), ',', uploadRowLimit)
	if err != nil {
		t.Fatalf("a stray quote failed the whole file: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("a stray quote emptied the file")
	}
	if entries[0].Card.Name != "Lightning Bolt" {
		t.Errorf("first card is %q, want Lightning Bolt", entries[0].Card.Name)
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
	entries, err := loadXlsx(newUploadParser(backend()), buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), uploadRowLimit)
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

	entries, err := loadXlsx(newUploadParser(backend()), reader, uploadRowLimit)
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
			if _, err := loadXlsx(newUploadParser(backend()), strings.NewReader(tt.body), uploadRowLimit); err == nil {
				t.Error("a file that is not a workbook was accepted")
			}
		})
	}
}

// A sheet's row ends at its last cell that is not blank, so a blank name in
// the last column is a row shorter than the header. It is kept, as in a CSV.
func TestLoadXlsxKeepsARowWithABlankLastCell(t *testing.T) {
	quietUploadLog(t)

	rows := [][]string{{"Edition", "Quantity", "Name"}, {"Beta", "4", ""}, {"Beta", "1", "Lightning Bolt"}}
	entries, err := loadXlsx(newUploadParser(backend()), buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d rows, want 2", len(entries))
	}
	if entries[0].Quantity != 4 || entries[0].Card.Name != "" {
		t.Errorf("short row = %+v, want quantity 4 and no name", entries[0])
	}
	if entries[1].Card.Name != "Lightning Bolt" {
		t.Errorf("name after the short row = %q, want Lightning Bolt", entries[1].Card.Name)
	}
}

func TestLoadXlsxStopsAtTheRowLimit(t *testing.T) {
	quietUploadLog(t)

	rows := [][]string{{"Name", "Edition", "Quantity"}}
	for i := 0; i < 50; i++ {
		rows = append(rows, []string{"Lightning Bolt", "Beta", "1"})
	}
	entries, err := loadXlsx(newUploadParser(backend()), buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), 10)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) > 10 {
		t.Errorf("read %d rows against a limit of 10", len(entries))
	}
}

// excelize pads a row out to its last cell, so one cell in column XFD made
// every row 16384 strings wide, and a 52KB file ran the server out of memory
// before the row limit was reached.
func TestLoadXlsxRefusesARowPastTheColumnCap(t *testing.T) {
	quietUploadLog(t)

	f := excelize.NewFile()
	defer f.Close()
	for c, h := range []string{"Name", "Edition", "Quantity"} {
		cell, _ := excelize.CoordinatesToCellName(c+1, 1)
		f.SetCellStr("Sheet1", cell, h)
	}
	f.SetCellStr("Sheet1", "XFD2", "x")
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatal(err)
	}

	_, err := loadXlsx(newUploadParser(backend()), &buf, uploadRowLimit)
	if err == nil || !strings.Contains(err.Error(), "row 2 has 16384 columns") {
		t.Errorf("err = %v, want row 2 refused for its width", err)
	}
}

// A row as wide as the cap is still a row: it is reported as a mismatch
// against its header, as any row wider than the header is.
func TestLoadXlsxReadsARowAtTheColumnCap(t *testing.T) {
	quietUploadLog(t)

	wide := make([]string, maxUploadColumns)
	wide[0], wide[len(wide)-1] = "Lightning Bolt", "x"
	rows := [][]string{{"Name", "Edition", "Quantity"}, wide, {"Lightning Bolt", "Beta", "1"}}
	entries, err := loadXlsx(newUploadParser(backend()), buildXlsx(t, map[string][][]string{"Sheet1": rows}, []string{"Sheet1"}), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadXlsx: %v", err)
	}
	if len(entries) != 2 || entries[0].MismatchError == nil {
		t.Errorf("entries = %+v, want the wide row as a mismatch and the next one read", entries)
	}
}

// A workbook is a zip, and what it unpacks to is bounded rather than left at
// excelize's 16GB default.
func TestLoadXlsxRefusesAWorkbookPastTheUnzipLimit(t *testing.T) {
	quietUploadLog(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(w, zeros{}, xlsxUnzipSizeLimit+1); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = loadXlsx(newUploadParser(backend()), &buf, uploadRowLimit)
	if err == nil || !strings.Contains(err.Error(), "unzip size exceeds") {
		t.Errorf("err = %v, want the workbook refused for its unpacked size", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// excelize hands any compound file to its decryptor, whose container reader
// sizes a slice from the header's directory sector count: this 512-byte
// header asks it for 32GB. An .xlsx is a zip, so loadXlsx refuses the
// header before excelize sees it.
func TestLoadXlsxRefusesACompoundFile(t *testing.T) {
	quietUploadLog(t)

	header := make([]byte, 512)
	copy(header, oleSignature)
	binary.LittleEndian.PutUint16(header[24:], 0x3e)       // minor version
	binary.LittleEndian.PutUint16(header[26:], 4)          // major version 4: 4096-byte sectors
	binary.LittleEndian.PutUint16(header[28:], 0xfffe)     // byte order
	binary.LittleEndian.PutUint16(header[30:], 12)         // sector shift
	binary.LittleEndian.PutUint16(header[32:], 6)          // mini sector shift
	binary.LittleEndian.PutUint32(header[40:], 0xfffffff0) // directory sectors
	binary.LittleEndian.PutUint32(header[48:], 0xfffffffe) // directory start: end of chain
	binary.LittleEndian.PutUint32(header[60:], 0xfffffffe) // mini FAT start
	binary.LittleEndian.PutUint32(header[68:], 0xfffffffe) // DIFAT start

	_, err := loadXlsx(newUploadParser(backend()), bytes.NewReader(header), uploadRowLimit)
	if err == nil || !strings.Contains(err.Error(), ".xls") {
		t.Errorf("err = %v, want the compound file refused", err)
	}
}

func buildXls(sheets ...xlstest.Sheet) io.Reader {
	return bytes.NewReader(xlstest.Workbook(sheets...))
}

func TestLoadOldXlsReadsWhatTheHeaderNames(t *testing.T) {
	quietUploadLog(t)

	rows := append([][]string{parserHeader}, parserRows...)
	entries, err := loadOldXls(newUploadParser(backend()), buildXls(xlstest.Sheet{Name: "Sheet1", Rows: rows}), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadOldXls: %v", err)
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

func TestLoadOldXlsPrefersTheSheetNamedForUs(t *testing.T) {
	quietUploadLog(t)

	decoy := [][]string{{"Name", "Edition", "Quantity"}, {"Decoy Card", "Nowhere", "99"}}
	ours := append([][]string{parserHeader}, parserRows...)
	entries, err := loadOldXls(newUploadParser(backend()), buildXls(
		xlstest.Sheet{Name: "Instructions", Rows: decoy},
		xlstest.Sheet{Name: "MTGBAN List", Rows: ours},
	), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadOldXls: %v", err)
	}
	if len(entries) != 2 || entries[0].Quantity != 4 {
		t.Errorf("entries = %+v, want the two rows of the MTGBAN sheet", entries)
	}
}

func TestLoadOldXlsStopsAtTheRowLimit(t *testing.T) {
	quietUploadLog(t)

	rows := [][]string{{"Name", "Edition", "Quantity"}}
	for i := 0; i < 50; i++ {
		rows = append(rows, []string{"Lightning Bolt", "Beta", "1"})
	}
	entries, err := loadOldXls(newUploadParser(backend()), buildXls(xlstest.Sheet{Name: "Sheet1", Rows: rows}), 10)
	if err != nil {
		t.Fatalf("loadOldXls: %v", err)
	}
	if len(entries) > 10 {
		t.Errorf("read %d rows against a limit of 10", len(entries))
	}
}

// extrame/xls handed back a nil row for a blank one, and the loop that read
// it panicked, so any list with a gap in it failed whole.
func TestLoadOldXlsReadsPastABlankRow(t *testing.T) {
	quietUploadLog(t)

	rows := [][]string{parserHeader, parserRows[0], nil, parserRows[1]}
	entries, err := loadOldXls(newUploadParser(backend()), buildXls(xlstest.Sheet{Name: "Sheet1", Rows: rows}), uploadRowLimit)
	if err != nil {
		t.Fatalf("loadOldXls: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("read %d rows, want the 2 around the gap", len(entries))
	}
}

func TestLoadOldXlsRefusesARowPastTheColumnCap(t *testing.T) {
	quietUploadLog(t)

	wide := make([]string, maxUploadColumns+1)
	wide[0], wide[maxUploadColumns] = "Lightning Bolt", "x"
	rows := [][]string{{"Name", "Edition", "Quantity"}, wide}
	_, err := loadOldXls(newUploadParser(backend()), buildXls(xlstest.Sheet{Name: "Sheet1", Rows: rows}), uploadRowLimit)
	if err == nil || !strings.Contains(err.Error(), "row 2 has 257 columns") {
		t.Errorf("err = %v, want row 2 refused for its width", err)
	}
}

// A compound file is an .xls whatever it is called, and excelize, which
// would hand it to its decryptor, never sees one.
func TestLoadUploadFileReadsAnXlsByItsContent(t *testing.T) {
	quietUploadLog(t)

	rows := append([][]string{parserHeader}, parserRows...)
	data := xlstest.Workbook(xlstest.Sheet{Name: "Sheet1", Rows: rows})
	for _, name := range []string{"list.xls", "list.xlsx", "list.csv"} {
		entries, err := loadUploadFile(newUploadParser(backend()), bytes.NewReader(data), name, uploadRowLimit)
		if err != nil || len(entries) != 2 {
			t.Errorf("%s: %d entries, err %v, want the 2 rows", name, len(entries), err)
		}
	}
}

// 30 bytes ran extrame/ole2 out of memory: it read past the end of the file
// without an error and looped on sector 0.
func TestLoadOldXlsRefusesTheFileThatCrashedTheOldReader(t *testing.T) {
	quietUploadLog(t)

	data := append(append([]byte{}, oleSignature...), make([]byte, 20)...)
	data = append(data, 0xfe, 0xff)
	if _, err := loadOldXls(newUploadParser(backend()), bytes.NewReader(data), uploadRowLimit); err == nil {
		t.Error("a 30-byte compound file was accepted")
	}
}

// Whatever is not a workbook is refused rather than handed back as rows
// built from noise.
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
			entries, err := loadOldXls(newUploadParser(backend()), strings.NewReader(tt.body), uploadRowLimit)
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
			_, _, err := loadCollection(context.Background(), newUploadParser(backend()), tt.link, uploadRowLimit)
			if err == nil {
				t.Fatalf("%q was accepted", tt.link)
			}
			if !strings.Contains(err.Error(), "unsupported URL") {
				t.Errorf("%q failed with %q, which means it got past the guard", tt.link, err)
			}
		})
	}
}
