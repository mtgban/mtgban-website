package xlsread

import (
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/mtgban/mtgban-website/internal/xlsread/xlstest"
)

func cellHead(row, col uint16) []byte {
	return append(append(xlstest.U16(row), xlstest.U16(col)...), xlstest.U16(0)...)
}

func labelSST(row, col uint16, i uint32) []byte {
	return xlstest.Record(recLabelSST, cellHead(row, col), xlstest.U32(i))
}

func label(row, col uint16, s string) []byte {
	return xlstest.Record(recLabel, cellHead(row, col), xlstest.LongString(s))
}

func number(row, col uint16, f float64) []byte {
	return xlstest.Record(recNumber, cellHead(row, col), binary.LittleEndian.AppendUint64(nil, math.Float64bits(f)))
}

func rk(row, col uint16, v uint32) []byte {
	return xlstest.Record(recRK, cellHead(row, col), xlstest.U32(v))
}

func rkInt(i int32, scaled bool) uint32 {
	v := uint32(i)<<2 | 2
	if scaled {
		v |= 1
	}
	return v
}

func formula(row, col uint16, value [8]byte) []byte {
	return xlstest.Record(recFormula, cellHead(row, col), value[:], xlstest.U16(0), xlstest.U32(0), xlstest.U16(0))
}

func boolErr(row, col uint16, v byte, isErr bool) []byte {
	e := byte(0)
	if isErr {
		e = 1
	}
	return xlstest.Record(recBoolErr, cellHead(row, col), []byte{v, e})
}

// book8 is a BIFF8 workbook of raw sheet bodies, each wrapped in BOF..EOF.
func book8(t *testing.T, sst []string, names []string, bodies ...[]byte) *Book {
	t.Helper()
	sheets := make([]xlstest.Sheet, len(names))
	wrapped := make([][]byte, len(bodies))
	for i := range names {
		sheets[i] = xlstest.Sheet{Name: names[i]}
		wrapped[i] = append(append(xlstest.BOF8(0x0010), bodies[i]...), xlstest.EOF()...)
	}
	b, err := Open(xlstest.Container("Workbook", xlstest.Globals(sheets, sst, wrapped)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return b
}

func equalRows(got, want [][]string) bool {
	return slices.EqualFunc(got, want, func(a, b []string) bool { return slices.Equal(a, b) })
}

func TestReadsEveryCellKind(t *testing.T) {
	sst := []string{"Name", "Price", "Lightning Bolt", "first", "chart", "after chart"}
	scaled := uint32(math.Float64bits(1250)>>34)<<2 | 1
	if math.Float64bits(1250)&(1<<34-1) != 0 {
		t.Fatal("1250 does not fit an RK float")
	}
	str := [8]byte{0, 0, 0, 0, 0, 0, 0xff, 0xff}
	tru := [8]byte{1, 0, 1, 0, 0, 0, 0xff, 0xff}
	var num [8]byte
	binary.LittleEndian.PutUint64(num[:], math.Float64bits(26))

	var body []byte
	for _, r := range [][]byte{
		labelSST(0, 0, 0), label(0, 1, "Qty"), labelSST(0, 2, 1), label(0, 3, "Ω wide"),
		labelSST(1, 0, 2), rk(1, 1, rkInt(4, false)), number(1, 2, 12.5), rk(1, 3, scaled),
		xlstest.Record(recMulRK, xlstest.U16(3), xlstest.U16(0),
			xlstest.U16(0), xlstest.U32(rkInt(1, false)), xlstest.U16(0), xlstest.U32(rkInt(2, false)), xlstest.U16(0), xlstest.U32(rkInt(-3, false)), xlstest.U16(2)),
		rk(3, 3, rkInt(1999, true)),
		formula(4, 0, num),
		formula(4, 1, str), xlstest.Record(recShrFmla, make([]byte, 10)), xlstest.Record(recString, xlstest.LongString("Total")),
		formula(4, 2, tru), boolErr(4, 3, 0x2a, true), boolErr(4, 4, 0, false),
		labelSST(5, 0, 3), label(5, 0, "second"), xlstest.Record(0x0201, cellHead(5, 1)),
		xlstest.BOF8(0x0020), labelSST(5, 2, 4), xlstest.EOF(),
		labelSST(5, 3, 5),
		label(9, 0, ""),
	} {
		body = append(body, r...)
	}

	b := book8(t, sst, []string{"Notes", "MTGBAN list"}, labelSST(0, 0, 0), body)
	if got := b.SheetNames(); !slices.Equal(got, []string{"Notes", "MTGBAN list"}) {
		t.Errorf("sheets %q", got)
	}
	rows, err := b.Rows(1, 100, 256)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"Name", "Qty", "Price", "Ω wide"},
		{"Lightning Bolt", "4", "12.5", "12.5"},
		nil,
		{"1", "2", "-3", "19.99"},
		{"26", "Total", "TRUE", "#N/A", "FALSE"},
		{"second", "", "", "after chart"},
	}
	if !equalRows(rows, want) {
		t.Errorf("rows\n got %q\nwant %q", rows, want)
	}
}

// Excel splits a long shared-string table across CONTINUE records, and text
// cut by a boundary picks up again with an option byte that may switch
// between one-byte and two-byte characters.
func TestReadsSharedStringsAcrossRecords(t *testing.T) {
	var strs []string
	for i := 0; i < 6; i++ {
		base := "x"
		if i%2 == 1 {
			base = "Ω"
		}
		strs = append(strs, strings.Repeat(base, 3000+i))
	}
	var body []byte
	for i := range strs {
		body = append(body, labelSST(uint16(i), 0, uint32(i))...)
	}
	b := book8(t, strs, []string{"Sheet1"}, body)
	rows, err := b.Rows(0, 100, 256)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range strs {
		if i >= len(rows) || len(rows[i]) != 1 || rows[i][0] != s {
			t.Errorf("string %d did not survive the record boundaries", i)
		}
	}

	// "ab" compressed, then a CONTINUE whose option byte turns wide for "cΩ"
	sst := xlstest.Record(recSST, xlstest.U32(1), xlstest.U32(1), xlstest.U16(4), []byte{0}, []byte("ab"))
	sst = append(sst, xlstest.Record(recContinue, []byte{1}, xlstest.U16('c'), xlstest.U16('Ω'))...)
	stream := append(xlstest.BOF8(0x0005), sst...)
	b = &Book{stream: append(stream, xlstest.EOF()...)}
	if err := b.parseGlobals(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.sst, []string{"abcΩ"}) {
		t.Errorf("sst %q, want the text to switch to two-byte characters", b.sst)
	}
}

// Excel 95 text is 8-bit in the workbook's codepage, and a CONTINUE carries
// on with no option byte.
func TestReadsExcel95(t *testing.T) {
	bof5 := func(kind uint16) []byte {
		return xlstest.Record(recBOF, xlstest.U16(0x0500), xlstest.U16(kind), make([]byte, 4))
	}
	label5 := func(row, col uint16, s string) []byte {
		return xlstest.Record(recLabel, cellHead(row, col), xlstest.U16(uint16(len(s))), []byte(s))
	}
	build := func(codepage uint16) []byte {
		name := "Lista \x92"
		sheet := append(bof5(0x0010), label5(0, 0, "Lim-D\xfbl\x92s Vault")...)
		sheet = append(sheet, number(0, 1, 3)...)
		// "\xc6ther Vial" with only its first four characters in the LABEL
		sheet = append(sheet, xlstest.Record(recLabel, cellHead(1, 0), xlstest.U16(10), []byte("\xc6the"))...)
		sheet = append(sheet, xlstest.Record(recContinue, []byte("r Vial"))...)
		sheet = append(sheet, xlstest.EOF()...)

		head := append(bof5(0x0005), xlstest.Record(recCodepage, xlstest.U16(codepage))...)
		bsLen := len(xlstest.Record(recBoundSheet, xlstest.U32(0), []byte{0, 0, byte(len(name))}, []byte(name)))
		pos := uint32(len(head) + bsLen + len(xlstest.EOF()))
		g := append(head, xlstest.Record(recBoundSheet, xlstest.U32(pos), []byte{0, 0, byte(len(name))}, []byte(name))...)
		g = append(g, xlstest.EOF()...)
		return xlstest.Container("Book", append(g, sheet...))
	}

	b, err := Open(build(1252))
	if err != nil {
		t.Fatal(err)
	}
	if got := b.SheetNames(); !slices.Equal(got, []string{"Lista ’"}) {
		t.Errorf("sheets %q", got)
	}
	rows, err := b.Rows(0, 100, 256)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"Lim-Dûl’s Vault", "3"}, {"Æther Vial"}}
	if !equalRows(rows, want) {
		t.Errorf("rows %q, want %q", rows, want)
	}

	// Another codepage keeps the bytes as Latin-1, as extrame/xls did
	b, err = Open(build(850))
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := b.Rows(0, 100, 256); len(rows) == 0 || rows[0][0] != "Lim-Dûl\u0092s Vault" {
		t.Errorf("rows %q", rows)
	}
}

func TestReadsTheRowAndColumnBounds(t *testing.T) {
	var body []byte
	for r := uint16(0); r < 10; r++ {
		body = append(body, label(r, 0, "a")...)
	}
	b := book8(t, nil, []string{"Sheet1"}, body)
	if rows, err := b.Rows(0, 4, 256); err != nil || len(rows) != 4 {
		t.Errorf("%d rows, err %v, want 4", len(rows), err)
	}

	// A cell past the columns asked for refuses the sheet, naming its row
	b = book8(t, nil, []string{"Sheet1"}, append(label(0, 0, "Name"), label(1, 299, "x")...))
	_, err := b.Rows(0, 100, 257)
	var wide *WideRowError
	if !errors.As(err, &wide) || wide.Row != 2 || wide.Cols != 300 {
		t.Errorf("err %v, want row 2 with 300 columns", err)
	}
	// unless it is past the rows asked for too
	if _, err := b.Rows(0, 1, 257); err != nil {
		t.Errorf("err %v for a wide row past the row limit", err)
	}
}

func TestRefusesWhatIsNotAnXls(t *testing.T) {
	oldBOF := xlstest.Record(recBOF, xlstest.U16(0x0400), xlstest.U16(0x0005), make([]byte, 4))
	for _, tt := range []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrNotXls},
		{"text", []byte("Name,Edition\nLightning Bolt,Beta\n"), ErrNotXls},
		{"a zip", []byte("PK\x03\x04not really"), ErrNotXls},
		{"no workbook stream", xlstest.Container("Something", []byte("x")), ErrNotXls},
		{"Excel 4", xlstest.Container("Book", append(oldBOF, xlstest.EOF()...)), ErrNotXls},
		{"FILEPASS", xlstest.Container("Workbook", append(append(xlstest.BOF8(0x0005), xlstest.Record(recFilePass, make([]byte, 6))...), xlstest.EOF()...)), ErrEncrypted},
		{"an encrypted .xlsx", xlstest.Container("EncryptedPackage", []byte("x")), ErrEncrypted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.data); !errors.Is(err, tt.want) {
				t.Errorf("err %v, want %v", err, tt.want)
			}
		})
	}
}

// Each of these ran extrame/ole2, or mscfb, out of memory.
func TestRefusesTheFilesThatCrashedTheOldReader(t *testing.T) {
	// 30 bytes: ole2 looped on sector 0 past the end of the file
	tiny := append(append([]byte{}, oleSignature...), make([]byte, 20)...)
	tiny = append(tiny, 0xfe, 0xff)

	// mscfb sized a slice from this directory sector count: 32GB
	dirCount := make([]byte, 512)
	copy(dirCount, oleSignature)
	binary.LittleEndian.PutUint16(dirCount[26:], 4)
	binary.LittleEndian.PutUint16(dirCount[28:], 0xfffe)
	binary.LittleEndian.PutUint16(dirCount[30:], 12)
	binary.LittleEndian.PutUint32(dirCount[40:], 0xfffffff0)

	// A stream whose sectors loop back on themselves, claiming 1GB
	cycle := xlstest.Container("Workbook", append(xlstest.BOF8(0x0005), xlstest.EOF()...))
	binary.LittleEndian.PutUint32(cycle[512+4*9:], 2)
	binary.LittleEndian.PutUint64(cycle[1024+128+120:], 1<<30)

	for name, data := range map[string][]byte{"tiny": tiny, "directory count": dirCount, "sector cycle": cycle} {
		start := time.Now()
		if _, err := Open(data); err == nil {
			t.Errorf("%s: opened", name)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Counts read from the file never size an allocation by themselves.
func TestForgedCountsAllocateNothing(t *testing.T) {
	sheet := func(body []byte) []byte { return append(append(xlstest.BOF8(0x0010), body...), xlstest.EOF()...) }
	for _, tt := range []struct {
		name   string
		sst    []byte
		sheet  []byte
		maxCol int
	}{
		{"4G shared strings", xlstest.Record(recSST, xlstest.U32(1), xlstest.U32(0xffffffff), xlstest.U16(1), []byte{0}, []byte("A")), nil, 256},
		{"64K characters", xlstest.Record(recSST, xlstest.U32(1), xlstest.U32(1), xlstest.U16(0xffff), []byte{1}, []byte("AB")), nil, 256},
		{"2GB extension block", xlstest.Record(recSST, xlstest.U32(1), xlstest.U32(1), xlstest.U16(1), []byte{4}, xlstest.U32(0x7fffffff), []byte("A")), nil, 256},
		{"index past the table", nil, labelSST(0, 0, 0xffffffff), 256},
		{"cell at 65535,65535", nil, number(0xffff, 0xffff, 1), 256},
		{"64K-wide MULRK", nil, xlstest.Record(recMulRK, xlstest.U16(0), xlstest.U16(0xfff0), xlstest.U16(0), xlstest.U32(2), xlstest.U16(0), xlstest.U32(2), xlstest.U16(0xfff1)), 256},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stream := append(xlstest.BOF8(0x0005), xlstest.Record(recBoundSheet, xlstest.U32(0), []byte{0, 0}, xlstest.ShortString("S"))...)
			stream = append(stream, tt.sst...)
			stream = append(stream, xlstest.EOF()...)
			binary.LittleEndian.PutUint32(stream[len(xlstest.BOF8(0))+4:], uint32(len(stream)))
			stream = append(stream, sheet(tt.sheet)...)
			n := allocated(func() {
				b := &Book{stream: stream}
				if b.parseGlobals() == nil {
					_, _ = b.Rows(0, 15001, tt.maxCol)
				}
			})
			if n > 1<<20 {
				t.Errorf("allocated %d bytes for a %d-byte stream", n, len(stream))
			}
		})
	}
}

// 10MB of MULRK records, as many cells as an upload body can carry, all in
// bounds: the sheet is refused at maxCells rather than held.
func TestRefusesASheetPastTheCellCap(t *testing.T) {
	var body []byte
	for row := 0; len(body) < 10<<20; row++ {
		rec := cat(xlstest.U16(uint16(row%15000)), xlstest.U16(0))
		for k := 0; k < 255; k++ {
			rec = append(rec, cat(xlstest.U16(0), xlstest.U32(rkInt(int32(k), false)))...)
		}
		body = append(body, xlstest.Record(recMulRK, rec, xlstest.U16(254))...)
	}
	b := &Book{stream: append(append(xlstest.BOF8(0x0010), body...), xlstest.EOF()...)}
	b.sheets = []sheet{{name: "S"}}
	if _, err := b.Rows(0, 15001, 256); !errors.Is(err, ErrTooManyCells) {
		t.Errorf("err %v, want ErrTooManyCells", err)
	}
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func seeds() [][]byte {
	long := strings.Repeat("Ω", 5000)
	return [][]byte{
		xlstest.Workbook(xlstest.Sheet{Name: "Sheet1", Rows: [][]string{{"Name", "Quantity"}, {"Lightning Bolt", "4"}}}),
		xlstest.Workbook(
			xlstest.Sheet{Name: "Notes", Rows: [][]string{{"decoy"}}},
			xlstest.Sheet{Name: "MTGBAN list", Rows: [][]string{{"Name", "Notes"}, {"Æther Vial", long}, nil, {"Fire // Ice", long + "x"}}},
		),
	}
}

// FuzzOpen holds Open and Rows to their promise: no panic escapes, every
// input finishes quickly, and allocation stays proportional to the input.
func FuzzOpen(f *testing.F) {
	for _, s := range seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		n := allocated(func() {
			if b, err := Open(data); err == nil {
				for i := range b.SheetNames() {
					_, _ = b.Rows(i, 15001, 257)
				}
			}
		})
		if d := time.Since(start); d > time.Second {
			t.Fatalf("took %v on %d bytes", d, len(data))
		}
		if n > 64*uint64(len(data))+4<<20 {
			t.Fatalf("allocated %d bytes for %d bytes of input", n, len(data))
		}
	})
}

// FuzzBIFF mutates the workbook stream itself, past the container, so the
// record parsers see forged counts, sizes and offsets directly.
func FuzzBIFF(f *testing.F) {
	for _, s := range seeds() {
		if stream, err := workbookStream(s); err == nil {
			f.Add(stream)
		}
	}
	f.Fuzz(func(t *testing.T, stream []byte) {
		start := time.Now()
		n := allocated(func() {
			b := &Book{stream: stream}
			if b.parseGlobals() == nil {
				for _, s := range b.sheets {
					_, _ = b.parseSheet(s.pos, 15001, 257)
				}
			}
		})
		if d := time.Since(start); d > time.Second {
			t.Fatalf("took %v on %d bytes", d, len(stream))
		}
		if n > 64*uint64(len(stream))+4<<20 {
			t.Fatalf("allocated %d bytes for %d bytes of stream", n, len(stream))
		}
	})
}

// sharedChainContainer is a compound file whose n stream entries, all named
// name, point at the one sector chain holding stream.
func sharedChainContainer(n int, name string, stream []byte) []byte {
	const sector = 512
	dirSectors := (n + 1 + 3) / 4
	streamSectors := (len(stream) + sector - 1) / sector
	fatSectors := 1
	for (fatSectors+dirSectors+streamSectors+127)/128 > fatSectors {
		fatSectors++
	}
	total := fatSectors + dirSectors + streamSectors

	header := make([]byte, sector)
	copy(header, oleSignature)
	binary.LittleEndian.PutUint16(header[24:], 0x3e)
	binary.LittleEndian.PutUint16(header[26:], 3)
	binary.LittleEndian.PutUint16(header[28:], 0xfffe)
	binary.LittleEndian.PutUint16(header[30:], 9)
	binary.LittleEndian.PutUint16(header[32:], 6)
	binary.LittleEndian.PutUint32(header[44:], uint32(fatSectors))
	binary.LittleEndian.PutUint32(header[48:], uint32(fatSectors))
	binary.LittleEndian.PutUint32(header[56:], 4096)
	binary.LittleEndian.PutUint32(header[60:], 0xfffffffe)
	binary.LittleEndian.PutUint32(header[68:], 0xfffffffe)
	for i := 0; i < 109; i++ {
		v := uint32(0xffffffff)
		if i < fatSectors {
			v = uint32(i)
		}
		binary.LittleEndian.PutUint32(header[76+4*i:], v)
	}

	fat := make([]byte, fatSectors*sector)
	for i := range fatSectors * 128 {
		binary.LittleEndian.PutUint32(fat[4*i:], 0xffffffff)
	}
	chain := func(start, count int) {
		for i := 0; i < count; i++ {
			next := uint32(start + i + 1)
			if i == count-1 {
				next = 0xfffffffe
			}
			binary.LittleEndian.PutUint32(fat[4*(start+i):], next)
		}
	}
	for i := 0; i < fatSectors; i++ {
		binary.LittleEndian.PutUint32(fat[4*i:], 0xfffffffd)
	}
	chain(fatSectors, dirSectors)
	chain(fatSectors+dirSectors, streamSectors)

	dir := make([]byte, dirSectors*sector)
	entry := func(i int, entryName string, kind byte, right, child, start uint32, size uint64) {
		b := dir[128*i:]
		units := utf16.Encode([]rune(entryName))
		for j, u := range units {
			binary.LittleEndian.PutUint16(b[2*j:], u)
		}
		if entryName != "" {
			binary.LittleEndian.PutUint16(b[64:], uint16(2*len(units)+2))
		}
		b[66], b[67] = kind, 1
		binary.LittleEndian.PutUint32(b[68:], 0xffffffff)
		binary.LittleEndian.PutUint32(b[72:], right)
		binary.LittleEndian.PutUint32(b[76:], child)
		binary.LittleEndian.PutUint32(b[116:], start)
		binary.LittleEndian.PutUint64(b[120:], size)
	}
	entry(0, "Root Entry", 5, 0xffffffff, 1, 0xfffffffe, 0)
	for i := 1; i <= n; i++ {
		right := uint32(i + 1)
		if i == n {
			right = 0xffffffff
		}
		entry(i, name, 2, right, 0xffffffff, uint32(fatSectors+dirSectors), uint64(len(stream)))
	}
	for i := n + 1; i < dirSectors*4; i++ {
		entry(i, "", 0, 0xffffffff, 0xffffffff, 0, 0)
	}

	out := append(header, fat...)
	out = append(out, dir...)
	out = append(out, stream...)
	return append(out, make([]byte, (total+1)*sector-len(out))...)
}

// Directory entries cost 128 bytes and may all point at one sector chain, so
// reading every Book stream made the work quadratic in the file's size: only
// one stream is read.
func TestReadsOneWorkbookStream(t *testing.T) {
	bof5 := xlstest.Record(recBOF, xlstest.U16(0x0500), xlstest.U16(0x0005), make([]byte, 4))
	stream := append(append(bof5, xlstest.EOF()...), make([]byte, 512<<10)...)
	data := sharedChainContainer(1000, "Book", stream)

	var err error
	n := allocated(func() { _, err = Open(data) })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if n > 16<<20 {
		t.Errorf("allocated %d MB opening a %d KB file of 1000 Book entries", n>>20, len(data)>>10)
	}
}

// When a string's count and flags fill a record exactly, its characters
// start in the CONTINUE, behind that record's own option byte.
func TestReadsTextStartingInAContinue(t *testing.T) {
	for _, tt := range []struct {
		name string
		cont []byte
		want string
	}{
		{"compressed", append([]byte{0}, 'c'), "c"},
		{"wide", append([]byte{1}, xlstest.U16('Ω')...), "Ω"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sst := xlstest.Record(recSST, xlstest.U32(2), xlstest.U32(2),
				xlstest.U16(2), []byte{0}, []byte("ab"), xlstest.U16(1), []byte{0})
			sst = append(sst, xlstest.Record(recContinue, tt.cont)...)
			b := &Book{stream: append(append(xlstest.BOF8(0x0005), sst...), xlstest.EOF()...)}
			if err := b.parseGlobals(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(b.sst, []string{"ab", tt.want}) {
				t.Errorf("sst %q, want %q", b.sst, []string{"ab", tt.want})
			}
		})
	}
}
