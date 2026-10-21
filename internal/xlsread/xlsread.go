// Package xlsread reads the cell text of a legacy Excel workbook (.xls),
// BIFF8 or BIFF5, from bytes already in memory. Every allocation is sized by
// bytes the file actually holds, so a forged count or offset costs no more
// than the file's own length.
package xlsread

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/richardlehane/mscfb"
)

var (
	// ErrNotXls is a file that is not a workbook this package reads.
	ErrNotXls = errors.New("not an xls file")
	// ErrEncrypted is a workbook that needs a password to read.
	ErrEncrypted = errors.New("password-protected workbooks are not supported")
	// ErrCorrupt is a workbook whose structure contradicts itself.
	ErrCorrupt = errors.New("corrupt xls file")
	// ErrTooManyCells is a sheet past maxCells.
	ErrTooManyCells = errors.New("xls sheet has too many cells")
)

// WideRowError names the first row holding a cell past the columns asked
// for, and how wide that cell makes it.
type WideRowError struct {
	Row, Cols int
}

// Error names the row and its width, counting both from one.
func (e *WideRowError) Error() string {
	return fmt.Sprintf("row %d has %d columns", e.Row, e.Cols)
}

// maxCells caps the cells one sheet may hold whatever bounds are asked for:
// a real upload has a few hundred thousand at most.
const maxCells = 1 << 20

var oleSignature = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

// IsOLE reports whether data starts like a compound file, which is what an
// .xls is and what a password-protected .xlsx is wrapped in.
func IsOLE(data []byte) bool {
	return bytes.HasPrefix(data, oleSignature)
}

// Book is an opened workbook.
type Book struct {
	stream []byte
	biff5  bool
	cp1252 bool
	sst    []string
	sheets []sheet
}

type sheet struct {
	name string
	pos  uint32
}

// Open parses the workbook globals of an .xls file.
func Open(data []byte) (b *Book, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("%w: %v", ErrCorrupt, r)
		}
	}()
	stream, err := workbookStream(data)
	if err != nil {
		return nil, err
	}
	b = &Book{stream: stream}
	if err := b.parseGlobals(); err != nil {
		return nil, err
	}
	return b, nil
}

// SheetNames lists the sheets in workbook order.
func (b *Book) SheetNames() []string {
	names := make([]string, len(b.sheets))
	for i, s := range b.sheets {
		names[i] = s.name
	}
	return names
}

// Rows returns the first maxRows rows of sheet i. As with excelize's
// GetRows, a row stops at its last non-empty cell, a blank row before the
// last is an empty slice, and nothing follows the last non-empty row. A
// cell at or past maxCols is a *WideRowError rather than dropped.
func (b *Book) Rows(i, maxRows, maxCols int) (rows [][]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			rows, err = nil, fmt.Errorf("%w: %v", ErrCorrupt, r)
		}
	}()
	if i < 0 || i >= len(b.sheets) {
		return nil, errors.New("no such sheet")
	}
	cells, err := b.parseSheet(b.sheets[i].pos, maxRows, maxCols)
	if err != nil {
		return nil, err
	}
	// The last record for a cell wins, as it does in Excel
	sort.SliceStable(cells, func(x, y int) bool {
		if cells[x].row != cells[y].row {
			return cells[x].row < cells[y].row
		}
		return cells[x].col < cells[y].col
	})
	for j := 0; j < len(cells); {
		k := j
		for k+1 < len(cells) && cells[k+1].row == cells[j].row && cells[k+1].col == cells[j].col {
			k++
		}
		c := cells[k]
		j = k + 1
		if c.val == "" {
			continue
		}
		for len(rows) <= int(c.row) {
			rows = append(rows, nil)
		}
		r := rows[c.row]
		for len(r) <= int(c.col) {
			r = append(r, "")
		}
		r[c.col] = c.val
		rows[c.row] = r
	}
	return rows, nil
}

// workbookStream pulls the Workbook (BIFF8) or Book (BIFF5) stream out of
// the compound file.
func workbookStream(data []byte) ([]byte, error) {
	if err := checkCFBHeader(data); err != nil {
		return nil, err
	}
	doc, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotXls, err)
	}
	var found []byte
	encrypted := false
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		switch entry.Name {
		case "EncryptedPackage":
			encrypted = true
			continue
		case "Workbook", "Book":
		default:
			continue
		}
		// A stream can't hold more than the file does: one that claims to
		// has a forged size or a sector cycle
		buf, err := io.ReadAll(io.LimitReader(entry, int64(len(data))+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if len(buf) > len(data) {
			return nil, fmt.Errorf("%w: stream larger than the file", ErrCorrupt)
		}
		found = buf
		if entry.Name == "Workbook" {
			break
		}
	}
	if found == nil {
		if encrypted {
			return nil, ErrEncrypted
		}
		return nil, fmt.Errorf("%w: no workbook stream", ErrNotXls)
	}
	return found, nil
}

// checkCFBHeader refuses a compound file whose header counts more sectors
// of any kind than the file holds. mscfb sizes slices from these counts
// before reading anything, and every sector a valid file counts exists.
func checkCFBHeader(data []byte) error {
	if len(data) < 512 || !IsOLE(data) {
		return ErrNotXls
	}
	var sectorSize int
	switch binary.LittleEndian.Uint16(data[30:32]) {
	case 9:
		sectorSize = 512
	case 12:
		sectorSize = 4096
	default:
		return fmt.Errorf("%w: illegal sector size", ErrNotXls)
	}
	sectors := uint64(len(data) / sectorSize)
	for _, off := range []int{40, 44, 64, 72} { // directory, FAT, mini FAT, DIFAT
		if uint64(binary.LittleEndian.Uint32(data[off:off+4])) > sectors {
			return fmt.Errorf("%w: sector count exceeds the file", ErrCorrupt)
		}
	}
	return nil
}

const (
	recBOF        = 0x0809
	recEOF        = 0x000a
	recFilePass   = 0x002f
	recCodepage   = 0x0042
	recBoundSheet = 0x0085
	recSST        = 0x00fc
	recContinue   = 0x003c
	recLabelSST   = 0x00fd
	recLabel      = 0x0204
	recRString    = 0x00d6
	recNumber     = 0x0203
	recRK         = 0x027e
	recMulRK      = 0x00bd
	recFormula    = 0x0006
	recShrFmla    = 0x04bc
	recArray      = 0x0221
	recTable      = 0x0236
	recString     = 0x0207
	recBoolErr    = 0x0205
)

// records walks the BIFF records of a stream from an offset.
type records struct {
	s   []byte
	pos int
}

func (r *records) next() (id uint16, body []byte, ok bool) {
	if r.pos+4 > len(r.s) {
		return 0, nil, false
	}
	id = binary.LittleEndian.Uint16(r.s[r.pos:])
	size := int(binary.LittleEndian.Uint16(r.s[r.pos+2:]))
	if r.pos+4+size > len(r.s) {
		return 0, nil, false
	}
	body = r.s[r.pos+4 : r.pos+4+size]
	r.pos += 4 + size
	return id, body, true
}

// continued gathers the CONTINUE records that follow the current one.
func (r *records) continued(first []byte) [][]byte {
	segs := [][]byte{first}
	for {
		save := r.pos
		id, body, ok := r.next()
		if !ok || id != recContinue {
			r.pos = save
			return segs
		}
		segs = append(segs, body)
	}
}

// text reads across segs the way this workbook's version stores text.
func (b *Book) text(segs [][]byte) *segReader {
	return &segReader{segs: segs, biff5: b.biff5, cp1252: b.cp1252}
}

func (b *Book) parseGlobals() error {
	r := &records{s: b.stream}
	id, body, ok := r.next()
	if !ok || id != recBOF || len(body) < 4 {
		return fmt.Errorf("%w: no BOF", ErrNotXls)
	}
	switch binary.LittleEndian.Uint16(body) {
	case 0x0600:
	case 0x0500:
		// Excel 95 text is 8-bit in the workbook's codepage, 1252 unless
		// a CODEPAGE record says otherwise
		b.biff5, b.cp1252 = true, true
	default:
		return fmt.Errorf("%w: unsupported BIFF version", ErrNotXls)
	}
	for {
		id, body, ok := r.next()
		if !ok || id == recEOF {
			return nil
		}
		switch id {
		case recFilePass:
			return ErrEncrypted
		case recCodepage:
			if b.biff5 && len(body) >= 2 {
				b.cp1252 = binary.LittleEndian.Uint16(body) == 1252
			}
		case recBoundSheet:
			if len(body) < 7 {
				continue
			}
			sr := b.text([][]byte{body[6:]})
			var name string
			if b.biff5 {
				name, _ = sr.bytesString(int(sr.u8()))
			} else {
				name, _ = sr.shortUnicode()
			}
			b.sheets = append(b.sheets, sheet{name: name, pos: binary.LittleEndian.Uint32(body)})
		case recSST:
			if !b.biff5 {
				b.parseSST(r.continued(body))
			}
		}
	}
}

func (b *Book) parseSST(segs [][]byte) {
	sr := b.text(segs)
	sr.u32() // total references
	unique := int(sr.u32())
	// Each string takes at least three bytes, which caps a forged count
	if limit := sr.remaining() / 3; unique > limit {
		unique = limit
	}
	b.sst = make([]string, 0, unique)
	for len(b.sst) < unique {
		s, err := sr.unicode()
		if err != nil {
			return
		}
		b.sst = append(b.sst, s)
	}
}

type cell struct {
	row, col uint16
	val      string
}

func (b *Book) parseSheet(pos uint32, maxRows, maxCols int) ([]cell, error) {
	if int64(pos) >= int64(len(b.stream)) {
		return nil, fmt.Errorf("%w: sheet outside the stream", ErrCorrupt)
	}
	r := &records{s: b.stream, pos: int(pos)}
	if id, _, ok := r.next(); !ok || id != recBOF {
		return nil, fmt.Errorf("%w: sheet has no BOF", ErrCorrupt)
	}
	var cells []cell
	var wide *WideRowError
	add := func(row, col uint16, val string) {
		if int(row) >= maxRows || val == "" && int(col) >= maxCols {
			return
		}
		if int(col) >= maxCols {
			if wide == nil || int(row)+1 < wide.Row {
				wide = &WideRowError{Row: int(row) + 1, Cols: int(col) + 1}
			} else if int(row)+1 == wide.Row {
				wide.Cols = max(wide.Cols, int(col)+1)
			}
			return
		}
		cells = append(cells, cell{row, col, val})
	}
	// An embedded chart nests its own BOF..EOF inside the sheet
	depth := 1
	var pending *cell
	for depth > 0 {
		if len(cells) > maxCells {
			return nil, ErrTooManyCells
		}
		id, body, ok := r.next()
		if !ok {
			break
		}
		switch id {
		case recBOF:
			depth++
			continue
		case recEOF:
			depth--
			continue
		}
		if depth != 1 {
			continue
		}
		switch id {
		case recString, recShrFmla, recArray, recTable:
			// These sit between a FORMULA and the STRING holding its text
		default:
			pending = nil
		}
		if len(body) < 6 && id != recString {
			continue
		}
		var row, col uint16
		if len(body) >= 4 {
			row = binary.LittleEndian.Uint16(body)
			col = binary.LittleEndian.Uint16(body[2:])
		}
		switch id {
		case recLabelSST:
			if len(body) < 10 {
				continue
			}
			if i := binary.LittleEndian.Uint32(body[6:]); int64(i) < int64(len(b.sst)) {
				add(row, col, b.sst[i])
			}
		case recLabel, recRString:
			add(row, col, b.labelText(r.continued(body[6:])))
		case recNumber:
			if len(body) < 14 {
				continue
			}
			add(row, col, formatFloat(math.Float64frombits(binary.LittleEndian.Uint64(body[6:]))))
		case recRK:
			if len(body) < 10 {
				continue
			}
			add(row, col, rkString(binary.LittleEndian.Uint32(body[6:])))
		case recMulRK:
			n := (len(body) - 6) / 6
			for k := 0; k < n && int(col)+k <= math.MaxUint16; k++ {
				off := 4 + 6*k
				add(row, col+uint16(k), rkString(binary.LittleEndian.Uint32(body[off+2:])))
			}
		case recFormula:
			if len(body) < 14 {
				continue
			}
			v := body[6:14]
			if v[6] != 0xff || v[7] != 0xff {
				add(row, col, formatFloat(math.Float64frombits(binary.LittleEndian.Uint64(v))))
				continue
			}
			switch v[0] {
			case 0: // the text follows in a STRING record
				pending = &cell{row: row, col: col}
			case 1:
				add(row, col, boolString(v[2]))
			case 2:
				add(row, col, errorString(v[2]))
			}
		case recString:
			if pending != nil {
				add(pending.row, pending.col, b.labelText(r.continued(body)))
				pending = nil
			}
		case recBoolErr:
			if len(body) < 8 {
				continue
			}
			if body[7] != 0 {
				add(row, col, errorString(body[6]))
			} else {
				add(row, col, boolString(body[6]))
			}
		}
	}
	if wide != nil {
		return nil, wide
	}
	return cells, nil
}

// labelText reads the text of a LABEL or STRING record: a 16-bit count,
// then BIFF8's option byte or BIFF5's 8-bit characters.
func (b *Book) labelText(segs [][]byte) string {
	sr := b.text(segs)
	var s string
	if b.biff5 {
		s, _ = sr.bytesString(int(sr.u16()))
	} else {
		s, _ = sr.longUnicode()
	}
	return s
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// rkString decodes an RK number: a signed 30-bit integer or the top 30 bits
// of a double, either of them possibly scaled by 100.
func rkString(rk uint32) string {
	if rk&2 != 0 {
		i := int64(int32(rk) >> 2)
		if rk&1 != 0 {
			return formatFloat(float64(i) / 100)
		}
		return strconv.FormatInt(i, 10)
	}
	f := math.Float64frombits(uint64(rk>>2) << 34)
	if rk&1 != 0 {
		f /= 100
	}
	return formatFloat(f)
}

func boolString(v byte) string {
	if v != 0 {
		return "TRUE"
	}
	return "FALSE"
}

func errorString(code byte) string {
	switch code {
	case 0x00:
		return "#NULL!"
	case 0x07:
		return "#DIV/0!"
	case 0x0f:
		return "#VALUE!"
	case 0x17:
		return "#REF!"
	case 0x1d:
		return "#NAME?"
	case 0x24:
		return "#NUM!"
	case 0x2a:
		return "#N/A"
	}
	return "#ERR!"
}

// cp1252 holds Windows-1252's 0x80-0x9F, where it parts from Latin-1;
// the five bytes it leaves unassigned stay as they are.
var cp1252 = [32]uint16{
	0x20ac, 0x81, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
	0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8d, 0x017d, 0x8f,
	0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
	0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x9d, 0x017e, 0x0178,
}

// segReader reads across a record and its CONTINUE records. In BIFF8, text
// split across a boundary restarts with a fresh option byte; anything else
// carries on as plain bytes, as BIFF5 text does too.
type segReader struct {
	segs   [][]byte
	si     int
	off    int
	err    error
	biff5  bool
	cp1252 bool
}

var errShort = errors.New("short read")

func (s *segReader) remaining() int {
	n := 0
	for i := s.si; i < len(s.segs); i++ {
		n += len(s.segs[i])
	}
	return n - s.off
}

func (s *segReader) advance() bool {
	for s.si < len(s.segs) && s.off >= len(s.segs[s.si]) {
		s.si++
		s.off = 0
	}
	return s.si < len(s.segs)
}

func (s *segReader) u8() byte {
	if s.err != nil || !s.advance() {
		s.err = errShort
		return 0
	}
	v := s.segs[s.si][s.off]
	s.off++
	return v
}

func (s *segReader) u16() uint16 {
	return uint16(s.u8()) | uint16(s.u8())<<8
}

func (s *segReader) u32() uint32 {
	return uint32(s.u16()) | uint32(s.u16())<<16
}

func (s *segReader) skip(n int) {
	for n > 0 && s.err == nil {
		if !s.advance() {
			s.err = errShort
			return
		}
		k := min(n, len(s.segs[s.si])-s.off)
		s.off += k
		n -= k
	}
}

// byteUnit is one 8-bit character as UTF-16: Latin-1 for BIFF8's
// compressed text, the codepage's for BIFF5's.
func (s *segReader) byteUnit(c byte) uint16 {
	if s.biff5 && s.cp1252 && c >= 0x80 && c < 0xa0 {
		return cp1252[c-0x80]
	}
	return uint16(c)
}

// chars reads n characters, one byte or UTF-16 each.
func (s *segReader) chars(n int, wide bool) (string, error) {
	if n > s.remaining() {
		return "", errShort
	}
	var sb strings.Builder
	units := make([]uint16, 0, min(n, 1024))
	for n > 0 && s.err == nil {
		if !s.advance() {
			s.err = errShort
			break
		}
		seg := s.segs[s.si]
		if wide {
			for n > 0 && s.off+1 < len(seg) {
				units = append(units, binary.LittleEndian.Uint16(seg[s.off:]))
				s.off += 2
				n--
			}
		} else {
			for n > 0 && s.off < len(seg) {
				units = append(units, s.byteUnit(seg[s.off]))
				s.off++
				n--
			}
		}
		if len(units) >= 1024 || n == 0 {
			sb.WriteString(string(utf16.Decode(units)))
			units = units[:0]
		}
		if n > 0 {
			s.si++
			s.off = 0
			if s.si >= len(s.segs) {
				s.err = errShort
				break
			}
			if !s.biff5 {
				// BIFF8 text continues with an option byte of its own
				wide = s.u8()&0x01 != 0
			}
		}
	}
	if len(units) > 0 {
		sb.WriteString(string(utf16.Decode(units)))
	}
	return sb.String(), s.err
}

// unicode reads an SST entry: XLUnicodeRichExtendedString.
func (s *segReader) unicode() (string, error) {
	n := int(s.u16())
	flags := s.u8()
	runs := 0
	if flags&0x08 != 0 {
		runs = int(s.u16())
	}
	ext := 0
	if flags&0x04 != 0 {
		ext = int(int32(s.u32()))
		if ext < 0 {
			return "", errShort
		}
	}
	if s.err != nil {
		return "", s.err
	}
	str, err := s.chars(n, flags&0x01 != 0)
	if err != nil {
		return "", err
	}
	s.skip(4*runs + ext)
	return str, s.err
}

// longUnicode reads an XLUnicodeString, a 16-bit count and an option byte.
func (s *segReader) longUnicode() (string, error) {
	n := int(s.u16())
	flags := s.u8()
	if s.err != nil {
		return "", s.err
	}
	return s.chars(n, flags&0x01 != 0)
}

// shortUnicode reads a ShortXLUnicodeString, an 8-bit count and an option
// byte.
func (s *segReader) shortUnicode() (string, error) {
	n := int(s.u8())
	flags := s.u8()
	if s.err != nil {
		return "", s.err
	}
	return s.chars(n, flags&0x01 != 0)
}

// bytesString reads n characters of BIFF5's 8-bit text.
func (s *segReader) bytesString(n int) (string, error) {
	return s.chars(n, false)
}
