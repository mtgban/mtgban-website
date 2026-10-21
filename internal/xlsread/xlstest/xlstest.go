// Package xlstest writes small .xls files for tests: no .xls writer exists
// in the module graph, and the tests would otherwise need binary fixtures.
package xlstest

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	endOfChain = 0xfffffffe
	fatSector  = 0xfffffffd
	noStream   = 0xffffffff
	freeSect   = 0xffffffff
)

// Record encodes one BIFF record.
func Record(id uint16, body ...[]byte) []byte {
	var b []byte
	for _, part := range body {
		b = append(b, part...)
	}
	out := binary.LittleEndian.AppendUint16(nil, id)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(b)))
	return append(out, b...)
}

// U16 encodes a little-endian 16-bit field for Record.
func U16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

// U32 encodes a little-endian 32-bit field for Record.
func U32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// Container wraps a workbook stream in a compound file, as Excel stores it.
// The stream is padded to 4096 bytes so it lives in regular sectors.
func Container(name string, stream []byte) []byte {
	if len(stream) < 4096 {
		stream = append(stream, make([]byte, 4096-len(stream))...)
	}
	sectors := (len(stream) + 511) / 512
	if sectors > 126 {
		panic("xlstest: stream too large for one FAT sector")
	}

	header := make([]byte, 512)
	copy(header, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	binary.LittleEndian.PutUint16(header[24:], 0x3e)   // minor version
	binary.LittleEndian.PutUint16(header[26:], 3)      // major version
	binary.LittleEndian.PutUint16(header[28:], 0xfffe) // byte order
	binary.LittleEndian.PutUint16(header[30:], 9)      // 512-byte sectors
	binary.LittleEndian.PutUint16(header[32:], 6)      // 64-byte mini sectors
	binary.LittleEndian.PutUint32(header[44:], 1)      // FAT sectors
	binary.LittleEndian.PutUint32(header[48:], 1)      // directory start
	binary.LittleEndian.PutUint32(header[56:], 4096)   // mini stream cutoff
	binary.LittleEndian.PutUint32(header[60:], endOfChain)
	binary.LittleEndian.PutUint32(header[68:], endOfChain)
	for i := 0; i < 109; i++ {
		binary.LittleEndian.PutUint32(header[76+4*i:], freeSect)
	}
	binary.LittleEndian.PutUint32(header[76:], 0) // the FAT is sector 0

	// Sector 0 is the FAT, 1 the directory, then the stream's chain
	fat := make([]byte, 512)
	for i := 0; i < 128; i++ {
		binary.LittleEndian.PutUint32(fat[4*i:], freeSect)
	}
	binary.LittleEndian.PutUint32(fat[0:], fatSector)
	binary.LittleEndian.PutUint32(fat[4:], endOfChain)
	for i := 0; i < sectors; i++ {
		next := uint32(3 + i)
		if i == sectors-1 {
			next = endOfChain
		}
		binary.LittleEndian.PutUint32(fat[4*(2+i):], next)
	}

	dir := make([]byte, 512)
	entry(dir[0:], "Root Entry", 5, 1, endOfChain, 0)
	entry(dir[128:], name, 2, noStream, 2, uint64(len(stream)))
	entry(dir[256:], "", 0, noStream, 0, 0)
	entry(dir[384:], "", 0, noStream, 0, 0)

	out := append(header, fat...)
	out = append(out, dir...)
	out = append(out, stream...)
	if pad := len(out) % 512; pad != 0 {
		out = append(out, make([]byte, 512-pad)...)
	}
	return out
}

func entry(b []byte, name string, kind byte, child, start uint32, size uint64) {
	units := utf16.Encode([]rune(name))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	if name != "" {
		binary.LittleEndian.PutUint16(b[64:], uint16(2*len(units)+2))
	}
	b[66] = kind
	b[67] = 1 // black
	binary.LittleEndian.PutUint32(b[68:], noStream)
	binary.LittleEndian.PutUint32(b[72:], noStream)
	binary.LittleEndian.PutUint32(b[76:], child)
	binary.LittleEndian.PutUint32(b[116:], start)
	binary.LittleEndian.PutUint64(b[120:], size)
}

// BOF8 opens a BIFF8 substream: 0x0005 for the workbook globals, 0x0010 for
// a worksheet.
func BOF8(kind uint16) []byte {
	return Record(0x0809, U16(0x0600), U16(kind), make([]byte, 12))
}

// EOF closes a substream.
func EOF() []byte { return Record(0x000a) }

// Sheet is one worksheet's name and its cells, as rows of text.
type Sheet struct {
	Name string
	Rows [][]string
}

// Workbook writes sheets as a BIFF8 .xls, every non-empty cell a shared
// string.
func Workbook(sheets ...Sheet) []byte {
	var sst []string
	index := map[string]uint32{}
	bodies := make([][]byte, len(sheets))
	for i, s := range sheets {
		body := append(BOF8(0x0010), dimensions(s.Rows)...)
		for r, row := range s.Rows {
			for c, val := range row {
				if val == "" {
					continue
				}
				n, ok := index[val]
				if !ok {
					n = uint32(len(sst))
					index[val] = n
					sst = append(sst, val)
				}
				body = append(body, Record(0x00fd, U16(uint16(r)), U16(uint16(c)), U16(0), U32(n))...)
			}
		}
		bodies[i] = append(body, EOF()...)
	}
	return Container("Workbook", Globals(sheets, sst, bodies))
}

// dimensions is the DIMENSIONS record Excel writes after a sheet's BOF,
// the range its cells take up. Readers that rely on it skip the first cell
// of a sheet without one.
func dimensions(rows [][]string) []byte {
	cols := 0
	for _, row := range rows {
		cols = max(cols, len(row))
	}
	return Record(0x0200, U32(0), U32(uint32(len(rows))), U16(0), U16(uint16(cols)), U16(0))
}

// Globals lays out the workbook globals, with each BOUNDSHEET pointing at
// its sheet's body, and appends the bodies.
func Globals(sheets []Sheet, sst []string, bodies [][]byte) []byte {
	head := BOF8(0x0005)
	var table []byte
	if len(sst) > 0 {
		table = SST(sst)
	}
	size := len(head) + len(table) + len(EOF())
	for _, s := range sheets {
		size += len(boundSheet(0, s.Name))
	}
	out := head
	pos := size
	for i, s := range sheets {
		out = append(out, boundSheet(uint32(pos), s.Name)...)
		pos += len(bodies[i])
	}
	out = append(out, table...)
	out = append(out, EOF()...)
	for _, b := range bodies {
		out = append(out, b...)
	}
	return out
}

func boundSheet(pos uint32, name string) []byte {
	return Record(0x0085, U32(pos), []byte{0, 0}, ShortString(name))
}

// SST writes a shared-string table, splitting it into CONTINUE records the
// way Excel does once it passes 8224 bytes.
func SST(strs []string) []byte {
	const limit = 8224
	segs := [][]byte{append(U32(uint32(len(strs))), U32(uint32(len(strs)))...)}
	for _, s := range strs {
		units := utf16.Encode([]rune(s))
		wide := false
		for _, u := range units {
			if u > 0xff {
				wide = true
			}
		}
		head := U16(uint16(len(units)))
		if wide {
			head = append(head, 1)
		} else {
			head = append(head, 0)
		}
		cur := &segs[len(segs)-1]
		if len(*cur)+len(head)+2 > limit {
			segs = append(segs, nil)
			cur = &segs[len(segs)-1]
		}
		*cur = append(*cur, head...)
		for _, u := range units {
			n := 1
			if wide {
				n = 2
			}
			if len(*cur)+n > limit {
				// Text split here restarts with its own option byte
				opt := byte(0)
				if wide {
					opt = 1
				}
				segs = append(segs, []byte{opt})
				cur = &segs[len(segs)-1]
			}
			if wide {
				*cur = binary.LittleEndian.AppendUint16(*cur, u)
			} else {
				*cur = append(*cur, byte(u))
			}
		}
	}
	out := Record(0x00fc, segs[0])
	for _, seg := range segs[1:] {
		out = append(out, Record(0x003c, seg)...)
	}
	return out
}

// ShortString encodes a ShortXLUnicodeString, an 8-bit count, compressed
// when it can be.
func ShortString(s string) []byte {
	units := utf16.Encode([]rune(s))
	return append([]byte{byte(len(units))}, chars(units)...)
}

// LongString encodes an XLUnicodeString, a 16-bit count, as LABEL and
// STRING carry it.
func LongString(s string) []byte {
	units := utf16.Encode([]rune(s))
	return append(U16(uint16(len(units))), chars(units)...)
}

// chars is the option byte and the characters after it.
func chars(units []uint16) []byte {
	for _, u := range units {
		if u > 0xff {
			out := []byte{1}
			for _, u := range units {
				out = binary.LittleEndian.AppendUint16(out, u)
			}
			return out
		}
	}
	out := []byte{0}
	for _, u := range units {
		out = append(out, byte(u))
	}
	return out
}
