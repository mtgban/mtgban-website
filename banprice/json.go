package banprice

import (
	"encoding/json"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"unicode/utf8"
)

// Writer writes a V2 a card at a time, exactly as encoding/json encodes it,
// keys sorted and HTML escaped: a full dump is never held in memory whole,
// and its first cards leave before the last are made. Cards must come in id
// order, as encoding/json sorts them.
//
// A price JSON cannot carry, NaN or an infinity, is refused as encoding/json
// refuses it, but only once the cards before it have been written.
type Writer struct {
	w      io.Writer
	prefix string
	cards  int
	buf    []byte
	keys   [2][]string
}

// NewWriter writes to w, opening the map with prefix before the first card.
func NewWriter(w io.Writer, prefix string) *Writer {
	return &Writer{w: w, prefix: prefix}
}

// Card writes one card's prices, finish to store to entries.
func (cw *Writer) Card(id string, finishes map[string]map[string][]Entry) error {
	cw.buf = cw.buf[:0]
	if cw.cards == 0 {
		cw.buf = append(cw.buf, cw.prefix...)
		cw.buf = append(cw.buf, '{')
	} else {
		cw.buf = append(cw.buf, ',')
	}
	cw.buf = appendString(cw.buf, id)
	cw.buf = append(cw.buf, ':')
	var err error
	cw.buf, err = appendFinishes(cw.buf, finishes, &cw.keys)
	if err != nil {
		return err
	}
	cw.cards++
	_, err = cw.w.Write(cw.buf)
	return err
}

// Close ends the map, if a card opened it.
func (cw *Writer) Close() error {
	if cw.cards == 0 {
		return nil
	}
	_, err := io.WriteString(cw.w, "}")
	return err
}

// WriteJSON writes v through a Writer, as encoding/json encodes it.
func (v V2) WriteJSON(w io.Writer) error {
	if v == nil {
		_, err := io.WriteString(w, "null")
		return err
	}
	if len(v) == 0 {
		_, err := io.WriteString(w, "{}")
		return err
	}
	cw := NewWriter(w, "")
	for _, id := range slices.Sorted(maps.Keys(v)) {
		err := cw.Card(id, v[id])
		if err != nil {
			return err
		}
	}
	return cw.Close()
}

// appendFinishes takes the slices it sorts keys in, so a whole document
// sorts them in two slices rather than one per card and finish.
func appendFinishes(b []byte, finishes map[string]map[string][]Entry, keys *[2][]string) ([]byte, error) {
	if finishes == nil {
		return append(b, "null"...), nil
	}
	var err error
	b = append(b, '{')
	keys[0] = sortedKeys(keys[0], finishes)
	for i, finish := range keys[0] {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, finish)
		b = append(b, ':')
		stores := finishes[finish]
		if stores == nil {
			b = append(b, "null"...)
			continue
		}
		b = append(b, '{')
		keys[1] = sortedKeys(keys[1], stores)
		for j, store := range keys[1] {
			if j > 0 {
				b = append(b, ',')
			}
			b = appendString(b, store)
			b = append(b, ':')
			b, err = appendEntries(b, stores[store])
			if err != nil {
				return nil, err
			}
		}
		b = append(b, '}')
	}
	return append(b, '}'), nil
}

// sortedKeys answers m's keys sorted, in keys' storage.
func sortedKeys[T any](keys []string, m map[string]T) []string {
	keys = keys[:0]
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// entryFields is Entry's fields as appendEntries writes them. Converting an
// Entry to it compiles only while the two agree, so a field added to Entry
// breaks the build here instead of vanishing from the output.
type entryFields struct {
	Condition string
	Price     float64
	Qty       int
	Available int
}

var _ = entryFields(Entry{})

func appendEntries(b []byte, entries []Entry) ([]byte, error) {
	if entries == nil {
		return append(b, "null"...), nil
	}
	var err error
	b = append(b, '[')
	for i, e := range entries {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '{')
		if e.Condition != "" {
			b = append(b, `"condition":`...)
			b = appendString(b, e.Condition)
			b = append(b, ',')
		}
		b = append(b, `"price":`...)
		b, err = appendFloat(b, e.Price)
		if err != nil {
			return nil, err
		}
		if e.Qty != 0 {
			b = append(b, `,"qty":`...)
			b = strconv.AppendInt(b, int64(e.Qty), 10)
		}
		if e.Available != 0 {
			b = append(b, `,"available":`...)
			b = strconv.AppendInt(b, int64(e.Available), 10)
		}
		b = append(b, '}')
	}
	return append(b, ']'), nil
}

// appendString quotes s as encoding/json does, handing it anything that
// needs escaping, which ids, finishes and store tags almost never do.
func appendString(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= utf8.RuneSelf || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			quoted, _ := json.Marshal(s)
			return append(b, quoted...)
		}
	}
	b = append(b, '"')
	b = append(b, s...)
	return append(b, '"')
}

// appendFloat formats f as encoding/json does: the shortest representation,
// in exponent form only for the very small and the very large.
func appendFloat(b []byte, f float64) ([]byte, error) {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, &json.UnsupportedValueError{Str: strconv.FormatFloat(f, 'g', -1, 64)}
	}
	format := byte('f')
	abs := math.Abs(f)
	if abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	b = strconv.AppendFloat(b, f, format, -1, 64)
	if format == 'e' {
		// e-09 to e-9
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b, nil
}
