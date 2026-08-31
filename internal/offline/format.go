// Package offline implements the offline mode price payload format,
// per user watermarking, and per set change fingerprints.
//
// Format layout (OFP1 binary payload):
//
//	u32 magic 0x4F465031 ("OFP1", big endian)
//	u8  format version (1)
//	u8  message type (1 full set; 2 reserved for deltas)
//	str set code
//	uv  snapshot unix seconds
//	uv  store count, then that many str (sorted shorthands; entries index into this)
//	uv  tag count, then that many str (sorted condition tags, e.g. "NM", "SP_foil")
//	section retail, then section buylist:
//	  uv uuid count
//	  per uuid (sorted):
//	    str uuid
//	    uv entry count
//	    per entry (sorted by store index):
//	      uv store index
//	      u8 flags: 1 regular, 2 foil, 4 etched, 8 sealed, 16 cond, 32 condmap, 64 qtymap, 128 baseqty
//	      for each set price flag (1,2,4,8): uv cents
//	      if baseqty: uv qty, uv qtyFoil, uv qtyEtched, uv qtySealed
//	      if cond: uv tag index
//	      if condmap: uv n, then n x (uv tag index, uv cents)
//	      if qtymap: uv n, then n x (uv tag index, uv qty)
//
//	str = uv byte length + UTF-8 bytes; uv = unsigned varint (encoding/binary);
//	cents = round(price * 100), negative prices clamp to 0.
//	Everything sorted so encoding is deterministic.
package offline

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	// FormatVersion is the wire version Encode stamps and Decode requires.
	FormatVersion = byte(1)
	// MsgTypeFull marks a full snapshot payload.
	MsgTypeFull = byte(1)
	// MsgTypeDelta is reserved so entry level deltas stay a non breaking add.
	MsgTypeDelta = byte(2)
)

var magic = []byte{0x4F, 0x46, 0x50, 0x31}

// PriceEntry is one card's regular and foil prices.
type PriceEntry struct {
	Regular float64
	Foil    float64
	Etched  float64
	Sealed  float64

	Cond string

	Qty       int
	QtyFoil   int
	QtyEtched int
	QtySealed int

	Conditions map[string]float64
	Quantities map[string]int
}

// SetPayload is one set's worth of prices, shaped uuid > store > entry.
type SetPayload struct {
	SetCode  string
	Snapshot time.Time

	Retail  map[string]map[string]*PriceEntry
	Buylist map[string]map[string]*PriceEntry
}

const (
	flagRegular = 1 << iota
	flagFoil
	flagEtched
	flagSealed
	flagCond
	flagCondMap
	flagQtyMap
	flagBaseQty
)

func cents(price float64) uint64 {
	if price <= 0 {
		return 0
	}
	return uint64(math.Round(price * 100))
}

func dollars(c uint64) float64 {
	return float64(c) / 100
}

type writer struct {
	buf bytes.Buffer
	tmp [binary.MaxVarintLen64]byte
}

func (w *writer) uv(v uint64) {
	n := binary.PutUvarint(w.tmp[:], v)
	w.buf.Write(w.tmp[:n])
}

func (w *writer) str(s string) {
	w.uv(uint64(len(s)))
	w.buf.WriteString(s)
}

// dictionaries collects the sorted store and tag dictionaries of a payload.
func dictionaries(p *SetPayload) (stores, tags []string) {
	storeSet := map[string]bool{}
	tagSet := map[string]bool{}
	for _, section := range []map[string]map[string]*PriceEntry{p.Retail, p.Buylist} {
		for _, byStore := range section {
			for store, e := range byStore {
				storeSet[store] = true
				if e.Cond != "" {
					tagSet[e.Cond] = true
				}
				for tag := range e.Conditions {
					tagSet[tag] = true
				}
				for tag := range e.Quantities {
					tagSet[tag] = true
				}
			}
		}
	}
	for s := range storeSet {
		stores = append(stores, s)
	}
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(stores)
	sort.Strings(tags)
	return stores, tags
}

// Encode packs a set's prices into the offline wire format.
func Encode(p *SetPayload) ([]byte, error) {
	stores, tags := dictionaries(p)
	storeIdx := map[string]uint64{}
	for i, s := range stores {
		storeIdx[s] = uint64(i)
	}
	tagIdx := map[string]uint64{}
	for i, t := range tags {
		tagIdx[t] = uint64(i)
	}

	w := &writer{}
	w.buf.Write(magic)
	w.buf.WriteByte(FormatVersion)
	w.buf.WriteByte(MsgTypeFull)
	w.str(p.SetCode)
	w.uv(uint64(p.Snapshot.Unix()))
	w.uv(uint64(len(stores)))
	for _, s := range stores {
		w.str(s)
	}
	w.uv(uint64(len(tags)))
	for _, t := range tags {
		w.str(t)
	}

	for _, section := range []map[string]map[string]*PriceEntry{p.Retail, p.Buylist} {
		if err := encodeSection(w, section, storeIdx, tagIdx, stores); err != nil {
			return nil, err
		}
	}
	return w.buf.Bytes(), nil
}

func encodeSection(w *writer, section map[string]map[string]*PriceEntry, storeIdx, tagIdx map[string]uint64, stores []string) error {
	uuids := make([]string, 0, len(section))
	for id := range section {
		uuids = append(uuids, id)
	}
	sort.Strings(uuids)

	w.uv(uint64(len(uuids)))
	for _, id := range uuids {
		w.str(id)
		byStore := section[id]
		entryStores := make([]string, 0, len(byStore))
		for s := range byStore {
			entryStores = append(entryStores, s)
		}
		sort.Slice(entryStores, func(i, j int) bool {
			return storeIdx[entryStores[i]] < storeIdx[entryStores[j]]
		})

		w.uv(uint64(len(entryStores)))
		for _, s := range entryStores {
			e := byStore[s]
			var flags byte
			if e.Regular > 0 {
				flags |= flagRegular
			}
			if e.Foil > 0 {
				flags |= flagFoil
			}
			if e.Etched > 0 {
				flags |= flagEtched
			}
			if e.Sealed > 0 {
				flags |= flagSealed
			}
			if e.Cond != "" {
				flags |= flagCond
			}
			if len(e.Conditions) > 0 {
				flags |= flagCondMap
			}
			if len(e.Quantities) > 0 {
				flags |= flagQtyMap
			}
			if e.Qty > 0 || e.QtyFoil > 0 || e.QtyEtched > 0 || e.QtySealed > 0 {
				flags |= flagBaseQty
			}

			w.uv(storeIdx[s])
			w.buf.WriteByte(flags)
			if flags&flagRegular != 0 {
				w.uv(cents(e.Regular))
			}
			if flags&flagFoil != 0 {
				w.uv(cents(e.Foil))
			}
			if flags&flagEtched != 0 {
				w.uv(cents(e.Etched))
			}
			if flags&flagSealed != 0 {
				w.uv(cents(e.Sealed))
			}
			if flags&flagBaseQty != 0 {
				w.uv(uint64(e.Qty))
				w.uv(uint64(e.QtyFoil))
				w.uv(uint64(e.QtyEtched))
				w.uv(uint64(e.QtySealed))
			}
			if flags&flagCond != 0 {
				w.uv(tagIdx[e.Cond])
			}
			if flags&flagCondMap != 0 {
				writeF64Map(w, e.Conditions, tagIdx)
			}
			if flags&flagQtyMap != 0 {
				writeIntMap(w, e.Quantities, tagIdx)
			}
		}
	}
	return nil
}

func sortedTags(m map[string]uint64, keys []string) []string {
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] < m[keys[j]] })
	return keys
}

func writeF64Map(w *writer, m map[string]float64, tagIdx map[string]uint64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	keys = sortedTags(tagIdx, keys)
	w.uv(uint64(len(keys)))
	for _, k := range keys {
		w.uv(tagIdx[k])
		w.uv(cents(m[k]))
	}
}

func writeIntMap(w *writer, m map[string]int, tagIdx map[string]uint64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	keys = sortedTags(tagIdx, keys)
	w.uv(uint64(len(keys)))
	for _, k := range keys {
		w.uv(tagIdx[k])
		w.uv(uint64(m[k]))
	}
}

type reader struct {
	buf *bytes.Reader
}

func (r *reader) uv() (uint64, error) {
	return binary.ReadUvarint(r.buf)
}

func (r *reader) str() (string, error) {
	n, err := r.uv()
	if err != nil {
		return "", err
	}
	if n > uint64(r.buf.Len()) {
		return "", errors.New("string length past end of buffer")
	}
	b := make([]byte, n)
	if _, err := r.buf.Read(b); err != nil {
		return "", err
	}
	return string(b), nil
}

// Decode unpacks what Encode produced.
func Decode(data []byte) (*SetPayload, error) {
	if len(data) < 6 || !bytes.Equal(data[:4], magic) {
		return nil, errors.New("bad magic")
	}
	if data[4] != FormatVersion {
		return nil, fmt.Errorf("unsupported format version %d", data[4])
	}
	if data[5] != MsgTypeFull {
		return nil, fmt.Errorf("unsupported message type %d", data[5])
	}
	r := &reader{buf: bytes.NewReader(data[6:])}

	p := &SetPayload{}
	var err error
	if p.SetCode, err = r.str(); err != nil {
		return nil, err
	}
	snap, err := r.uv()
	if err != nil {
		return nil, err
	}
	p.Snapshot = time.Unix(int64(snap), 0).UTC()

	stores, err := readDict(r)
	if err != nil {
		return nil, err
	}
	tags, err := readDict(r)
	if err != nil {
		return nil, err
	}

	if p.Retail, err = decodeSection(r, stores, tags); err != nil {
		return nil, err
	}
	if p.Buylist, err = decodeSection(r, stores, tags); err != nil {
		return nil, err
	}
	return p, nil
}

func readDict(r *reader) ([]string, error) {
	n, err := r.uv()
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i := range out {
		if out[i], err = r.str(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func decodeSection(r *reader, stores, tags []string) (map[string]map[string]*PriceEntry, error) {
	nUUID, err := r.uv()
	if err != nil {
		return nil, err
	}
	section := make(map[string]map[string]*PriceEntry, nUUID)
	for i := uint64(0); i < nUUID; i++ {
		id, err := r.str()
		if err != nil {
			return nil, err
		}
		nEntry, err := r.uv()
		if err != nil {
			return nil, err
		}
		byStore := make(map[string]*PriceEntry, nEntry)
		for j := uint64(0); j < nEntry; j++ {
			sIdx, err := r.uv()
			if err != nil {
				return nil, err
			}
			if sIdx >= uint64(len(stores)) {
				return nil, errors.New("store index out of range")
			}
			flagByte, err := r.buf.ReadByte()
			if err != nil {
				return nil, err
			}
			e := &PriceEntry{}
			for _, pf := range []struct {
				flag byte
				dst  *float64
			}{{flagRegular, &e.Regular}, {flagFoil, &e.Foil}, {flagEtched, &e.Etched}, {flagSealed, &e.Sealed}} {
				if flagByte&pf.flag != 0 {
					c, err := r.uv()
					if err != nil {
						return nil, err
					}
					*pf.dst = dollars(c)
				}
			}
			if flagByte&flagBaseQty != 0 {
				for _, dst := range []*int{&e.Qty, &e.QtyFoil, &e.QtyEtched, &e.QtySealed} {
					v, err := r.uv()
					if err != nil {
						return nil, err
					}
					*dst = int(v)
				}
			}
			if flagByte&flagCond != 0 {
				tIdx, err := r.uv()
				if err != nil {
					return nil, err
				}
				if tIdx >= uint64(len(tags)) {
					return nil, errors.New("tag index out of range")
				}
				e.Cond = tags[tIdx]
			}
			if flagByte&flagCondMap != 0 {
				m, err := readF64Map(r, tags)
				if err != nil {
					return nil, err
				}
				e.Conditions = m
			}
			if flagByte&flagQtyMap != 0 {
				m, err := readIntMap(r, tags)
				if err != nil {
					return nil, err
				}
				e.Quantities = m
			}
			byStore[stores[sIdx]] = e
		}
		section[id] = byStore
	}
	return section, nil
}

func readF64Map(r *reader, tags []string) (map[string]float64, error) {
	n, err := r.uv()
	if err != nil {
		return nil, err
	}
	m := make(map[string]float64, n)
	for i := uint64(0); i < n; i++ {
		tIdx, err := r.uv()
		if err != nil {
			return nil, err
		}
		c, err := r.uv()
		if err != nil {
			return nil, err
		}
		if tIdx >= uint64(len(tags)) {
			return nil, errors.New("tag index out of range")
		}
		m[tags[tIdx]] = dollars(c)
	}
	return m, nil
}

func readIntMap(r *reader, tags []string) (map[string]int, error) {
	n, err := r.uv()
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, n)
	for i := uint64(0); i < n; i++ {
		tIdx, err := r.uv()
		if err != nil {
			return nil, err
		}
		v, err := r.uv()
		if err != nil {
			return nil, err
		}
		if tIdx >= uint64(len(tags)) {
			return nil, errors.New("tag index out of range")
		}
		m[tags[tIdx]] = int(v)
	}
	return m, nil
}
