package offline

import (
	"encoding/binary"
	"hash/fnv"
)

// Fingerprint is an order independent hash of price tuples, used to detect
// whether a set's canonical data changed between snapshots.
type Fingerprint struct {
	xor   uint64
	count uint64
}

// Add folds one price row into the fingerprint.
func (f *Fingerprint) Add(uuid, store, tag string, cents uint64, qty int) {
	h := fnv.New64a()
	var nums [16]byte
	binary.BigEndian.PutUint64(nums[:8], cents)
	binary.BigEndian.PutUint64(nums[8:], uint64(qty))
	h.Write([]byte(uuid))
	h.Write([]byte{0})
	h.Write([]byte(store))
	h.Write([]byte{0})
	h.Write([]byte(tag))
	h.Write([]byte{0})
	h.Write(nums[:])
	f.xor ^= h.Sum64()
	f.count++
}

// Sum folds the count in so duplicate tuples still change the result.
func (f *Fingerprint) Sum() uint64 {
	return f.xor ^ (f.count * 0x9E3779B97F4A7C15)
}
