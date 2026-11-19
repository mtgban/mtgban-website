// Package dailycap caps what one client address adds in a UTC day, in
// memory of a fixed size.
package dailycap

import (
	"hash/maphash"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	sketchRows  = 4
	sketchWidth = 1 << 16 // a power of two
)

// sketch is a count-min sketch: its memory is fixed however many keys it counts,
// and an estimate is never below the truth, so a collision can only cap early.
// A key's estimate runs high by about everything counted over sketchWidth.
type sketch [sketchRows][sketchWidth]atomic.Uint32

// cells returns the cell of each row that key counts in.
func (s *sketch) cells(seed maphash.Seed, key string) (at [sketchRows]uint32) {
	h := maphash.String(seed, key)
	h1, h2 := uint32(h), uint32(h>>32)|1
	for i := range at {
		at[i] = (h1 + uint32(i)*h2) & (sketchWidth - 1)
	}
	return at
}

// take returns how much of n key may still add under limit, and counts it.
// Each concurrent take reads the estimate before the others add to it, so k at once
// can each pass and the total can go over limit by up to k times n.
func (s *sketch) take(seed maphash.Seed, key string, n, limit int64) int64 {
	at := s.cells(seed, key)
	est := uint32(limit)
	for i, j := range at {
		est = min(est, s[i][j].Load())
	}
	n = min(n, limit-int64(est))
	if n <= 0 {
		return 0
	}
	for i, j := range at {
		s[i][j].Add(uint32(n))
	}
	return n
}

// seen reports whether key may have been counted; a collision can say yes for a key never counted.
func (s *sketch) seen(seed maphash.Seed, key string) bool {
	for i, j := range s.cells(seed, key) {
		if s[i][j].Load() == 0 {
			return false
		}
	}
	return true
}

// Caps holds an address to perName added to each name a UTC day and to
// errorRows new error rows, in today's Day.
type Caps struct {
	perName, errorRows int64
	cur                atomic.Pointer[Day]
}

// New returns caps with nothing counted. A limit is a uint32, as a
// sketch's cells are.
func New(perName, errorRows uint32) *Caps {
	return &Caps{perName: int64(perName), errorRows: int64(errorRows)}
}

// Day estimates what each address added to each name on one UTC day,
// and which error rows each address started.
type Day struct {
	day                int64
	seed               maphash.Seed
	perName, errorRows int64
	names              sketch // address and name: what it added
	errors             sketch // address and row: whether it started it; address alone: how many it started
}

// For returns the Day for now's UTC day, starting a fresh one when the day has turned.
func (c *Caps) For(now time.Time) *Day {
	day := now.UTC().Unix() / 86400
	for {
		cur := c.cur.Load()
		if cur != nil && cur.day == day {
			return cur
		}
		next := &Day{day: day, seed: maphash.MakeSeed(), perName: c.perName, errorRows: c.errorRows}
		if c.cur.CompareAndSwap(cur, next) {
			return next
		}
	}
}

// Take returns how much of n the address may still add to name today, and counts it.
// Concurrent calls can pass the cap by up to their own n each.
func (a *Day) Take(address, name string, n int64) int64 {
	return a.names.take(a.seed, address+"\x00"+name, n, a.perName)
}

// MayAddErrorRow reports whether the address may add to an error row today: a row it already
// started always may, and a new one spends one of its error rows.
// Concurrent calls can start one row past the budget each.
func (a *Day) MayAddErrorRow(address, device, build, script, class string, line int) bool {
	row := address + "\x01" + device + "\x00" + build + "\x00" + script + "\x00" + class + "\x00" + strconv.Itoa(line)
	if a.errors.seen(a.seed, row) {
		return true
	}
	if a.errors.take(a.seed, address+"\x02", 1, a.errorRows) == 0 {
		return false
	}
	a.errors.take(a.seed, row, 1, 1)
	return true
}
