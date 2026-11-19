package main

import (
	"hash/maphash"
	"strconv"
	"sync/atomic"
	"time"
)

// metricsPerAddressDay is the most one client address may add to one name in a UTC day.
// A reader's own day is far below it; it stops one address from moving a name's totals.
const metricsPerAddressDay = 1000

// errorRowsPerAddressDay is the most new error rows one client address may start in a UTC day,
// one post's worth; a row it already started still adds. With feature_errors keeping 200 rows
// a day, filling the day takes 40 addresses, and no address can use up a script's rows.
const errorRowsPerAddressDay = metricsMaxErrorEntries

const (
	addressDayRows  = 4
	addressDayWidth = 1 << 16 // a power of two
)

// sketch is a count-min sketch: its memory is fixed however many keys it counts,
// and an estimate is never below the truth, so a collision can only cap early.
type sketch [addressDayRows][addressDayWidth]atomic.Uint32

// cells returns the cell of each row that key counts in.
func (s *sketch) cells(seed maphash.Seed, key string) (at [addressDayRows]uint32) {
	h := maphash.String(seed, key)
	h1, h2 := uint32(h), uint32(h>>32)|1
	for i := range at {
		at[i] = (h1 + uint32(i)*h2) & (addressDayWidth - 1)
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

// addressDay estimates what each address added to each name on one UTC day,
// and which error rows each address started.
type addressDay struct {
	day    int64
	seed   maphash.Seed
	names  sketch // address and name: what it added
	errors sketch // address and row: whether it started it; address alone: how many it started
}

// metricsAddressDay is today's sketch; a post on a new UTC day replaces it.
var metricsAddressDay atomic.Pointer[addressDay]

// metricsNow is the clock the daily cap reads.
var metricsNow = time.Now

// addressDayFor returns the sketch for now's UTC day, starting a fresh one when the day has turned.
func addressDayFor(now time.Time) *addressDay {
	day := now.UTC().Unix() / 86400
	for {
		cur := metricsAddressDay.Load()
		if cur != nil && cur.day == day {
			return cur
		}
		next := &addressDay{day: day, seed: maphash.MakeSeed()}
		if metricsAddressDay.CompareAndSwap(cur, next) {
			return next
		}
	}
}

// take returns how much of n the address may still add to name today, and counts it.
// Concurrent posts can pass the cap by up to metricsMaxCount each: about 200 with the limiter's burst of 20.
func (a *addressDay) take(address, name string, n int64) int64 {
	return a.names.take(a.seed, address+"\x00"+name, n, metricsPerAddressDay)
}

// mayAddErrorRow reports whether the address may add to an error row today: a row it already
// started always may, and a new one spends one of its errorRowsPerAddressDay.
// Concurrent posts can start one row past the budget each.
func (a *addressDay) mayAddErrorRow(address, device, build, script, class string, line int) bool {
	row := address + "\x01" + device + "\x00" + build + "\x00" + script + "\x00" + class + "\x00" + strconv.Itoa(line)
	if a.errors.seen(a.seed, row) {
		return true
	}
	if a.errors.take(a.seed, address+"\x02", 1, errorRowsPerAddressDay) == 0 {
		return false
	}
	a.errors.take(a.seed, row, 1, 1)
	return true
}
