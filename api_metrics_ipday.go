package main

import (
	"hash/maphash"
	"sync/atomic"
	"time"
)

// metricsPerAddressDay is the most one client address may add to one name in a UTC day.
// A reader's own day is far below it; it stops one address from moving a name's totals.
const metricsPerAddressDay = 1000

const (
	addressDayRows  = 4
	addressDayWidth = 1 << 16 // a power of two
)

// addressDay estimates what each address added to each name on one UTC day.
// It is a count-min sketch: its memory is fixed however many addresses post,
// and an estimate is never below the truth, so a collision can only cap early.
type addressDay struct {
	day   int64
	seed  maphash.Seed
	cells [addressDayRows][addressDayWidth]atomic.Uint32
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
// Two posts at once can pass the cap by at most one post's worth, which is fine for a bound.
func (a *addressDay) take(address, name string, n int64) int64 {
	h := maphash.String(a.seed, address+"\x00"+name)
	h1, h2 := uint32(h), uint32(h>>32)|1
	var at [addressDayRows]uint32
	est := uint32(metricsPerAddressDay)
	for i := range at {
		at[i] = (h1 + uint32(i)*h2) & (addressDayWidth - 1)
		est = min(est, a.cells[i][at[i]].Load())
	}
	n = min(n, int64(metricsPerAddressDay)-int64(est))
	if n <= 0 {
		return 0
	}
	for i, j := range at {
		a.cells[i][j].Add(uint32(n))
	}
	return n
}
