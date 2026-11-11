package observability

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"
)

const (
	defaultMaxKeys = 50_000           // keys held across all pending minutes
	chunkRows      = 6000             // rows per UpsertMinutes call
	staleAfter     = 30 * time.Minute // pending minutes older than this are dropped
)

// Dims are the dimensions every counted row carries.
type Dims struct {
	Instance, Tier, Device string
	Signed, Bot            bool
}

// Row is one key's count for one minute.
type Row struct {
	Dims
	Scope, Name, Value string
	N                  int64
}

// CounterStore writes a minute's rows, adding to any already stored.
type CounterStore interface {
	UpsertMinutes(ctx context.Context, minute time.Time, rows []Row) error
}

// CounterStats reports the counter's health since it started.
type CounterStats struct {
	Dropped, FlushFailed, Flushed, Rejected int64
	LastFlush                               time.Time
}

type counterKey struct {
	Dims
	scope, name, value string
}

// Counter aggregates feature counts in memory and flushes them per minute.
type Counter struct {
	store    CounterStore
	instance string
	now      func() time.Time
	maxKeys  int
	sem      chan struct{} // serialises flushes

	mu      sync.Mutex
	pending map[time.Time]map[counterKey]int64
	keys    int // pending keys plus keys in flight that may come back
	closed  bool
	stats   CounterStats
	// Amounts not yet moved into a metrics.* row.
	dropSince, failSince, rejectSince int64
}

// NewCounter builds a Counter writing to store under instance.
func NewCounter(store CounterStore, instance string, now func() time.Time) *Counter {
	return &Counter{
		store:    store,
		instance: instance,
		now:      now,
		maxKeys:  defaultMaxKeys,
		sem:      make(chan struct{}, 1),
		pending:  map[time.Time]map[counterKey]int64{},
	}
}

// Add counts n for the key in the current minute. It never blocks on I/O.
func (c *Counter) Add(d Dims, scope, name, value string, n int64) {
	if c == nil || n <= 0 {
		return
	}
	minute := c.now().UTC().Truncate(time.Minute)
	k := counterKey{Dims: d, scope: scope, name: name, value: value}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	m := c.pending[minute]
	if _, ok := m[k]; !ok && c.keys >= c.maxKeys {
		c.stats.Dropped++
		c.dropSince++
		return
	}
	c.addLocked(minute, k, n)
}

// Reject counts one value the registry refused, written as metrics.rejected.
func (c *Counter) Reject() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.stats.Rejected++
	c.rejectSince++
}

// Flush writes every pending minute before the current one.
func (c *Counter) Flush(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.flush(ctx, false)
}

// Run flushes every interval until ctx is done.
func (c *Counter) Run(ctx context.Context, every time.Duration) {
	if c == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.runOnce(ctx, every)
		}
	}
}

func (c *Counter) runOnce(ctx context.Context, every time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, every)
	defer cancel()
	if err := c.safeFlush(ctx, false); err != nil {
		log.Println("observability: counter flush:", err)
	}
}

// Close flushes everything once, the current minute included, bounded by ctx.
// Add is a no-op afterwards, and a second Close returns nil.
func (c *Counter) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- c.safeFlush(ctx, true) }()
	select {
	case err := <-done:
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats returns the counter's totals.
func (c *Counter) Stats() CounterStats {
	if c == nil {
		return CounterStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// safeFlush turns a panic in a flush into an error, so its goroutine survives.
func (c *Counter) safeFlush(ctx context.Context, final bool) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("counter flush panic: %v", p)
		}
	}()
	return c.flush(ctx, final)
}

type minuteRows struct {
	minute time.Time
	rows   []Row
}

func (c *Counter) flush(ctx context.Context, final bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.sem }()

	now := c.now().UTC()
	batches := sortedRows(c.take(now.Truncate(time.Minute), final))
	for i, b := range batches {
		for start := 0; start < len(b.rows); start += chunkRows {
			end := min(start+chunkRows, len(b.rows))
			panicked, err := c.upsert(ctx, b.minute, b.rows[start:end])
			if err != nil {
				unsent := append([]minuteRows{{b.minute, b.rows[start:]}}, batches[i+1:]...)
				// At-least-once: a cancel landing after the server committed re-sends this chunk.
				if panicked {
					c.drop(unsent)
				} else {
					c.putBack(unsent)
				}
				return err
			}
			c.mu.Lock()
			c.stats.Flushed += int64(end - start)
			c.keys -= end - start
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	c.stats.LastFlush = now
	c.mu.Unlock()
	return nil
}

// upsert calls the store, turning a panic into an error.
func (c *Counter) upsert(ctx context.Context, minute time.Time, rows []Row) (panicked bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			panicked, err = true, fmt.Errorf("counter store panic: %v", p)
		}
	}()
	return false, c.store.UpsertMinutes(ctx, minute, rows)
}

type minuteKeys struct {
	minute time.Time
	keys   map[counterKey]int64
}

// take adds the counter's own rows and detaches the minutes to send.
// Their keys stay counted in c.keys until sent, dropped or merged back.
func (c *Counter) take(current time.Time, final bool) []minuteKeys {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := current.Add(-staleAfter)
	for m, keys := range c.pending {
		if m.Before(cutoff) {
			c.stats.Dropped += int64(len(keys))
			c.dropSince += int64(len(keys))
			c.keys -= len(keys)
			delete(c.pending, m)
		}
	}

	last := current.Add(-time.Minute)
	own := Dims{Instance: c.instance, Device: "job"}
	c.addLocked(last, counterKey{Dims: own, name: "metrics.flush"}, 1)
	for name, n := range map[string]int64{
		"metrics.dropped":    c.dropSince,
		"metrics.flush_fail": c.failSince,
		"metrics.rejected":   c.rejectSince,
	} {
		if n > 0 {
			c.addLocked(last, counterKey{Dims: own, name: name}, n)
		}
	}
	c.dropSince, c.failSince, c.rejectSince = 0, 0, 0

	var out []minuteKeys
	for m, keys := range c.pending {
		if final || m.Before(current) {
			out = append(out, minuteKeys{m, keys})
			delete(c.pending, m)
		}
	}
	return out
}

// sortedRows turns detached minutes into sorted rows, outside the lock.
func sortedRows(taken []minuteKeys) []minuteRows {
	slices.SortFunc(taken, func(a, b minuteKeys) int { return a.minute.Compare(b.minute) })
	out := make([]minuteRows, 0, len(taken))
	for _, t := range taken {
		rows := make([]Row, 0, len(t.keys))
		for k, n := range t.keys {
			rows = append(rows, Row{Dims: k.Dims, Scope: k.scope, Name: k.name, Value: k.value, N: n})
		}
		slices.SortFunc(rows, compareRows)
		out = append(out, minuteRows{t.minute, rows})
	}
	return out
}

// putBack returns unsent rows to pending after a failed upsert.
func (c *Counter) putBack(unsent []minuteRows) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.FlushFailed++
	c.failSince++
	for _, b := range unsent {
		m := c.pending[b.minute]
		if m == nil {
			m = map[counterKey]int64{}
			c.pending[b.minute] = m
		}
		for _, r := range b.rows {
			k := counterKey{Dims: r.Dims, scope: r.Scope, name: r.Name, value: r.Value}
			if _, ok := m[k]; ok {
				c.keys-- // merged: the in-flight count is released
			}
			m[k] += r.N
		}
	}
}

// drop counts unsent rows as dropped after the store panicked.
func (c *Counter) drop(unsent []minuteRows) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.FlushFailed++
	c.failSince++
	for _, b := range unsent {
		c.stats.Dropped += int64(len(b.rows))
		c.dropSince += int64(len(b.rows))
		c.keys -= len(b.rows)
	}
}

// addLocked adds n to a key with no cap check; c.mu must be held.
func (c *Counter) addLocked(minute time.Time, k counterKey, n int64) {
	m := c.pending[minute]
	if m == nil {
		m = map[counterKey]int64{}
		c.pending[minute] = m
	}
	if _, ok := m[k]; !ok {
		c.keys++
	}
	m[k] += n
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// compareRows orders rows by instance, tier, device, signed, bot, scope, name, value.
func compareRows(a, b Row) int {
	return cmp.Or(
		cmp.Compare(a.Instance, b.Instance),
		cmp.Compare(a.Tier, b.Tier),
		cmp.Compare(a.Device, b.Device),
		compareBool(a.Signed, b.Signed),
		compareBool(a.Bot, b.Bot),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Value, b.Value),
	)
}
