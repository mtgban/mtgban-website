// Package metricsreport holds the admin Metrics section's rules and the
// cache of the queries behind them.
package metricsreport

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

const (
	stampEvery      = time.Minute
	minEntries      = 2048 // the floor of a cache's size, which otherwise follows the registry
	defaultLoadMax  = 30 * time.Second
	defaultStampMax = 5 * time.Second
)

// ErrType is returned to a caller that joined a load of another type for its key.
var ErrType = errors.New("metricsreport: cached value has another type for this key")

// Key names one cached load. Every field is validated before it gets here.
type Key struct {
	Report   string // bundle, tiers, visits, week, silent, stock, health, through, instances, name, hours
	Instance string
	Days     int
	Signed   bool
	Humans   bool
	Shift    int    // days To is moved back; 7 for the digest's earlier snapshot
	Name     string // a registry name or area, for the per-name loads
	To       string // the load's last day as 2006-01-02, "" when it has none
}

// Cache keeps report query results until the fold stamp moves, one load per key at a time.
type Cache struct {
	stamp      func(context.Context) (string, error)
	now        func() time.Time
	maxEntries int
	loadMax    time.Duration // deadline of one shared load; zero means defaultLoadMax
	stampMax   time.Duration // deadline of one stamp query; zero means defaultStampMax
	joined     func()        // test hook, called under mu when a caller joins a load

	mu        sync.Mutex
	entries   map[Key]*entry
	lastCheck time.Time
	checked   bool
	known     string
	haveKnown bool
}

type entry struct {
	val      any
	has      bool
	loadedAt time.Time
	call     *call
	err      error         // a remembered failure, served until failedAt plus failFor
	failedAt time.Time     // when err was remembered
	failFor  time.Duration // how long a failure of this key is remembered; zero is not at all
}

type call struct {
	done chan struct{}
	val  any
	err  error
}

// NewCache takes the stamp to watch and the clock.
func NewCache(stamp func(context.Context) (string, error), now func() time.Time) *Cache {
	return &Cache{
		stamp:      stamp,
		now:        now,
		maxEntries: max(minEntries, 6*len(observability.All())),
		loadMax:    defaultLoadMax,
		stampMax:   defaultStampMax,
		entries:    map[Key]*entry{},
	}
}

// Load returns the cached value for k, running load once when there is none.
func Load[T any](ctx context.Context, c *Cache, k Key, load func(context.Context) (T, error)) (T, error) {
	return LoadFor(ctx, c, k, 0, load)
}

// LoadFor is Load for a value good for at most maxAge; zero means until the fold stamp moves.
func LoadFor[T any](ctx context.Context, c *Cache, k Key, maxAge time.Duration, load func(context.Context) (T, error)) (T, error) {
	return LoadRemembering(ctx, c, k, maxAge, 0, load)
}

// LoadRemembering is LoadFor that also remembers a failed load of k for failFor, returning its
// error without loading again until then, so a slow database is not asked on every reload.
// A caller whose context is already done gets its error and starts no load.
func LoadRemembering[T any](ctx context.Context, c *Cache, k Key, maxAge, failFor time.Duration, load func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if c == nil {
		return load(ctx)
	}
	c.checkStamp(ctx)

	c.mu.Lock()
	e := c.entries[k]
	if e == nil {
		if len(c.entries) >= c.maxEntries {
			c.entries = map[Key]*entry{}
		}
		e = &entry{}
		c.entries[k] = e
	}
	if e.err != nil && e.call == nil {
		if c.now().Sub(e.failedAt) < e.failFor {
			err := e.err
			c.mu.Unlock()
			return zero, err
		}
		e.err = nil
	}
	e.failFor = failFor
	if e.has && e.call == nil && (maxAge <= 0 || c.now().Sub(e.loadedAt) < maxAge) {
		if v, ok := e.val.(T); ok {
			c.mu.Unlock()
			return v, nil
		}
	}
	cl := e.call
	if cl != nil {
		if c.joined != nil {
			c.joined()
		}
	} else {
		cl = &call{done: make(chan struct{})}
		e.call = cl
		go c.run(ctx, k, e, cl, func(lctx context.Context) (any, error) {
			return load(lctx)
		})
	}
	c.mu.Unlock()

	select {
	case <-cl.done:
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	if cl.err != nil {
		return zero, cl.err
	}
	v, ok := cl.val.(T)
	if !ok {
		return zero, ErrType
	}
	return v, nil
}

// run does one load for every waiter of cl; a success is stored while its entry is current, and a
// failure removes it, unless its key remembers failures, when the entry keeps the error.
func (c *Cache) run(ctx context.Context, k Key, e *entry, cl *call, load func(context.Context) (any, error)) {
	start := c.now()
	limit := c.loadMax
	if limit <= 0 {
		limit = defaultLoadMax
	}
	// Shared by callers, so detached from each; the deadline is wall time, as a context's must be.
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), limit)
	defer func() {
		cancel()
		if r := recover(); r != nil {
			cl.val, cl.err = nil, fmt.Errorf("metricsreport: load %s panicked: %v\n%s", k.Report, r, debug.Stack())
		}
		c.mu.Lock()
		e.call = nil
		if c.entries[k] == e {
			switch {
			case cl.err == nil:
				e.val, e.has, e.loadedAt = cl.val, true, start
			case e.failFor > 0:
				e.val, e.has, e.err, e.failedAt = nil, false, cl.err, c.now()
			default:
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
		close(cl.done)
	}()
	cl.val, cl.err = load(lctx)
}

// checkStamp asks the stamp at most once per stampEvery and empties the map when it moved.
func (c *Cache) checkStamp(ctx context.Context) {
	if c.stamp == nil {
		return
	}
	c.mu.Lock()
	now := c.now()
	if c.checked && now.Sub(c.lastCheck) < stampEvery {
		c.mu.Unlock()
		return
	}
	c.checked, c.lastCheck = true, now
	c.mu.Unlock()

	limit := c.stampMax
	if limit <= 0 {
		limit = defaultStampMax
	}
	// never past the caller's own deadline, so the check cannot hold a request beyond it
	if dl, ok := ctx.Deadline(); ok {
		limit = min(limit, time.Until(dl))
	}
	if limit <= 0 {
		return
	}
	// Detached so a cancelled request does not skip the minute's check; wall-time deadline.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), limit)
	s, err := c.stamp(sctx)
	cancel()
	if err != nil {
		return
	}
	c.mu.Lock()
	if c.haveKnown && s != c.known {
		c.entries = map[Key]*entry{}
	}
	c.known, c.haveKnown = s, true
	c.mu.Unlock()
}

// Drop empties the cache.
func (c *Cache) Drop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = map[Key]*entry{}
	c.mu.Unlock()
}
