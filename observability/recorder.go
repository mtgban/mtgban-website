package observability

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// store is the subset of *Client the recorder needs (lets tests fake it).
type store interface {
	InsertBatch(ctx context.Context, evs []Event) error
	RefreshRollup(ctx context.Context) error
}

type recorderCfg struct {
	bufferSize      int
	batchSize       int
	flushInterval   time.Duration
	refreshInterval time.Duration
}

func defaultRecorderCfg() recorderCfg {
	return recorderCfg{
		bufferSize:      4096,
		batchSize:       256, // batchSize * 5 must stay < 65535 (Postgres param limit)
		flushInterval:   5 * time.Second,
		refreshInterval: time.Hour,
	}
}

// Recorder buffers events and flushes them to the store off the request path.
type Recorder struct {
	ch      chan Event
	store   store
	cfg     recorderCfg
	dropped int64
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func newRecorder(s store, cfg recorderCfg) *Recorder {
	return &Recorder{
		ch:    make(chan Event, cfg.bufferSize),
		store: s,
		cfg:   cfg,
		done:  make(chan struct{}),
	}
}

func (r *Recorder) start() {
	r.wg.Add(2)
	go r.runFlush()
	go r.runRefresh()
}

// NewRecorder builds a Recorder with default config and starts its goroutine.
func NewRecorder(s store) *Recorder {
	r := newRecorder(s, defaultRecorderCfg())
	r.start()
	return r
}

// Record enqueues an event without blocking. A full buffer drops the event.
func (r *Recorder) Record(ev Event) {
	if r == nil {
		return
	}
	select {
	case r.ch <- ev:
	default:
		atomic.AddInt64(&r.dropped, 1)
	}
}

// Dropped returns the number of events dropped due to a full buffer.
func (r *Recorder) Dropped() int64 {
	if r == nil {
		return 0
	}
	return atomic.LoadInt64(&r.dropped)
}

// Close stops the goroutine after draining and flushing pending events.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() { close(r.done) })
	r.wg.Wait()
	return nil
}

func (r *Recorder) runFlush() {
	defer r.wg.Done()
	flushTicker := time.NewTicker(r.cfg.flushInterval)
	defer flushTicker.Stop()

	batch := make([]Event, 0, r.cfg.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					log.Println("observability: flush panic:", p)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := r.store.InsertBatch(ctx, batch); err != nil {
				log.Println("observability: insert batch:", err)
			}
		}()
		batch = batch[:0:0]
	}

	for {
		select {
		case ev := <-r.ch:
			batch = append(batch, ev)
			if len(batch) >= r.cfg.batchSize {
				flush()
			}
		case <-flushTicker.C:
			flush()
			if d := atomic.LoadInt64(&r.dropped); d > 0 {
				log.Printf("observability: dropped %d events (buffer full)", d)
			}
		case <-r.done:
			for {
				select {
				case ev := <-r.ch:
					batch = append(batch, ev)
					if len(batch) >= r.cfg.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (r *Recorder) runRefresh() {
	defer r.wg.Done()
	refreshTicker := time.NewTicker(r.cfg.refreshInterval)
	defer refreshTicker.Stop()
	for {
		select {
		case <-refreshTicker.C:
			func() {
				defer func() {
					if p := recover(); p != nil {
						log.Println("observability: refresh panic:", p)
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := r.store.RefreshRollup(ctx); err != nil {
					log.Println("observability: refresh rollup:", err)
				}
			}()
		case <-r.done:
			return
		}
	}
}
