// Package joblog provides crash-resilient observability for a long-running
// Go process: cron/background job tracking, periodic heartbeats, and a tee
// of stdout/stderr (plus arbitrary tagged sources) into Postgres. Designed
// so a sudden process death doesn't take the diagnostic trail with it.
//
// Wiring sketch:
//
//	r := joblog.New(joblog.Config{
//	    DB:          sqlDB,
//	    BuildCommit: build.Commit,
//	    Notify:      myAlerter,
//	})
//	_ = r.EnsureSchemas(ctx)
//	r.StartCapture()                 // tee stdout/stderr into log_lines
//	r.StartLogPruner(14*24*time.Hour, 24*time.Hour)
//	r.StartHeartbeat(5 * time.Minute)
//	r.RunJob("my.cron", myCronFn)
package joblog

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/mackerelio/go-osstat/memory"
)

// NotifyFunc is the alerting callback shape. The third argument signals an
// urgent event (e.g. a panic) so the implementation can escalate.
type NotifyFunc func(kind, message string, alert bool)

// Config bundles the runner's construction-time dependencies. DB is the only
// required field; everything else has a sensible default.
type Config struct {
	DB          *sql.DB
	ReadOnly    bool       // skip DDL/INSERTs (useful when DB is a read replica)
	BuildCommit string     // recorded on every job_runs row
	Host        string     // defaults to os.Hostname()
	Notify      NotifyFunc // called on panic; nil disables alerting

	// Sink tuning. Zero values fall back to defaults.
	SinkCapacity  int           // bounded channel between capture and drainer (default 4096)
	BatchSize     int           // multi-INSERT row count (default 200)
	FlushInterval time.Duration // periodic flush even if batch not full (default 2s)
}

// Runner is the package's central handle. Construct one per process at boot.
type Runner struct {
	db          *sql.DB
	readOnly    bool
	host        string
	buildCommit string
	notify      NotifyFunc

	sink *dbLogSink

	// Original fd 1 / fd 2 are dup'd aside by StartCapture so the drainer's
	// own diagnostics don't recurse into the capture pipe.
	originalStdout *os.File
	originalStderr *os.File
}

// New returns a Runner. Safe to call before EnsureSchemas; methods that need
// the DB short-circuit when Config.DB is nil or Config.ReadOnly is true.
func New(cfg Config) *Runner {
	host := cfg.Host
	if host == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			host = h
		} else {
			host = "unknown"
		}
	}

	sinkCap := cfg.SinkCapacity
	if sinkCap <= 0 {
		sinkCap = 4096
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 200
	}
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = 2 * time.Second
	}

	r := &Runner{
		db:          cfg.DB,
		readOnly:    cfg.ReadOnly,
		host:        host,
		buildCommit: cfg.BuildCommit,
		notify:      cfg.Notify,
	}
	r.sink = newDBLogSink(r, sinkCap, batch, flush)
	return r
}

// Host returns the hostname recorded on each row. Exposed mainly for tests.
func (r *Runner) Host() string { return r.host }

// memSnapshot is a point-in-time view of process and host memory used for
// before/after diffs around a job run.
type memSnapshot struct {
	HeapAlloc    int64
	HeapSys      int64
	Goroutines   int
	NumGC        int64
	PauseTotalNs int64
	SysMemUsed   int64
	SysMemTotal  int64
	SysMemKnown  bool
}

func takeMemSnapshot() memSnapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	snap := memSnapshot{
		HeapAlloc:    int64(ms.HeapAlloc),
		HeapSys:      int64(ms.HeapSys),
		Goroutines:   runtime.NumGoroutine(),
		NumGC:        int64(ms.NumGC),
		PauseTotalNs: int64(ms.PauseTotalNs),
	}
	if memData, err := memory.Get(); err == nil {
		snap.SysMemUsed = int64(memData.Used)
		snap.SysMemTotal = int64(memData.Total)
		snap.SysMemKnown = true
	}
	return snap
}

// RunJob wraps a void-returning background function with timing, memory
// snapshots, panic recovery, and a durable record in job_runs. Drop-in
// replacement for cron.AddFunc handlers and ad-hoc `go fn()` startup
// goroutines.
func (r *Runner) RunJob(name string, fn func()) {
	r.RunJobErr(name, func() error {
		fn()
		return nil
	})
}

// RunJobErr is the error-returning sibling of RunJob; the returned error
// (if any) is recorded as the run's status/error_msg.
func (r *Runner) RunJobErr(name string, fn func() error) {
	start := time.Now()
	before := takeMemSnapshot()
	log.Printf("job %q: start (heap=%dMB goroutines=%d numgc=%d)",
		name, before.HeapAlloc>>20, before.Goroutines, before.NumGC)

	var (
		runErr     error
		panicMsg   string
		panicStack string
	)

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				panicMsg = toErrorString(rec)
				panicStack = string(debug.Stack())
				log.Printf("job %q PANIC: %s\n%s", name, panicMsg, panicStack)
				if r.notify != nil {
					r.notify("job", "panic in "+name+": "+panicMsg, true)
				}
			}
		}()
		runErr = fn()
	}()

	after := takeMemSnapshot()
	dur := time.Since(start)

	status := "success"
	switch {
	case panicMsg != "":
		status = "panic"
	case runErr != nil:
		status = "error"
	}

	log.Printf("job %q: %s in %s (heapΔ=%+dMB goroutinesΔ=%+d numgcΔ=%+d)",
		name, status, dur,
		(after.HeapAlloc-before.HeapAlloc)>>20,
		after.Goroutines-before.Goroutines,
		after.NumGC-before.NumGC,
	)

	r.recordJobRun(name, "job", status, start, &dur, before, after, runErr, panicMsg, panicStack)
}

// StartHeartbeat spawns a goroutine that records a periodic snapshot of
// memory/goroutine counters into job_runs. Heartbeats are the data points
// between cron runs that let us see whether resource use creeps even when
// no scheduled job is firing. interval <= 0 disables the heartbeat.
func (r *Runner) StartHeartbeat(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("joblog: heartbeat goroutine PANIC: %v\n%s", rec, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			snap := takeMemSnapshot()
			r.recordJobRun("heartbeat", "heartbeat", "tick", time.Now(), nil, snap, snap, nil, "", "")
		}
	}()
}

// recordJobRun is the single funnel for both job and heartbeat inserts. It
// swallows its own errors (a logging-system failure must not kill the caller)
// and always emits a local log line so we keep a breadcrumb even if the DB
// write fails.
func (r *Runner) recordJobRun(name, kind, status string, start time.Time, dur *time.Duration, before, after memSnapshot, runErr error, panicMsg, panicStack string) {
	run := JobRun{
		Host:        r.host,
		BuildCommit: r.buildCommit,
		JobName:     name,
		Kind:        kind,
		Status:      status,
		StartedAt:   start,
	}

	heapBefore := before.HeapAlloc
	heapAfter := after.HeapAlloc
	heapSysBefore := before.HeapSys
	heapSysAfter := after.HeapSys
	gorBefore := before.Goroutines
	gorAfter := after.Goroutines
	gcBefore := before.NumGC
	gcAfter := after.NumGC
	pauseBefore := before.PauseTotalNs
	pauseAfter := after.PauseTotalNs

	run.HeapAllocBefore = &heapBefore
	run.HeapAllocAfter = &heapAfter
	run.HeapSysBefore = &heapSysBefore
	run.HeapSysAfter = &heapSysAfter
	run.GoroutinesBefore = &gorBefore
	run.GoroutinesAfter = &gorAfter
	run.NumGCBefore = &gcBefore
	run.NumGCAfter = &gcAfter
	run.PauseTotalNsBefore = &pauseBefore
	run.PauseTotalNsAfter = &pauseAfter

	if after.SysMemKnown {
		used := after.SysMemUsed
		total := after.SysMemTotal
		run.SysMemUsedBytes = &used
		run.SysMemTotalBytes = &total
	}

	if dur != nil {
		ms := dur.Milliseconds()
		run.DurationMs = &ms
		finished := start.Add(*dur)
		run.FinishedAt = &finished
	}
	if runErr != nil {
		msg := runErr.Error()
		run.ErrorMsg = &msg
	}
	if panicMsg != "" {
		// Store the panic value in error_msg so a single column shows the
		// proximate cause regardless of status; panic_stack carries the
		// trace.
		msg := panicMsg
		run.ErrorMsg = &msg
		if panicStack != "" {
			run.PanicStack = &panicStack
		}
	}

	if !r.canWrite() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.insertJobRun(ctx, run); err != nil {
		log.Printf("job %q: failed to record run: %v", name, err)
	}
}

func toErrorString(v any) string {
	switch e := v.(type) {
	case error:
		return e.Error()
	case string:
		return e
	default:
		return fmt.Sprintf("%v", v)
	}
}
