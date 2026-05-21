package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/mackerelio/go-osstat/memory"
	"github.com/mtgban/mtgban-website/timeseries"
)

// jobHost caches os.Hostname so every job_runs insert doesn't pay the syscall.
var jobHost = func() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}()

// memSnapshot is a point-in-time view of process and host memory used for
// before/after diffs around a job run.
type memSnapshot struct {
	HeapAlloc      int64
	HeapSys        int64
	Goroutines     int
	NumGC          int64
	PauseTotalNs   int64
	SysMemUsed     int64
	SysMemTotal    int64
	SysMemKnown    bool
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

// runJob wraps a void-returning background function with timing, memory
// snapshots, panic recovery, and a durable record in job_runs. The wrapper
// always logs locally so we have a fallback if the database insert itself
// fails. Designed to be a drop-in for cron.AddFunc handlers and ad-hoc
// `go fn()` startup goroutines.
func runJob(name string, fn func()) {
	runJobErr(name, func() error {
		fn()
		return nil
	})
}

// runJobErr is the error-returning sibling of runJob; the returned error
// (if any) is recorded as the run's status/error_msg.
func runJobErr(name string, fn func() error) {
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
			if r := recover(); r != nil {
				panicMsg = toErrorString(r)
				panicStack = string(debug.Stack())
				log.Printf("job %q PANIC: %s\n%s", name, panicMsg, panicStack)
				ServerNotify("job", "panic in "+name+": "+panicMsg, true)
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

	recordJobRun(name, "job", status, start, &dur, before, after, runErr, panicMsg, panicStack)
}

// startHeartbeat spawns a goroutine that records a periodic snapshot of
// memory/goroutine counters into job_runs. Heartbeats are the data points
// between cron runs that let us see whether resource use creeps even when
// no scheduled job is firing. Cancellation is via process exit; the goroutine
// is intentionally lightweight (one DB row per interval).
func startHeartbeat(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("heartbeat goroutine PANIC: %v\n%s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			snap := takeMemSnapshot()
			recordJobRun("heartbeat", "heartbeat", "tick", time.Now(), nil, snap, snap, nil, "", "")
		}
	}()
}

// recordJobRun is the single funnel for both job and heartbeat inserts. It
// swallows its own errors (a logging-system failure must not kill the caller)
// and always emits a local log line so we keep a breadcrumb even if the DB
// write fails.
func recordJobRun(name, kind, status string, start time.Time, dur *time.Duration, before, after memSnapshot, runErr error, panicMsg, panicStack string) {
	run := timeseries.JobRun{
		Host:        jobHost,
		BuildCommit: BuildCommit,
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

	if PricesArchiveDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := PricesArchiveDB.InsertJobRun(ctx, run); err != nil {
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
