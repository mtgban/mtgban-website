package main

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// LogRetention controls how long captured log lines live in Postgres before
// the daily prune drops them.
const LogRetention = 14 * 24 * time.Hour

// logSinkCapacity bounds the in-memory queue between the pipe readers and
// the DB drainer. Past this point new lines are dropped (drop-newest)
// rather than blocking the writer — we trade losing the tail of a burst
// for never coupling app latency to DB health.
const logSinkCapacity = 4096

// logBatchSize / logFlushInterval shape the drainer: it flushes whenever
// either threshold is hit, so a chatty cron run lands in one statement and
// a quiet system still flushes promptly.
const (
	logBatchSize     = 200
	logFlushInterval = 2 * time.Second
)

// dbLogSink is the funnel from "a line was captured" to "rows in log_lines".
// Submits are non-blocking; the drainer batches inserts and counts drops so
// we can observe pressure without losing the app to a stalled DB.
type dbLogSink struct {
	ch      chan timeseries.LogLine
	dropped atomic.Int64
}

var logSink *dbLogSink

// taggedLogWriter is an io.Writer adapter that submits each Write call as a
// single log_lines row tagged with the provided source. Used to tee the
// per-page LogPages file loggers into the DB sink without rewriting any of
// their call sites — *log.Logger always emits one Write per record. The
// trailing newline from log's formatter is stripped to match the pipe
// capture's line shape.
type taggedLogWriter struct {
	source string
}

func (w taggedLogWriter) Write(p []byte) (int, error) {
	if logSink != nil {
		logSink.submit(timeseries.LogLine{
			Timestamp: time.Now(),
			Host:      jobHost,
			Source:    w.source,
			Message:   strings.TrimRight(string(p), "\n"),
		})
	}
	return len(p), nil
}

// newPageLogWriter returns an io.Writer that tags submissions with the given
// page name. Safe to use even before logSink is initialized; writes become
// no-ops until then.
func newPageLogWriter(page string) taggedLogWriter {
	return taggedLogWriter{source: "page:" + page}
}

func newDBLogSink() *dbLogSink {
	return &dbLogSink{ch: make(chan timeseries.LogLine, logSinkCapacity)}
}

// submit attempts a non-blocking send. On a full channel it increments the
// dropped counter — that counter is itself reported periodically below so we
// can tell when capture is missing data.
func (s *dbLogSink) submit(line timeseries.LogLine) {
	select {
	case s.ch <- line:
	default:
		s.dropped.Add(1)
	}
}

// drain runs forever, batching captured lines into multi-value INSERTs.
// Errors are logged but never returned — a logging-system failure must not
// kill the very app whose logs we're trying to preserve.
func (s *dbLogSink) drain() {
	batch := make([]timeseries.LogLine, 0, logBatchSize)
	ticker := time.NewTicker(logFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 || PricesArchiveDB == nil {
			batch = batch[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := PricesArchiveDB.InsertLogLines(ctx, batch)
		cancel()
		if err != nil {
			// Use a direct write to original stderr so we don't recurse
			// into the capture pipe. originalStderr is set by the pipe
			// setup; if it's nil (no capture configured) fall back to log.
			if originalStderr != nil {
				_, _ = originalStderr.WriteString(
					time.Now().Format(time.RFC3339) + " loglines: insert failed: " + err.Error() + "\n")
			} else {
				log.Printf("loglines: insert failed: %v", err)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case line := <-s.ch:
			batch = append(batch, line)
			if len(batch) >= logBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
			if dropped := s.dropped.Swap(0); dropped > 0 && originalStderr != nil {
				_, _ = originalStderr.WriteString(
					time.Now().Format(time.RFC3339) +
						" loglines: dropped " + itoa(dropped) + " lines under backpressure\n")
			}
		}
	}
}

// itoa is a tiny strconv-free int formatter so the drop-warning path doesn't
// pull strconv (avoiding accidental allocations under pressure is overkill
// here, but the function is genuinely small).
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// startLogPruner runs a daily DELETE that trims log_lines beyond the
// retention window. Failures are logged but otherwise ignored — the next
// tick will retry. Wrapped in runJob so its own runs are observable.
func startLogPruner() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		// Run once on boot too so a long-stopped server catches up.
		runPruneLogLines()
		for range ticker.C {
			runPruneLogLines()
		}
	}()
}

func runPruneLogLines() {
	if PricesArchiveDB == nil {
		return
	}
	runJobErr("loglines.prune", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		n, err := PricesArchiveDB.PruneLogLines(ctx, time.Now().Add(-LogRetention))
		if err != nil {
			return err
		}
		if n > 0 {
			log.Printf("loglines: pruned %d rows older than %s", n, LogRetention)
		}
		return nil
	})
}
