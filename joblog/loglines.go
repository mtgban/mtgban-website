package joblog

import (
	"context"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

// dbLogSink is the funnel from "a line was captured" to "rows in log_lines".
// Submits are non-blocking; the drainer batches inserts and counts drops so
// pressure is observable without coupling app latency to DB health.
type dbLogSink struct {
	owner         *Runner
	ch            chan LogLine
	dropped       atomic.Int64
	batchSize     int
	flushInterval time.Duration
	started       atomic.Bool
}

func newDBLogSink(owner *Runner, capacity, batchSize int, flush time.Duration) *dbLogSink {
	return &dbLogSink{
		owner:         owner,
		ch:            make(chan LogLine, capacity),
		batchSize:     batchSize,
		flushInterval: flush,
	}
}

// submit attempts a non-blocking send. On a full channel it increments the
// dropped counter — itself reported periodically by the drainer so the
// operator can tell when capture is missing data.
func (s *dbLogSink) submit(line LogLine) {
	if s == nil {
		return
	}
	select {
	case s.ch <- line:
	default:
		s.dropped.Add(1)
	}
}

// drain runs forever, batching captured lines into multi-value INSERTs.
// Errors are logged but never returned — a logging-system failure must not
// kill the app whose logs we're trying to preserve.
func (s *dbLogSink) drain() {
	batch := make([]LogLine, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 || !s.owner.canWrite() {
			batch = batch[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.owner.insertLogLines(ctx, batch)
		cancel()
		if err != nil {
			// Use a direct write to original stderr so we don't recurse
			// into the capture pipe.
			if s.owner.originalStderr != nil {
				_, _ = s.owner.originalStderr.WriteString(
					time.Now().Format(time.RFC3339) + " joblog: insert failed: " + err.Error() + "\n")
			} else {
				log.Printf("joblog: insert failed: %v", err)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case line := <-s.ch:
			batch = append(batch, line)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
			if dropped := s.dropped.Swap(0); dropped > 0 && s.owner.originalStderr != nil {
				_, _ = s.owner.originalStderr.WriteString(
					time.Now().Format(time.RFC3339) +
						" joblog: dropped " + itoa(dropped) + " lines under backpressure\n")
			}
		}
	}
}

// SubmitLine queues a single LogLine for asynchronous insertion. Non-blocking;
// drops on a full sink. Useful for sources outside stdout/stderr capture
// (e.g. wrapping a *log.Logger with TaggedWriter).
func (r *Runner) SubmitLine(line LogLine) {
	if r == nil {
		return
	}
	if line.Host == "" {
		line.Host = r.host
	}
	if line.Timestamp.IsZero() {
		line.Timestamp = time.Now()
	}
	r.sink.submit(line)
}

// TaggedWriter is an io.Writer that submits each Write as a single log_lines
// row tagged with the configured source. Designed to wrap *log.Logger output
// (which writes one record per Write call) without rewriting call sites. The
// trailing newline from log's formatter is stripped to match the pipe
// capture's line shape.
type TaggedWriter struct {
	runner *Runner
	source string
}

// PageLogWriter returns a TaggedWriter that tags submissions with the given
// page name, prefixed with "page:". Safe to use before StartCapture: writes
// just queue into the sink (or drop if no DB).
func (r *Runner) PageLogWriter(name string) io.Writer {
	return TaggedWriter{runner: r, source: "page:" + name}
}

// SourceWriter is the more general form of PageLogWriter — caller picks the
// exact source label.
func (r *Runner) SourceWriter(source string) io.Writer {
	return TaggedWriter{runner: r, source: source}
}

func (w TaggedWriter) Write(p []byte) (int, error) {
	if w.runner != nil {
		w.runner.SubmitLine(LogLine{
			Source:  w.source,
			Message: strings.TrimRight(string(p), "\n"),
		})
	}
	return len(p), nil
}

// startSinkOnce starts the drainer goroutine the first time it's needed.
// StartCapture and StartLogPruner both call this so order-of-setup doesn't
// matter to the caller.
func (r *Runner) startSinkOnce() {
	if r.sink.started.CompareAndSwap(false, true) {
		go r.sink.drain()
	}
}

// StartLogPruner runs a periodic DELETE that trims log_lines beyond the
// retention window. Failures are logged but otherwise ignored — the next
// tick will retry. Wrapped in RunJob so its own runs are observable.
//
// retention <= 0 disables the pruner.
func (r *Runner) StartLogPruner(retention, interval time.Duration) {
	if retention <= 0 || !r.canWrite() {
		return
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	r.startSinkOnce()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// Run once on boot too so a long-stopped server catches up.
		r.runPrune(retention)
		for range ticker.C {
			r.runPrune(retention)
		}
	}()
}

func (r *Runner) runPrune(retention time.Duration) {
	if !r.canWrite() {
		return
	}
	r.RunJobErr("joblog.prune", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		n, err := r.pruneLogLines(ctx, time.Now().Add(-retention))
		if err != nil {
			return err
		}
		if n > 0 {
			log.Printf("joblog: pruned %d log_lines rows older than %s", n, retention)
		}
		return nil
	})
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
