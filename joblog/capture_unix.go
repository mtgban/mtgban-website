//go:build !windows

package joblog

import (
	"bufio"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// passthroughBufferLines is the queue depth in front of each platform-side
// stdout/stderr fd. Sized to absorb several seconds of normal logging without
// drops; if the platform's log collector stalls longer than that, lines are
// dropped rather than blocking.
const passthroughBufferLines = 4096

// passthroughDropReportInterval bounds how often the drainer summarises
// dropped lines into log_lines. Kept on the long side because the report
// itself is only interesting if drops are sustained.
const passthroughDropReportInterval = 30 * time.Second

// StartCapture redirects this process's stdout (fd 1) and stderr (fd 2) onto
// pipes whose read end we drain into the DB log sink. The original
// descriptors are dup'd first so the captured bytes still reach the original
// destination (terminal / systemd journal / managed-platform log collector) —
// capture is a tee, not a hijack.
//
// Returns true if capture was wired up, false if any syscall failed; the
// caller logs failure but does not abort startup. Safe to call only once
// per process.
func (r *Runner) StartCapture() bool {
	if r == nil {
		return false
	}

	origOutFd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return false
	}
	origErrFd, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		_ = syscall.Close(origOutFd)
		return false
	}
	r.originalStdout = os.NewFile(uintptr(origOutFd), "/dev/stdout.orig")
	r.originalStderr = os.NewFile(uintptr(origErrFd), "/dev/stderr.orig")

	outR, outW, err := os.Pipe()
	if err != nil {
		return false
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return false
	}

	if err := syscall.Dup2(int(outW.Fd()), int(os.Stdout.Fd())); err != nil {
		return false
	}
	if err := syscall.Dup2(int(errW.Fd()), int(os.Stderr.Fd())); err != nil {
		return false
	}
	// fd 1/2 now point at the pipe writers; the original write ends are
	// duplicates inside this process and can be closed without losing them.
	_ = outW.Close()
	_ = errW.Close()

	r.startSinkOnce()

	outPass := newPassthroughWriter(r, r.originalStdout, "stdout", passthroughBufferLines)
	errPass := newPassthroughWriter(r, r.originalStderr, "stderr", passthroughBufferLines)

	go r.drainPipe(outR, "stdout", outPass)
	go r.drainPipe(errR, "stderr", errPass)
	return true
}

// drainPipe reads lines from rd, tees each line to the passthrough (which
// queues the write non-blockingly) and submits the line to the DB sink.
// Lines longer than the scanner buffer are split — better truncation than
// loss.
func (r *Runner) drainPipe(rd *os.File, source string, passthrough *passthroughWriter) {
	scanner := bufio.NewScanner(rd)
	// Bump the max token size so goroutine dumps and other large outputs
	// don't trip the default 64KB cap.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		passthrough.write(line)
		r.sink.submit(LogLine{
			Timestamp: time.Now(),
			Host:      r.host,
			Source:    source,
			Message:   line,
		})
	}
}

// passthroughWriter is the non-blocking front of the platform-side
// stdout/stderr fd. Write attempts a non-blocking enqueue and drops on a full
// channel; a dedicated drainer goroutine performs the (potentially blocking)
// write to dst.
//
// Why drop instead of block: dst is whatever the platform attached to fd 1/2
// before we dup2'd ourselves in (a terminal, journald, a managed-platform log
// collector). If dst stalls — common on managed platforms when their
// collector backpressures — a synchronous write here would block the pipe
// drainer, fill the kernel pipe behind fd 1/2, and wedge every goroutine in
// the process that calls log.Print. Dropping lines is the cheap cost we pay
// to keep the rest of the process moving; the same lines still reach the DB
// sink, which is the durable record.
type passthroughWriter struct {
	dst     *os.File
	ch      chan []byte
	dropped atomic.Int64
	name    string
	owner   *Runner
}

// newPassthroughWriter constructs a writer and starts its drainer. The
// drainer is process-lifetime; there is no Close.
func newPassthroughWriter(owner *Runner, dst *os.File, name string, capacity int) *passthroughWriter {
	p := &passthroughWriter{
		dst:   dst,
		ch:    make(chan []byte, capacity),
		name:  name,
		owner: owner,
	}
	go p.drain()
	return p
}

// write queues a line (the trailing newline is added here) for the drainer.
// Non-blocking: on a full queue the line is dropped and counted.
func (p *passthroughWriter) write(line string) {
	if p == nil {
		return
	}
	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	select {
	case p.ch <- buf:
	default:
		p.dropped.Add(1)
	}
}

// drain runs forever. The Write to dst can block indefinitely if the
// platform's collector is wedged; that's fine — only this goroutine pays the
// price, the channel fills up, and write() drops new lines. When dst
// recovers the write completes and we resume.
//
// Drop counts are reported to the DB sink (not back to dst, which would
// recurse into the same wedge) so operators can see when platform-side logs
// are missing data.
func (p *passthroughWriter) drain() {
	ticker := time.NewTicker(passthroughDropReportInterval)
	defer ticker.Stop()
	for {
		select {
		case buf := <-p.ch:
			_, _ = p.dst.Write(buf)
		case <-ticker.C:
			if n := p.dropped.Swap(0); n > 0 && p.owner != nil {
				p.owner.sink.submit(LogLine{
					Timestamp: time.Now(),
					Host:      p.owner.host,
					Source:    "joblog",
					Message: fmt.Sprintf(
						"passthrough dropped %d %s lines under platform-side backpressure",
						n, p.name),
				})
			}
		}
	}
}
