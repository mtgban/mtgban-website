//go:build !windows

package main

import (
	"bufio"
	"os"
	"syscall"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// originalStderr is a re-opened handle on the original fd 2 captured before
// we dup'd the pipe over it. The drainer writes its own diagnostics here so
// it doesn't recurse into the capture pipe.
var originalStderr *os.File

// originalStdout mirrors originalStderr for fd 1.
var originalStdout *os.File

// startStdLogCapture redirects this process's stdout (fd 1) and stderr (fd 2)
// onto pipes whose read end we drain into the DB log sink. The original
// descriptors are dup'd first so the captured bytes still reach the original
// destination (terminal / systemd journal / logs/ file) — capture is a tee,
// not a hijack.
//
// Returns true if capture was wired up, false if any syscall failed; the
// caller logs failure but does not abort startup.
func startStdLogCapture(sink *dbLogSink) bool {
	// Save originals via dup so we can keep writing to them after dup2.
	origOutFd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return false
	}
	origErrFd, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		_ = syscall.Close(origOutFd)
		return false
	}
	originalStdout = os.NewFile(uintptr(origOutFd), "/dev/stdout.orig")
	originalStderr = os.NewFile(uintptr(origErrFd), "/dev/stderr.orig")

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

	go drainPipe(outR, "stdout", originalStdout, sink)
	go drainPipe(errR, "stderr", originalStderr, sink)
	return true
}

// drainPipe reads lines from r, tees each line back to the local passthrough
// (so the operator still sees stdout/stderr) and submits it to the DB sink.
// Lines longer than the scanner buffer are split — better truncation than
// loss.
func drainPipe(r *os.File, source string, passthrough *os.File, sink *dbLogSink) {
	scanner := bufio.NewScanner(r)
	// Bump the max token size so goroutine dumps and other large outputs
	// don't trip the default 64KB cap.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// Tee to the original destination first so local logs/terminal
		// keep working even if the DB sink is full.
		_, _ = passthrough.Write([]byte(line + "\n"))
		if sink != nil {
			sink.submit(timeseries.LogLine{
				Timestamp: time.Now(),
				Host:      jobHost,
				Source:    source,
				Message:   line,
			})
		}
	}
}
