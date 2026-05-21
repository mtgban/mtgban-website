//go:build !windows

package joblog

import (
	"bufio"
	"os"
	"syscall"
	"time"
)

// StartCapture redirects this process's stdout (fd 1) and stderr (fd 2) onto
// pipes whose read end we drain into the DB log sink. The original
// descriptors are dup'd first so the captured bytes still reach the original
// destination (terminal / systemd journal / log file) — capture is a tee,
// not a hijack.
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
	go r.drainPipe(outR, "stdout", r.originalStdout)
	go r.drainPipe(errR, "stderr", r.originalStderr)
	return true
}

// drainPipe reads lines from rd, tees each line back to the local
// passthrough (so the operator still sees stdout/stderr) and submits it to
// the DB sink. Lines longer than the scanner buffer are split — better
// truncation than loss.
func (r *Runner) drainPipe(rd *os.File, source string, passthrough *os.File) {
	scanner := bufio.NewScanner(rd)
	// Bump the max token size so goroutine dumps and other large outputs
	// don't trip the default 64KB cap.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// Tee to the original destination first so local logs/terminal
		// keep working even if the DB sink is full.
		_, _ = passthrough.Write([]byte(line + "\n"))
		r.sink.submit(LogLine{
			Timestamp: time.Now(),
			Host:      r.host,
			Source:    source,
			Message:   line,
		})
	}
}
