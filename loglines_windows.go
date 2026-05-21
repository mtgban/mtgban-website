//go:build windows

package main

import "os"

// originalStderr is unused on Windows but referenced by cross-platform code.
var originalStderr *os.File

// originalStdout mirrors originalStderr.
var originalStdout *os.File

// startStdLogCapture is a no-op on Windows: dup2-based pipe redirection of
// fd 1/2 isn't available via syscall there. Returns false so callers know
// nothing was wired up.
func startStdLogCapture(_ *dbLogSink) bool {
	return false
}
