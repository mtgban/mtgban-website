//go:build windows

package joblog

// StartCapture is a no-op on Windows: dup2-based pipe redirection of fd 1/2
// isn't available via the syscall package there. Returns false so callers
// can log that capture isn't wired up.
func (r *Runner) StartCapture() bool {
	return false
}
