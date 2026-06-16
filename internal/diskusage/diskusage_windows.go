//go:build windows

// Package diskusage reports filesystem usage. The actual syscall is
// platform specific, so it is isolated here to keep build tags out of
// the main package.
package diskusage

// Stats is not implemented on Windows and reports no usage.
func Stats(path string) (used, total uint64, err error) {
	return 0, 0, nil
}
