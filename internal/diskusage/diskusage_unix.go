//go:build !windows

// Package diskusage reports filesystem usage. The actual syscall is
// platform specific, so it is isolated here to keep build tags out of
// the main package.
package diskusage

import "golang.org/x/sys/unix"

// Stats returns the used and total bytes of the filesystem containing path.
func Stats(path string) (used, total uint64, err error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	return total - avail, total, nil
}
