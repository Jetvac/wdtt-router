//go:build unix

package agent

import (
	"os"
	"syscall"
)

func flock(f *os.File, how int) error { return syscall.Flock(int(f.Fd()), how) }

const (
	lockEx = syscall.LOCK_EX | syscall.LOCK_NB
	lockUn = syscall.LOCK_UN
)

// DiskSpace reports the free and total bytes of the file system at path.
func DiskSpace(path string) (free, total int64, ok bool) {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil {
		return 0, 0, false
	}
	return int64(fs.Bavail) * int64(fs.Bsize), int64(fs.Blocks) * int64(fs.Bsize), true
}
