//go:build !unix

package agent

import "os"

// The agent runs on Linux servers; these stand-ins only let the package
// build and its tests run elsewhere.

func flock(*os.File, int) error { return nil }

const (
	lockEx = 0
	lockUn = 0
)

// DiskSpace is not known here.
func DiskSpace(string) (free, total int64, ok bool) { return 0, 0, false }
