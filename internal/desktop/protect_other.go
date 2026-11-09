//go:build !windows

package desktop

// Outside Windows (development only) the key file relies on its 0600 mode.
func protect(b []byte) ([]byte, error)   { return b, nil }
func unprotect(b []byte) ([]byte, error) { return b, nil }
