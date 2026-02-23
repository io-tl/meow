//go:build !windows

package transport

import "os"

// IsRoot checks if the process has root privileges (Unix).
func IsRoot() bool {
	return os.Geteuid() == 0
}
