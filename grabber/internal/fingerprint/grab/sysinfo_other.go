//go:build !linux

package grab

// getTotalSystemRAM returns the total system RAM in MB (fallback)
func getTotalSystemRAM() uint64 {
	return 8192 // 8GB by default on non-Linux platforms
}
