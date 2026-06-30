//go:build linux

package grab

import (
	"syscall"

	"github.com/rs/zerolog/log"
)

// getTotalSystemRAM returns the total system RAM in MB
func getTotalSystemRAM() uint64 {
	var sysinfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		log.Warn().Err(err).Msg("WARNING: Cannot detect system RAM (defaulting to 8GB)")
		return 8192
	}
	return sysinfo.Totalram * uint64(sysinfo.Unit) / (1024 * 1024)
}
