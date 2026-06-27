package transport

import (
	"log"
	"os"
	"syscall"
)

// DetectBestTransport automatically detects and returns the best available transport method for Windows.
// Npcap is only attempted when running as Administrator to avoid slow fallback for unprivileged users.
//
//	Npcap   (~500K PPS) — true SYN scan via raw packet injection, requires Npcap + Admin
//	Connect (~50K PPS)  — full TCP handshake, no privileges needed
func DetectBestTransport(config *TransportConfig) (Transport, error) {
	var candidates []transportCandidate
	if IsAdmin() {
		candidates = append(candidates, transportCandidate{"Npcap", NewNpcapTransport})
	}
	candidates = append(candidates, transportCandidate{"Connect", NewConnectTransport})
	return detectTransport(config, candidates)
}

// CheckCapabilities checks what capabilities are available and logs them
func CheckCapabilities() {
	verbose := os.Getenv("MEOW_DEBUG") != ""
	if verbose {
		npcapAvail := npcapDLL.Load() == nil
		log.Println("Checking available transport capabilities...")
		log.Printf("  - Npcap available: %v", npcapAvail)
		if !npcapAvail {
			log.Printf("  - Note: Install Npcap and run as Administrator for SYN scan (~500K PPS)")
		}
	}
}

// IsAdmin checks if the process has administrator privileges on Windows
func IsAdmin() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// IsRoot is an alias for IsAdmin on Windows for compatibility
func IsRoot() bool {
	return IsAdmin()
}
