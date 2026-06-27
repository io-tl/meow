package transport

import (
	"log"
	"os"
)

// DetectBestTransport on macOS only supports TCP connect (no raw sockets without extra libs).
func DetectBestTransport(config *TransportConfig) (Transport, error) {
	return detectTransport(config, []transportCandidate{
		{"Connect", NewConnectTransport},
	})
}

// CheckCapabilities logs available transport capabilities on macOS.
func CheckCapabilities() {
	verbose := os.Getenv("MEOW_DEBUG") != ""
	if verbose {
		log.Println("Checking available transport capabilities (darwin)...")
		log.Printf("  - Root/EUID=0: %v", IsRoot())
		log.Println("  - Only TCP connect transport available on macOS")
	}
}
