package transport

import (
	"log"
	"os"
	"syscall"
)

// DetectBestTransport automatically detects and returns the best available transport method for Linux
func DetectBestTransport(config *TransportConfig) (Transport, error) {
	return detectTransport(config, []transportCandidate{
		{"AF_PACKET+mmap", NewAFPacketTransport},
		{"Raw Socket", NewRawSocketTransport},
		{"Connect", NewConnectTransport},
	})
}

// CanUseAFPacket checks if AF_PACKET with mmap is available
func CanUseAFPacket() bool {
	// Try to create AF_PACKET socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return false
	}
	syscall.Close(fd)

	// Check if we can set PACKET_VERSION (required for mmap)
	fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	// Try to set PACKET_VERSION to TPACKET_V3
	version := int(3) // TPACKET_V3
	err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 10 /*PACKET_VERSION*/, version)
	return err == nil
}

// CanUseRawSocket checks if raw sockets are available
func CanUseRawSocket() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// CheckCapabilities checks what capabilities are available and logs them
func CheckCapabilities() {
	verbose := os.Getenv("MEOW_DEBUG") != ""
	if verbose {
		log.Println("Checking available transport capabilities...")
		log.Printf("  - Root/EUID=0: %v", IsRoot())
		log.Printf("  - AF_PACKET available: %v", CanUseAFPacket())
		log.Printf("  - Raw Socket available: %v", CanUseRawSocket())
	}
}

// htons converts host byte order to network byte order (big endian)
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
