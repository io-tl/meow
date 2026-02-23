package transport

import (
	"fmt"
	"log"
	"os"
)

type transportCandidate struct {
	name    string
	creator func(*TransportConfig) (Transport, error)
}

func detectTransport(config *TransportConfig, methods []transportCandidate) (Transport, error) {
	verbose := os.Getenv("VERBOSE") != ""

	var lastErr error
	for _, method := range methods {
		if verbose {
			log.Printf("Trying transport method: %s", method.name)
		}
		t, err := method.creator(config)
		if err == nil {
			log.Printf("Using transport: %s", method.name)
			if verbose {
				caps := t.GetCapabilities()
				log.Printf("  - SYN scan: %v", caps.SupportsSYNScan)
				log.Printf("  - Custom source port: %v", caps.SupportsCustomSourcePort)
				log.Printf("  - Raw packets: %v", caps.SupportsRawPackets)
				log.Printf("  - Max PPS estimate: %d", caps.MaxPacketsPerSecond)
			}
			return t, nil
		}
		lastErr = err
		if verbose {
			log.Printf("✗ %s not available: %v", method.name, err)
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no transport method available")
	}
	return nil, lastErr
}
