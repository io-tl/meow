package grab

import (
	_ "embed"
	"io"
	"strings"
)

// Embed the nmap files directly into the binary
// This avoids the dependency on /usr/share/nmap/ and makes the binary portable
//
// The files are loaded at compile time with the //go:embed directive
// Total size: ~3.5MB (nmap-service-probes: 2.5MB, nmap-services: 1MB)

//go:embed data/nmap-service-probes
var nmapServiceProbes string

//go:embed data/nmap-services
var nmapServices string

// GetEmbeddedProbesReader returns an io.Reader for nmap-service-probes
func GetEmbeddedProbesReader() io.Reader {
	return strings.NewReader(nmapServiceProbes)
}

// GetEmbeddedServicesReader returns an io.Reader for nmap-services
func GetEmbeddedServicesReader() io.Reader {
	return strings.NewReader(nmapServices)
}

// GetEmbeddedProbesSize returns the size of the embedded nmap-service-probes file
func GetEmbeddedProbesSize() int {
	return len(nmapServiceProbes)
}

// GetEmbeddedServicesSize returns the size of the embedded nmap-services file
func GetEmbeddedServicesSize() int {
	return len(nmapServices)
}
