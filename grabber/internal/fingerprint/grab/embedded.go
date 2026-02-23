package grab

import (
	_ "embed"
	"io"
	"strings"
)

// Embed des fichiers nmap directement dans le binaire
// Cela évite la dépendance sur /usr/share/nmap/ et rend le binaire portable
//
// Les fichiers sont chargés au moment de la compilation avec la directive //go:embed
// Taille totale: ~3.5MB (nmap-service-probes: 2.5MB, nmap-services: 1MB)

//go:embed data/nmap-service-probes
var nmapServiceProbes string

//go:embed data/nmap-services
var nmapServices string

// GetEmbeddedProbesReader retourne un io.Reader pour nmap-service-probes
func GetEmbeddedProbesReader() io.Reader {
	return strings.NewReader(nmapServiceProbes)
}

// GetEmbeddedServicesReader retourne un io.Reader pour nmap-services
func GetEmbeddedServicesReader() io.Reader {
	return strings.NewReader(nmapServices)
}

// GetEmbeddedProbesSize retourne la taille du fichier nmap-service-probes embarqué
func GetEmbeddedProbesSize() int {
	return len(nmapServiceProbes)
}

// GetEmbeddedServicesSize retourne la taille du fichier nmap-services embarqué
func GetEmbeddedServicesSize() int {
	return len(nmapServices)
}
