package types

import "time"

// BaseResult provides common fields for all enrichment module results.
type BaseResult struct {
	Protocol string `json:"protocol"`
	Error    string `json:"error,omitempty"`
}

// EnrichmentRequest represents an enrichment request received from NATS
// Expected message format from scan.port.fingerprinted
type EnrichmentRequest struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Domain  string `json:"domain,omitempty"` // Optional: for SNI support (HTTPS)
}

// EnrichmentResult represents the enriched result to publish on NATS
// This will be published to scan.port.enriched
type EnrichmentResult struct {
	IP        string      `json:"ip"`
	Port      int         `json:"port"`
	Service   string      `json:"service"`
	Domain    string      `json:"domain,omitempty"`
	Data      interface{} `json:"data"`            // Module-specific enriched data
	Timestamp string      `json:"timestamp"`       // RFC3339 timestamp
	Error     string      `json:"error,omitempty"` // Error message if enrichment failed
}

// NewEnrichmentResult creates a new enrichment result with timestamp
func NewEnrichmentResult(ip string, port int, service string, domain string, data interface{}) *EnrichmentResult {
	return &EnrichmentResult{
		IP:        ip,
		Port:      port,
		Service:   service,
		Domain:    domain,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewEnrichmentError creates an enrichment result with an error
func NewEnrichmentError(ip string, port int, service string, domain string, err error) *EnrichmentResult {
	return &EnrichmentResult{
		IP:        ip,
		Port:      port,
		Service:   service,
		Domain:    domain,
		Error:     err.Error(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}
