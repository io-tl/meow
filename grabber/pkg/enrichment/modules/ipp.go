package modules

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// IPPModule implements the Internet Printing Protocol enrichment module
type IPPModule struct {
	BaseModule
}

// IPPSModule implements the IPPS (secure) enrichment module
type IPPSModule struct {
	BaseModule
}

// IPPResult represents the enriched IPP data
type IPPResult struct {
	Protocol       string            `json:"protocol"` // ipp or ipps
	Version        string            `json:"version,omitempty"`
	PrinterInfo    map[string]string `json:"printer_info,omitempty"`
	TLS            *TLSInfo          `json:"tls,omitempty"` // For IPPS
	Error          string            `json:"error,omitempty"`
}

func init() {
	Register(&IPPModule{
		BaseModule: NewBaseModule(
			"ipp",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})

	Register(&IPPSModule{
		BaseModule: NewBaseModule(
			"ipps",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *IPPModule) Scan(ip string, port int) (interface{}, error) {
	return scanIPP(ip, port, false, m.DefaultTimeout())
}

func (m *IPPSModule) Scan(ip string, port int) (interface{}, error) {
	return scanIPP(ip, port, true, m.DefaultTimeout())
}

// scanIPP performs IPP/IPPS enrichment
func scanIPP(ip string, port int, useTLS bool, timeout time.Duration) (*IPPResult, error) {
	protocol := "ipp"
	if useTLS {
		protocol = "ipps"
	}

	result := &IPPResult{
		Protocol:    protocol,
		PrinterInfo: make(map[string]string),
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Try IPP Get-Printer-Attributes request
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// IPP headers
	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", "IPP-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer resp.Body.Close()

	// Check if it's an IPP service
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/ipp") || resp.StatusCode == 200 {
		result.Version = "detected"
		// Extract TLS info if IPPS
		if useTLS && resp.TLS != nil {
			result.TLS = TLSInfoFromConnectionState(resp.TLS)
		}
	} else {
		result.Error = fmt.Sprintf("Non-IPP service (status: %d)", resp.StatusCode)
	}

	return result, nil
}
