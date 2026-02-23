package modules

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DNSModule implements the DNS enrichment module
type DNSModule struct {
	BaseModule
}

// DNSResult represents the enriched DNS data
type DNSResult struct {
	Protocol     string `json:"protocol"`
	Version      string `json:"version,omitempty"`      // BIND version if exposed
	Hostname     string `json:"hostname,omitempty"`     // Server hostname from HOSTNAME.BIND
	SupportsZone bool   `json:"supports_zone_transfer"` // AXFR support
	Recursion    bool   `json:"recursion_available"`
	DNSSEC       bool   `json:"dnssec"`
	Error        string `json:"error,omitempty"`
}

func init() {
	Register(&DNSModule{
		BaseModule: NewBaseModule(
			"dns",
			[]string{"domain"},
			true, // Should enrich
			5*time.Second,
		),
	})
}

func (m *DNSModule) Scan(ip string, port int) (interface{}, error) {
	return scanDNS(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - DNS doesn't use SNI
func (m *DNSModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// scanDNS performs DNS enrichment
func scanDNS(ip string, port int, timeout time.Duration) (*DNSResult, error) {
	result := &DNSResult{
		Protocol: "dns",
	}

	target := fmt.Sprintf("%s:%d", ip, port)
	client := &dns.Client{
		Timeout: timeout,
		Net:     "tcp",
	}

	// Test basic query to check if server responds
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := client.Exchange(m, target)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Check capabilities from response
	result.Recursion = resp.RecursionAvailable
	result.DNSSEC = resp.AuthenticatedData

	// Try to get BIND version (version.bind)
	versionQuery := new(dns.Msg)
	versionQuery.SetQuestion("version.bind.", dns.TypeTXT)
	versionQuery.Question[0].Qclass = dns.ClassCHAOS

	versionResp, _, err := client.Exchange(versionQuery, target)
	if err == nil && len(versionResp.Answer) > 0 {
		if txt, ok := versionResp.Answer[0].(*dns.TXT); ok {
			if len(txt.Txt) > 0 {
				result.Version = txt.Txt[0]
			}
		}
	}

	// Try to get hostname (hostname.bind)
	hostnameQuery := new(dns.Msg)
	hostnameQuery.SetQuestion("hostname.bind.", dns.TypeTXT)
	hostnameQuery.Question[0].Qclass = dns.ClassCHAOS

	hostnameResp, _, err := client.Exchange(hostnameQuery, target)
	if err == nil && len(hostnameResp.Answer) > 0 {
		if txt, ok := hostnameResp.Answer[0].(*dns.TXT); ok {
			if len(txt.Txt) > 0 {
				result.Hostname = txt.Txt[0]
			}
		}
	}

	// Try zone transfer (AXFR) - just test if it's allowed
	// Use a common domain for testing
	axfrQuery := new(dns.Msg)
	axfrQuery.SetQuestion("example.com.", dns.TypeAXFR)

	transfer := &dns.Transfer{}

	_, err = transfer.In(axfrQuery, target)
	if err == nil {
		// Zone transfer succeeded (this is a security issue!)
		result.SupportsZone = true
	} else {
		// Zone transfer refused (expected)
		result.SupportsZone = false
	}

	return result, nil
}
