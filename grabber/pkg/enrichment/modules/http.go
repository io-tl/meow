package modules

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	// censysUserAgent is the User-Agent used by Censys scans
	censysUserAgent = "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
)

var (
	wappalyzerClient     *wappalyzer.Wappalyze
	wappalyzerClientOnce sync.Once
	wappalyzerClientErr  error
)

// getWappalyzerClient returns a singleton Wappalyzer client
func getWappalyzerClient() (*wappalyzer.Wappalyze, error) {
	wappalyzerClientOnce.Do(func() {
		wappalyzerClient, wappalyzerClientErr = wappalyzer.New()
	})
	return wappalyzerClient, wappalyzerClientErr
}

// HTTPModule implements the HTTP enrichment module (without zgrab)
type HTTPModule struct {
	BaseModule
}

// HTTPSModule implements the HTTPS enrichment module (without zgrab)
type HTTPSModule struct {
	BaseModule
}

// HTTPResult represents the enriched HTTP/HTTPS data
type HTTPResult struct {
	Protocol      string              `json:"protocol"` // http or https
	StatusCode    int                 `json:"status_code"`
	StatusText    string              `json:"status_text"`
	Headers       map[string][]string `json:"headers"`
	Banner        string              `json:"banner,omitempty"` // HTTP response headers as banner (status line + headers)
	Body          string              `json:"body,omitempty"`   // Truncated body (first 10KB)
	BodyLength    int                 `json:"body_length"`      // Best known full body length
	BodyTruncated bool                `json:"body_truncated,omitempty"`
	Technologies  []Technology        `json:"technologies,omitempty"` // Wappalyzer detected technologies
	Favicon       *FaviconInfo        `json:"favicon,omitempty"`      // Favicon hash info
	Redirects     []string            `json:"redirects,omitempty"`    // Redirect chain
	TLS           *TLSInfo            `json:"tls,omitempty"`          // TLS/SSL info (HTTPS only)
	Error         string              `json:"error,omitempty"`        // Error if request failed
}

// Technology represents a detected web technology
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

// FaviconInfo represents favicon hash information
type FaviconInfo struct {
	URL  string `json:"url,omitempty"`
	MD5  string `json:"md5,omitempty"`  // MD5 hash
	MMH3 int32  `json:"mmh3,omitempty"` // MurmurHash3 (Shodan compatible)
	Size int    `json:"size,omitempty"` // Size in bytes
}

func init() {
	Register(&HTTPModule{
		BaseModule: NewBaseModule(
			"http",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})

	Register(&HTTPSModule{
		BaseModule: NewBaseModule(
			"https",
			[]string{"ssl", "ssl/http", "https-alt"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *HTTPModule) Scan(ip string, port int) (interface{}, error) {
	return scanHTTP(ip, port, false, "", m.DefaultTimeout())
}

func (m *HTTPSModule) Scan(ip string, port int) (interface{}, error) {
	return scanHTTP(ip, port, true, "", m.DefaultTimeout())
}

// ScanWithSNI implements SNI support for HTTP
func (m *HTTPModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return scanHTTP(ip, port, false, domain, m.DefaultTimeout())
}

// ScanWithSNI implements SNI support for HTTPS
func (m *HTTPSModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return scanHTTP(ip, port, true, domain, m.DefaultTimeout())
}

// scanHTTP performs HTTP/HTTPS enrichment without zgrab
func scanHTTP(ip string, port int, useHTTPS bool, domain string, timeout time.Duration) (*HTTPResult, error) {
	protocol := "http"
	if useHTTPS {
		protocol = "https"
	}

	result := &HTTPResult{
		Protocol: protocol,
	}

	// Always use IP in URL for direct connection (avoids DNS resolution issues)
	// Domain is used for Host header and SNI only
	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	url := baseURL + "/"

	// Configure TLS with SNI support
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if domain != "" {
		tlsConfig.ServerName = domain
	}

	// Create HTTP client with custom transport
	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Track redirects but don't follow them (max 1)
			if len(via) >= 1 {
				// Record only the most recent redirect (last entry in via)
				// to avoid duplicating the entire chain on each callback invocation
				result.Redirects = append(result.Redirects, via[len(via)-1].URL.String())
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Set Host header to domain if provided (important for virtual hosts)
	if domain != "" {
		req.Host = domain
	}

	// Set User-Agent (Censys)
	req.Header.Set("User-Agent", censysUserAgent)

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer resp.Body.Close()

	// Extract response data
	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.Headers = resp.Header

	// Read body (limit to 100KB for Wappalyzer analysis)
	bodyReader := io.LimitReader(resp.Body, 100*1024)
	bodyBytes, err := io.ReadAll(bodyReader)
	if err == nil {
		result.Body = string(bodyBytes)
		result.BodyLength = len(bodyBytes)
		if resp.ContentLength > int64(len(bodyBytes)) {
			result.BodyLength = int(resp.ContentLength)
			result.BodyTruncated = true
		}
	}

	// Detect technologies using Wappalyzer
	result.Technologies = detectTechnologiesWappalyzer(resp.Header, bodyBytes)

	// Extract TLS information (HTTPS only)
	if useHTTPS && resp.TLS != nil {
		result.TLS = TLSInfoFromConnectionState(resp.TLS)
	}

	// Fetch favicon and compute hash
	result.Favicon = fetchFavicon(client, baseURL, domain, bodyBytes)

	return result, nil
}

// detectTechnologiesWappalyzer detects technologies using Wappalyzer
func detectTechnologiesWappalyzer(headers http.Header, body []byte) []Technology {
	var techs []Technology

	// Get Wappalyzer client
	client, err := getWappalyzerClient()
	if err != nil {
		// Fallback to basic detection if Wappalyzer fails
		return detectTechnologiesFallback(headers)
	}

	// Use FingerprintWithCats for category information
	fingerprints := client.FingerprintWithCats(headers, body)

	// Get category mapping for ID to name conversion
	catMapping := wappalyzer.GetCategoriesMapping()

	for name, catInfo := range fingerprints {
		tech := Technology{
			Name: name,
		}

		// Convert category IDs to names
		for _, catID := range catInfo.Cats {
			if cat, ok := catMapping[catID]; ok {
				tech.Categories = append(tech.Categories, cat.Name)
			}
		}

		techs = append(techs, tech)
	}

	return techs
}

// detectTechnologiesFallback is a basic fallback when Wappalyzer is unavailable
func detectTechnologiesFallback(headers http.Header) []Technology {
	var techs []Technology

	// Server header
	if server := headers.Get("Server"); server != "" {
		techs = append(techs, Technology{Name: server, Categories: []string{"Web servers"}})
	}

	// X-Powered-By header
	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, Technology{Name: powered, Categories: []string{"Programming languages"}})
	}

	// X-AspNet-Version
	if aspnet := headers.Get("X-AspNet-Version"); aspnet != "" {
		techs = append(techs, Technology{Name: "ASP.NET", Version: aspnet, Categories: []string{"Web frameworks"}})
	}

	// X-Generator
	if generator := headers.Get("X-Generator"); generator != "" {
		techs = append(techs, Technology{Name: generator, Categories: []string{"CMS"}})
	}

	return techs
}

// fetchFavicon fetches and hashes the favicon
func fetchFavicon(client *http.Client, baseURL, domain string, body []byte) *FaviconInfo {
	// Try to find favicon URL in HTML
	faviconURL := findFaviconURL(baseURL, body)
	if faviconURL == "" {
		// Default favicon location
		faviconURL = baseURL + "/favicon.ico"
	}

	// Fetch favicon
	req, err := http.NewRequest("GET", faviconURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", censysUserAgent)
	if domain != "" {
		req.Host = domain
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != 200 {
		return nil
	}

	contentLength := 0
	if resp.ContentLength > 0 {
		contentLength = int(resp.ContentLength)
	} else if value := resp.Header.Get("Content-Length"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			contentLength = parsed
		}
	}

	// Read favicon (limit to 1MB)
	faviconData, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}
	if len(faviconData) == 0 {
		return nil
	}
	// Additional check to ensure content length is reasonable
	if contentLength > 10*1024*1024 {
		return nil // Reject unreasonably large favicons
	}

	// Compute hashes
	md5Hash := fmt.Sprintf("%x", md5.Sum(faviconData))
	mmh3Hash := mmh3Hash32(faviconStandartBase64(faviconData))

	return &FaviconInfo{
		URL:  faviconURL,
		MD5:  md5Hash,
		MMH3: mmh3Hash,
		Size: max(contentLength, len(faviconData)),
	}
}

// findFaviconURL extracts favicon URL from HTML
func findFaviconURL(baseURL string, body []byte) string {
	// Regex to find <link rel="icon" or <link rel="shortcut icon"
	re := regexp.MustCompile(`<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']`)
	matches := re.FindSubmatch(body)
	if len(matches) < 2 {
		// Try alternative order (href before rel)
		re = regexp.MustCompile(`<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut )?icon["']`)
		matches = re.FindSubmatch(body)
	}

	if len(matches) >= 2 {
		href := string(matches[1])
		// Handle relative URLs
		if strings.HasPrefix(href, "//") {
			// Protocol-relative URL
			if strings.HasPrefix(baseURL, "https") {
				return "https:" + href
			}
			return "http:" + href
		} else if strings.HasPrefix(href, "/") {
			// Absolute path
			return baseURL + href
		} else if !strings.HasPrefix(href, "http") {
			// Relative path
			return baseURL + "/" + href
		}
		return href
	}

	return ""
}

// faviconStandartBase64 encodes favicon for MMH3 hash (Shodan compatible)
func faviconStandartBase64(data []byte) []byte {
	// Shodan uses standard base64 with newlines every 76 chars
	encoded := base64.StdEncoding.EncodeToString(data)
	var result strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		result.WriteString(encoded[i:end])
		result.WriteString("\n")
	}
	return []byte(result.String())
}

// mmh3Hash32 computes MurmurHash3 32-bit hash (Shodan compatible)
func mmh3Hash32(data []byte) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)

	length := len(data)
	h1 := uint32(0) // seed = 0

	// Body
	nblocks := length / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// Tail
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}
