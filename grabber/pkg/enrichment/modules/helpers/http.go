package helpers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPProbeResult holds the raw result of an HTTP probe.
type HTTPProbeResult struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// HTTPProbe performs a GET request and returns the status, headers, and body.
// Set useTLS to true for HTTPS connections (with InsecureSkipVerify).
func HTTPProbe(ip string, port int, path string, useTLS bool, timeout time.Duration) (*HTTPProbeResult, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, port, path)

	client := &http.Client{Timeout: timeout}
	if useTLS {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &HTTPProbeResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}, nil
}

// HTTPProbeJSON performs a GET request and unmarshals the JSON body.
// Set useTLS to true for HTTPS connections.
func HTTPProbeJSON(ip string, port int, path string, useTLS bool, timeout time.Duration) (map[string]interface{}, error) {
	result, err := HTTPProbe(ip, port, path, useTLS, timeout)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(result.Body, &data); err != nil {
		return nil, err
	}
	return data, nil
}
