package helpers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func parseTestServerAddr(ts *httptest.Server) (string, int) {
	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestHTTPProbe_GET200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	result, err := HTTPProbe(ip, port, "/", false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("got status %d, want 200", result.StatusCode)
	}
	if string(result.Body) != "OK" {
		t.Errorf("got body %q, want %q", result.Body, "OK")
	}
}

func TestHTTPProbe_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	result, err := HTTPProbe(ip, port, "/notfound", false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 404 {
		t.Errorf("got status %d, want 404", result.StatusCode)
	}
}

func TestHTTPProbe_Headers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	result, err := HTTPProbe(ip, port, "/", false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Headers.Get("X-Custom") != "value" {
		t.Errorf("got header %q, want %q", result.Headers.Get("X-Custom"), "value")
	}
}

func TestHTTPProbe_TLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("TLS OK"))
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	result, err := HTTPProbe(ip, port, "/", true, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("got status %d, want 200", result.StatusCode)
	}
	if string(result.Body) != "TLS OK" {
		t.Errorf("got body %q, want %q", result.Body, "TLS OK")
	}
}

func TestHTTPProbeJSON_Valid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": "1.0",
			"name":    "test",
		})
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	data, err := HTTPProbeJSON(ip, port, "/", false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["version"] != "1.0" {
		t.Errorf("got version %v, want %q", data["version"], "1.0")
	}
	if data["name"] != "test" {
		t.Errorf("got name %v, want %q", data["name"], "test")
	}
}

func TestHTTPProbeJSON_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	_, err := HTTPProbeJSON(ip, port, "/", false, 5*time.Second)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestHTTPProbeJSON_Path(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer ts.Close()

	ip, port := parseTestServerAddr(ts)
	data, err := HTTPProbeJSON(ip, port, "/api/info", false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["status"] != "ok" {
		t.Errorf("got status %v, want %q", data["status"], "ok")
	}
}

func TestHTTPProbe_ConnectionRefused(t *testing.T) {
	// Use a port that's definitely not listening
	_, err := HTTPProbe("127.0.0.1", 1, "/", false, 1*time.Second)
	if err == nil {
		t.Error("expected error for connection refused")
	}
}
