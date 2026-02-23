package modules

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestScanElasticsearch_ValidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":         "node-1",
			"cluster_name": "my-cluster",
			"tagline":      "You Know, for Search",
			"version": map[string]interface{}{
				"number": "8.10.0",
			},
		})
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	result, err := scanElasticsearch(host, port, ts.Client().Timeout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "8.10.0" {
		t.Errorf("Version = %q, want %q", result.Version, "8.10.0")
	}
	if result.ClusterName != "my-cluster" {
		t.Errorf("ClusterName = %q", result.ClusterName)
	}
	if result.Name != "node-1" {
		t.Errorf("Name = %q", result.Name)
	}
	if result.Tagline != "You Know, for Search" {
		t.Errorf("Tagline = %q", result.Tagline)
	}
}

func TestScanElasticsearch_NoVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"name": "node"})
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	result, err := scanElasticsearch(host, port, ts.Client().Timeout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty", result.Version)
	}
}

func TestElasticsearch_ModuleRegistered(t *testing.T) {
	_, ok := Get("elasticsearch")
	if !ok {
		t.Fatal("elasticsearch not registered")
	}
	_, ok = Get("elastic")
	if !ok {
		t.Fatal("elastic alias not registered")
	}
}
