package modules

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestScanCouchDB_ValidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"couchdb": "Welcome",
			"version": "3.3.0",
			"vendor":  map[string]interface{}{"name": "The Apache Software Foundation"},
		})
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	mod, ok := Get("couchdb")
	if !ok {
		t.Fatal("couchdb not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*CouchDBResult)
	if result.Version != "3.3.0" {
		t.Errorf("Version = %q, want %q", result.Version, "3.3.0")
	}
	if result.Protocol != "couchdb" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

func TestScanCouchDB_NoVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	mod, _ := Get("couchdb")
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*CouchDBResult)
	if result.Version != "" {
		t.Errorf("Version = %q, want empty", result.Version)
	}
}

func TestCouchDB_ModuleRegistered(t *testing.T) {
	_, ok := Get("couchdb")
	if !ok {
		t.Fatal("couchdb not registered")
	}
}
