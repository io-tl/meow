package modules

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestScanInfluxDB_ValidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ping":
			w.Header().Set("X-Influxdb-Version", "1.8.10")
			w.Header().Set("X-Influxdb-Build", "OSS")
			w.WriteHeader(204)
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "DATABASES"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []interface{}{
					map[string]interface{}{
						"series": []interface{}{
							map[string]interface{}{
								"values": []interface{}{
									[]interface{}{"_internal"},
									[]interface{}{"mydb"},
								},
							},
						},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "USERS"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []interface{}{
					map[string]interface{}{
						"series": []interface{}{
							map[string]interface{}{
								"values": []interface{}{
									[]interface{}{"admin"},
								},
							},
						},
					},
				},
			})
		}
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	mod, ok := Get("influxdb")
	if !ok {
		t.Fatal("influxdb not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*InfluxDBResult)
	if !result.Ping {
		t.Error("Ping = false")
	}
	if result.Version != "1.8.10" {
		t.Errorf("Version = %q, want %q", result.Version, "1.8.10")
	}
	if len(result.Databases) != 2 {
		t.Errorf("Databases = %v, want 2", result.Databases)
	}
	if len(result.Users) != 1 {
		t.Errorf("Users = %v, want 1", result.Users)
	}
}

func TestScanInfluxDB_AuthRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(401)
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	mod, _ := Get("influxdb")
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*InfluxDBResult)
	if !result.AuthNeeded {
		t.Error("AuthNeeded = false, want true")
	}
}

func TestInfluxDB_ModuleRegistered(t *testing.T) {
	_, ok := Get("influxdb")
	if !ok {
		t.Fatal("influxdb not registered")
	}
}
