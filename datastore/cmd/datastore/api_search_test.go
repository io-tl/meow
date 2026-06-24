package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"meow/datastore"
	_ "modernc.org/sqlite"
)

// setupTestAPI creates a gin engine with a minimal in-memory SQLite DB
// and the search API endpoints registered.
func setupTestAPI(t *testing.T) (*gin.Engine, *API) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)

	// Load schema
	if _, err := db.Exec(datastore.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}

	// Insert test data
	if _, err := db.Exec(`INSERT INTO hosts (ip, country_code, asn, first_seen, last_scan, open_ports_count, services_count) VALUES ('1.2.3.4', 'US', 15169, 1000, 2000, 1, 1)`); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status) VALUES ('1.2.3.4', 443, 'https', 'nginx', 1000, 'enriched')`); err != nil {
		t.Fatalf("insert service: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := &API{db: &DB{DB: db}}

	r.GET("/api/search", api.searchQuery)
	r.GET("/api/search/services", api.searchQueryServices)
	r.GET("/api/hosts", api.searchHosts)

	t.Cleanup(func() { db.Close() })
	return r, api
}

// doSearchQ performs a GET request to the given endpoint with q= properly URL-encoded.
func doSearchQ(r *gin.Engine, endpoint, q string) *httptest.ResponseRecorder {
	u := endpoint + "?q=" + url.QueryEscape(q)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// doSearchParams performs a GET request with URL-encoded query parameters.
func doSearchParams(r *gin.Engine, endpoint string, params map[string]string) *httptest.ResponseRecorder {
	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	u := endpoint + "?" + v.Encode()
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// --- SQL Injection via MeowQL q= parameter ---

func TestAPISearchSQLInjectionValues(t *testing.T) {
	r, _ := setupTestAPI(t)

	payloads := []string{
		// Classic injections
		`service:"' OR '1'='1"`,
		`service:"'; DROP TABLE hosts--"`,
		`service:"' UNION SELECT * FROM hosts--"`,
		`country:"' AND 1=1--"`,
		`banner:"' OR 1=1#"`,
		// Numeric field with string injection
		`port:443`,
		// JSON path injection in value
		`enrichment.key:"' OR 1=1--"`,
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			w := doSearchQ(r, "/api/search", payload)
			// Should return 200 (safe parameterized query) or 400 (rejected by parser)
			// Must NEVER return 500 from a SQL syntax error caused by injection
			if w.Code == 500 {
				var resp map[string]any
				json.Unmarshal(w.Body.Bytes(), &resp)
				t.Errorf("got 500 for payload %q, response: %v", payload, resp)
			}
		})
	}
}

func TestAPISearchServicesSQLInjectionValues(t *testing.T) {
	r, _ := setupTestAPI(t)

	payloads := []string{
		`service:"' OR '1'='1"`,
		`service:"' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18--"`,
		`enrichment.key:"'; DROP TABLE services--"`,
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			w := doSearchQ(r, "/api/search/services", payload)
			if w.Code == 500 {
				var resp map[string]any
				json.Unmarshal(w.Body.Bytes(), &resp)
				t.Errorf("got 500 for payload %q, response: %v", payload, resp)
			}
		})
	}
}

// --- JSON path injection via field names ---

func TestAPISearchSQLInjectionJSONPath(t *testing.T) {
	r, _ := setupTestAPI(t)

	// These should be rejected at the MeowQL level (unknown field)
	// and return 400, never 500
	injections := []string{
		`enrichment.x' OR 1=1--:test`,
		`enrichment.x') UNION SELECT 1--:test`,
		`enrichment.x;DROP TABLE hosts:test`,
	}

	for _, inj := range injections {
		t.Run(inj, func(t *testing.T) {
			w := doSearchQ(r, "/api/search", inj)
			if w.Code == 500 {
				t.Errorf("got 500 for JSON path injection %q", inj)
			}
		})
	}
}

// --- Error message does NOT leak SQL ---

func TestAPISearchErrorDoesNotLeakSQL(t *testing.T) {
	r, _ := setupTestAPI(t)

	// Invalid MeowQL that causes parse error → 400
	w := doSearchQ(r, "/api/search", "port:")
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad MeowQL, got %d", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	errMsg, _ := resp["error"].(string)
	// The error should be a parse error, not SQL
	if strings.Contains(errMsg, "SELECT") || strings.Contains(errMsg, "FROM hosts") {
		t.Errorf("error message leaks SQL: %s", errMsg)
	}
}

func TestAPISearch500DoesNotLeakSQLDetail(t *testing.T) {
	r, _ := setupTestAPI(t)

	// A valid MeowQL query on a healthy DB should return 200
	w := doSearchQ(r, "/api/search", "port:443")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Verify no "detail" key exists in responses
	if _, ok := resp["detail"]; ok {
		t.Error("response should not contain 'detail' key")
	}
}

// --- Traditional API filter injection (/api/hosts) ---

func TestAPIHostsFilterSQLInjection(t *testing.T) {
	r, _ := setupTestAPI(t)

	tests := []struct {
		name   string
		params map[string]string
	}{
		{"q_sqli", map[string]string{"q": "' OR 1=1--"}},
		{"q_union", map[string]string{"q": "' UNION SELECT 1,2,3--"}},
		{"country_sqli", map[string]string{"country": "' OR '1'='1"}},
		{"cloud_sqli", map[string]string{"cloud": "' OR '1'='1"}},
		{"asn_non_numeric", map[string]string{"asn": "abc; DROP TABLE hosts"}},
		{"port_non_numeric", map[string]string{"port": "abc; DROP TABLE hosts"}},
		{"service_sqli", map[string]string{"service": "' OR 1=1--"}},
		{"technology_sqli", map[string]string{"technology": "' OR 1=1--"}},
		{"combined_sqli", map[string]string{"port": "443", "service": "' OR 1=1--"}},
		{"combined_tech_sqli", map[string]string{"port": "443", "technology": "' UNION SELECT 1--"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doSearchParams(r, "/api/hosts", tt.params)
			// Must not crash (500 from SQL injection), must be 200
			if w.Code == 500 {
				var resp map[string]any
				json.Unmarshal(w.Body.Bytes(), &resp)
				errMsg, _ := resp["error"].(string)
				t.Errorf("got 500 (possible injection): error=%q", errMsg)
			}
		})
	}
}

func TestAPIHostsVerifiedPortFilterUsesSameServiceRow(t *testing.T) {
	r, api := setupTestAPI(t)

	// Host 1.2.3.4 already has a verified 443 service from setup; add a ghost 80 port.
	if _, err := api.db.Exec(`INSERT INTO services (ip, port, detected_at) VALUES ('1.2.3.4', 80, 1100)`); err != nil {
		t.Fatalf("insert ghost service: %v", err)
	}

	// A second host has port 80 identified and should remain visible.
	if _, err := api.db.Exec(`INSERT INTO hosts (ip, country_code, asn, first_seen, last_scan, open_ports_count, services_count) VALUES ('5.6.7.8', 'US', 64512, 1000, 3000, 1, 1)`); err != nil {
		t.Fatalf("insert second host: %v", err)
	}
	if _, err := api.db.Exec(`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status) VALUES ('5.6.7.8', 80, 'http', 'Apache', 1200, 'enriched')`); err != nil {
		t.Fatalf("insert verified 80 service: %v", err)
	}

	w := doSearchParams(r, "/api/hosts", map[string]string{
		"port":     "80",
		"verified": "true",
	})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Hosts []map[string]any `json:"hosts"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Total != 1 {
		t.Fatalf("expected 1 host, got %d", resp.Total)
	}
	if len(resp.Hosts) != 1 {
		t.Fatalf("expected 1 host in payload, got %d", len(resp.Hosts))
	}

	gotIP, _ := resp.Hosts[0]["ip"].(string)
	if gotIP != "5.6.7.8" {
		t.Fatalf("expected only host 5.6.7.8, got %q", gotIP)
	}

	services, _ := resp.Hosts[0]["services"].([]any)
	if len(services) != 1 {
		t.Fatalf("expected one listed service for matching host, got %d", len(services))
	}
	svc, _ := services[0].(map[string]any)
	portVal, _ := svc["port"].(float64)
	if strconv.Itoa(int(portVal)) != "80" {
		t.Fatalf("expected listed service port 80, got %#v", svc["port"])
	}
}

// --- Verify safe queries still work ---

func TestAPISearchLegitQueries(t *testing.T) {
	r, _ := setupTestAPI(t)

	queries := []string{
		"port:443",
		`service:"https"`,
		"country:US",
		`port:443 and country:US`,
		"asn:15169",
	}

	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			w := doSearchQ(r, "/api/search", q)
			if w.Code != 200 {
				t.Errorf("expected 200 for %q, got %d: %s", q, w.Code, w.Body.String())
			}

			var resp map[string]any
			json.Unmarshal(w.Body.Bytes(), &resp)

			if _, ok := resp["hosts"]; !ok {
				t.Errorf("response missing 'hosts' key for %q", q)
			}
			if _, ok := resp["total"]; !ok {
				t.Errorf("response missing 'total' key for %q", q)
			}
		})
	}
}

func TestAPISearchServicesLegitQueries(t *testing.T) {
	r, _ := setupTestAPI(t)

	queries := []string{
		"port:443",
		`service:"https"`,
	}

	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			w := doSearchQ(r, "/api/search/services", q)
			if w.Code != 200 {
				t.Errorf("expected 200 for %q, got %d: %s", q, w.Code, w.Body.String())
			}
		})
	}
}

// --- Empty/malformed queries ---

func TestAPISearchEmptyQuery(t *testing.T) {
	r, _ := setupTestAPI(t)

	w := doSearchQ(r, "/api/search", "")
	if w.Code != 200 {
		t.Errorf("empty query should return 200, got %d", w.Code)
	}
}

func TestAPISearchMalformedQueries(t *testing.T) {
	r, _ := setupTestAPI(t)

	malformed := []string{
		"port:",
		":443",
		"port:443 and",
		"((port:443)",
		"nonexistent:value",
	}

	for _, q := range malformed {
		t.Run(q, func(t *testing.T) {
			w := doSearchQ(r, "/api/search", q)
			if w.Code != 400 {
				t.Errorf("expected 400 for malformed %q, got %d", q, w.Code)
			}
		})
	}
}
