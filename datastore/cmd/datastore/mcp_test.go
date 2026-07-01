package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"meow/datastore"
	_ "modernc.org/sqlite"
)

// mockPublisher is a test double for the natsPublisher interface.
type mockPublisher struct {
	mu       sync.Mutex
	messages []publishedMsg
	err      error // if set, Publish returns this error
}

type publishedMsg struct {
	Subject string
	Data    []byte
}

func (m *mockPublisher) Publish(subject string, data []byte) error {
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, publishedMsg{Subject: subject, Data: data})
	return nil
}

func (m *mockPublisher) lastMessage() *publishedMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.messages) == 0 {
		return nil
	}
	return &m.messages[len(m.messages)-1]
}

// setupTestMCP creates an mcpHandler with an in-memory SQLite DB seeded with test data.
func setupTestMCP(t *testing.T) *mcpHandler {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(datastore.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	wdb := &DB{DB: db}
	// Install the host_count triggers so seeded service_certificates maintain
	// certificates.host_count exactly as production does.
	if err := migrateCertHostCount(wdb); err != nil {
		t.Fatalf("cert host_count migration: %v", err)
	}

	seedTestData(t, db)

	t.Cleanup(func() { db.Close() })
	return &mcpHandler{
		db:          wdb,
		nc:          &mockPublisher{},
		scanTracker: NewScannerTracker(),
	}
}

func seedTestData(t *testing.T, db *sql.DB) {
	t.Helper()

	stmts := []string{
		// Hosts
		`INSERT INTO hosts (ip, ip_int, country_code, country_name, city, asn, as_org, cloud_provider, cloud_type, first_seen, last_scan, open_ports_count, services_count)
		 VALUES ('10.0.0.1', 167772161, 'FR', 'France', 'Paris', 12345, 'TestOrg', 'aws', 'cloud', 1700000000, 1700001000, 3, 3)`,
		`INSERT INTO hosts (ip, ip_int, country_code, country_name, city, asn, as_org, first_seen, last_scan, open_ports_count, services_count)
		 VALUES ('10.0.0.2', 167772162, 'US', 'United States', 'New York', 15169, 'Google', 1700000000, 1700001000, 2, 2)`,
		`INSERT INTO hosts (ip, ip_int, country_code, country_name, asn, as_org, first_seen, last_scan, open_ports_count, services_count)
		 VALUES ('10.0.0.3', 167772163, 'FR', 'France', 12345, 'TestOrg', 1700000000, 1700001000, 1, 1)`,

		// Services
		`INSERT INTO services (ip, port, service, product, version, banner, banner_hash, detected_at, enrichment_status, enrichment_data)
		 VALUES ('10.0.0.1', 22, 'ssh', 'OpenSSH', '8.9', 'SSH-2.0-OpenSSH_8.9', 'hash_ssh_89', 1700000000, 'enriched', '{"protocol":"ssh","version":"2.0"}')`,
		`INSERT INTO services (ip, port, service, product, version, detected_at, enrichment_status, enrichment_data)
		 VALUES ('10.0.0.1', 443, 'https', 'nginx', '1.24', 1700000000, 'enriched', '{"protocol":"https","status_code":200}')`,
		`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status, enrichment_data)
		 VALUES ('10.0.0.1', 21, 'ftp', 'vsftpd', 1700000000, 'enriched', '{"protocol":"ftp","anonymous_login":true}')`,
		`INSERT INTO services (ip, port, service, product, version, banner, banner_hash, detected_at, enrichment_status)
		 VALUES ('10.0.0.2', 22, 'ssh', 'OpenSSH', '8.9', 'SSH-2.0-OpenSSH_8.9', 'hash_ssh_89', 1700000000, 'enriched')`,
		`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status, enrichment_data)
		 VALUES ('10.0.0.2', 80, 'http', 'Apache', 1700000000, 'enriched', '{"protocol":"http","status_code":200}')`,
		`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status, enrichment_data)
		 VALUES ('10.0.0.3', 6379, 'redis', 'Redis', 1700000000, 'enriched', '{"protocol":"redis","auth_required":false}')`,

		// HTTP data
		`INSERT INTO http_data (ip, port, status_code, server, title, technologies, cms)
		 VALUES ('10.0.0.1', 443, 200, 'nginx/1.24', 'Welcome', '[{"name":"nginx"}]', NULL)`,
		`INSERT INTO http_data (ip, port, status_code, server, title, technologies, cms, framework)
		 VALUES ('10.0.0.2', 80, 200, 'Apache/2.4', 'Admin Panel', '[{"name":"jQuery"},{"name":"WordPress"}]', 'WordPress', 'PHP')`,

		// Certificates
		`INSERT INTO certificates (fingerprint_sha256, subject_cn, issuer_cn, subject_org, names, not_before, not_after, is_self_signed, public_key_algorithm, public_key_bits, signature_algorithm, serial_number, first_seen, last_seen)
		 VALUES ('abc123def456', '*.example.com', 'Let''s Encrypt', 'Example Inc', '["*.example.com","example.com"]', 1690000000, 1900000000, 0, 'RSA', 2048, 'SHA256WithRSA', 'AABB', 1700000000, 1700001000)`,
		`INSERT INTO certificates (fingerprint_sha256, subject_cn, issuer_cn, names, not_before, not_after, is_self_signed, public_key_algorithm, public_key_bits, serial_number, first_seen, last_seen)
		 VALUES ('selfcert789', 'localhost', 'localhost', '["localhost"]', 1690000000, 1600000000, 1, 'RSA', 1024, 'CCDD', 1700000000, 1700001000)`,

		// Service certificates
		`INSERT INTO service_certificates (ip, port, cert_fingerprint, chain_position, jarm, first_seen, last_seen)
		 VALUES ('10.0.0.1', 443, 'abc123def456', 0, 'jarm_fingerprint_abc', 1700000000, 1700001000)`,
		`INSERT INTO service_certificates (ip, port, cert_fingerprint, chain_position, jarm, first_seen, last_seen)
		 VALUES ('10.0.0.2', 80, 'selfcert789', 0, 'jarm_fingerprint_xyz', 1700000000, 1700001000)`,

		// Host domains
		`INSERT INTO host_domains (ip, domain, source, discovered_port, first_seen, last_seen)
		 VALUES ('10.0.0.1', 'example.com', 'certificate', 443, 1700000000, 1700001000)`,
		`INSERT INTO host_domains (ip, domain, source, discovered_port, first_seen, last_seen)
		 VALUES ('10.0.0.1', 'www.example.com', 'certificate', 443, 1700000000, 1700001000)`,

		// Service enrichments (domain-level)
		`INSERT INTO service_enrichments (ip, port, domain, enrichment_data, status, status_code, title, server, protocol, enriched_at)
		 VALUES ('10.0.0.1', 443, 'example.com', '{"protocol":"https","status_code":200}', 'enriched', 200, 'Welcome', 'nginx', 'https', 1700001000)`,
		`INSERT INTO service_enrichments (ip, port, domain, enrichment_data, status, status_code, title, server, protocol, enriched_at)
		 VALUES ('10.0.0.2', 80, 'example.com', '{"protocol":"http","status_code":301}', 'enriched', 301, 'Redirect', 'Apache', 'http', 1700001000)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed data: %v\nstatement: %s", err, stmt)
		}
	}
}

// callTool is a test helper to construct a CallToolRequest and invoke a handler.
func callTool(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

// parseResult unmarshals a tool result text into a map.
func parseResult(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if result == nil {
		t.Fatal("result is nil")
	}
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("result content is not TextContent: %T", result.Content[0])
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text.Text), &data); err != nil {
		t.Fatalf("json unmarshal: %v\nraw: %s", err, text.Text)
	}
	return data
}

// assertNoError checks that the tool result is not an error.
func assertNoError(t *testing.T, result *mcp.CallToolResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		text, _ := result.Content[0].(mcp.TextContent)
		t.Fatalf("tool returned error: %s", text.Text)
	}
}

// envResults parses the unified output envelope { tool, count, truncated, results }
// and returns the results array (always present for successful calls).
func envResults(t *testing.T, result *mcp.CallToolResult) []any {
	t.Helper()
	data := parseResult(t, result)
	res, ok := data["results"].([]any)
	if !ok {
		t.Fatalf("envelope missing results array: %v", data)
	}
	return res
}

// envFirst returns results[0] as an object map. Object-returning tools wrap their
// single object as results = [ <obj> ].
func envFirst(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	res := envResults(t, result)
	if len(res) == 0 {
		t.Fatal("envelope results array is empty")
	}
	m, ok := res[0].(map[string]any)
	if !ok {
		t.Fatalf("results[0] is not an object: %T", res[0])
	}
	return m
}

// envCount returns the envelope's count field (== len(results)).
func envCount(t *testing.T, result *mcp.CallToolResult) int {
	t.Helper()
	data := parseResult(t, result)
	c, ok := data["count"].(float64)
	if !ok {
		t.Fatalf("envelope missing count field: %v", data)
	}
	return int(c)
}

// envTruncated returns the envelope's truncated field.
func envTruncated(t *testing.T, result *mcp.CallToolResult) bool {
	t.Helper()
	data := parseResult(t, result)
	b, ok := data["truncated"].(bool)
	if !ok {
		t.Fatalf("envelope missing truncated field: %v", data)
	}
	return b
}

// ---------------------------------------------------------------------------
// meow_search
// ---------------------------------------------------------------------------

func TestSearchHostsBasic(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "country:FR",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 2 {
		t.Errorf("expected 2 FR hosts, got %d", got)
	}
}

func TestSearchHostsByPort(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:22",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 2 {
		t.Errorf("expected 2 hosts with port 22, got %d", got)
	}
}

func TestSearchHostsCIDR(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "ip:10.0.0.0/24",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 3 {
		t.Errorf("expected 3 hosts in 10.0.0.0/24, got %d", got)
	}
}

func TestSearchServicesMode(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 2 {
		t.Errorf("expected 2 SSH services, got %d", got)
	}
}

// TestSearchExactMatchCaseInsensitive guards that the '=' operator stays
// case-insensitive after switching from LOWER() to COLLATE NOCASE. The host is
// seeded with country_code 'US'; a lowercase literal must still match.
func TestSearchExactMatchCaseInsensitive(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": `country="us"`,
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 1 {
		t.Errorf("expected 1 US host via case-insensitive exact match, got %d", got)
	}
}

// TestSearchServicesExactMatchCaseInsensitive is the services-table counterpart:
// product is seeded as 'OpenSSH', an uppercase exact match must still match.
func TestSearchServicesExactMatchCaseInsensitive(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": `product="OPENSSH"`,
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 2 {
		t.Errorf("expected 2 OpenSSH services via case-insensitive exact match, got %d", got)
	}
}

func TestSearchCompoundQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:443 and country:FR",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 1 {
		t.Errorf("expected 1 host with port 443 in FR, got %d", got)
	}
}

func TestSearchSetOperator(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:{22,443}",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 2 {
		t.Errorf("expected 2 hosts with port 22 or 443, got %d", got)
	}
}

func TestSearchInvalidQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for invalid query")
	}
}

func TestSearchEmptyQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for missing query")
	}
}

func TestSearchPagination(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "ip:10.0.0.0/24",
		"limit": float64(1),
		"page":  float64(2),
	}))
	assertNoError(t, result, err)

	// limit=1 page=2 returns a single host row (offset 1 of 3 matches).
	if count := envCount(t, result); count != 1 {
		t.Errorf("expected count=1, got %d", count)
	}
	// A full page (len >= limit) signals more results may exist.
	if !envTruncated(t, result) {
		t.Error("expected truncated=true when page is filled to its limit")
	}
}

// ---------------------------------------------------------------------------
// meow_count (lightweight count-only query)
// ---------------------------------------------------------------------------

// countTotal reads the single { total: N } object from a meow_count envelope.
func countTotal(t *testing.T, result *mcp.CallToolResult) int {
	t.Helper()
	obj := envFirst(t, result)
	v, ok := obj["total"].(float64)
	if !ok {
		t.Fatalf("count result missing total: %v", obj)
	}
	return int(v)
}

func TestStatsCountHosts(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "country:FR",
	}))
	assertNoError(t, result, err)

	if got := countTotal(t, result); got != 2 {
		t.Errorf("expected 2 FR hosts, got %d", got)
	}
}

func TestStatsCountServices(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	if got := countTotal(t, result); got != 2 {
		t.Errorf("expected 2 SSH services, got %d", got)
	}
}

func TestStatsCountCompound(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "port:443 and country:FR",
	}))
	assertNoError(t, result, err)

	if got := countTotal(t, result); got != 1 {
		t.Errorf("expected 1 host with port 443 in FR, got %d", got)
	}
}

func TestStatsCountInvalidQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "port:",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for invalid query")
	}
}

// ---------------------------------------------------------------------------
// meow_schema (enrichment schema discovery)
// ---------------------------------------------------------------------------

func TestStatsEnrichmentSchemaService(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSchema(context.Background(), callTool(map[string]any{
		"service": "ftp",
	}))
	assertNoError(t, result, err)

	// Per-service schema: results = list of enrichment key entries.
	keys := envResults(t, result)
	if len(keys) == 0 {
		t.Fatal("expected enrichment keys for ftp")
	}
	// FTP test data has: protocol, anonymous_login
	foundAnon := false
	for _, k := range keys {
		entry := k.(map[string]any)
		if entry["key"] == "anonymous_login" {
			foundAnon = true
			if entry["type"] != "integer" {
				// SQLite stores booleans as integers
				t.Errorf("expected type integer for anonymous_login, got %v", entry["type"])
			}
		}
	}
	if !foundAnon {
		t.Error("expected anonymous_login key in ftp enrichment schema")
	}
}

func TestStatsEnrichmentSchemaAll(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSchema(context.Background(), callTool(map[string]any{
		"service": "*",
	}))
	assertNoError(t, result, err)

	// No target → family overview: results = list of {protocol, members, count}.
	families := envResults(t, result)
	if len(families) == 0 {
		t.Fatal("expected families in schema overview")
	}
	// ssh, ftp, redis services are enriched → their canonical families appear.
	// http + https collapse into the single "http" family.
	famNames := make(map[string]map[string]any)
	for _, f := range families {
		entry := f.(map[string]any)
		famNames[entry["protocol"].(string)] = entry
	}
	for _, expected := range []string{"ssh", "ftp", "redis", "http"} {
		if famNames[expected] == nil {
			t.Errorf("expected %s family in schema overview", expected)
		}
	}
	// The "http" family must report BOTH member services seen in the DB.
	httpMembers := famNames["http"]["members"].([]any)
	memberSet := map[string]bool{}
	for _, m := range httpMembers {
		memberSet[m.(string)] = true
	}
	if !memberSet["http"] || !memberSet["https"] {
		t.Errorf("expected http family to include both http and https members, got %v", httpMembers)
	}
}

func TestStatsEnrichmentSchemaSearch(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSchema(context.Background(), callTool(map[string]any{
		"service": "*",
		"search":  "anonymous",
	}))
	assertNoError(t, result, err)

	families := envResults(t, result)
	if len(families) != 1 {
		t.Errorf("expected 1 family with anonymous key, got %d", len(families))
	}
	if len(families) > 0 {
		fam := families[0].(map[string]any)
		if fam["protocol"] != "ftp" {
			t.Errorf("expected ftp family for anonymous search, got %v", fam["protocol"])
		}
	}
}

// TestStatsEnrichmentSchemaProtocolParam verifies the new family-aware
// protocol= param performs a UNION of enrichment keys across all members of a
// protocol family. The http family covers both the http (10.0.0.2:80) and https
// (10.0.0.1:443) services, so status_code must aggregate a count of 2.
func TestStatsEnrichmentSchemaProtocolParam(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSchema(context.Background(), callTool(map[string]any{
		"protocol": "http",
	}))
	assertNoError(t, result, err)

	keys := envResults(t, result)
	if len(keys) == 0 {
		t.Fatal("expected enrichment keys for http family")
	}
	var statusCount int
	found := false
	for _, k := range keys {
		entry := k.(map[string]any)
		if entry["key"] == "status_code" {
			found = true
			statusCount = int(entry["count"].(float64))
		}
	}
	if !found {
		t.Fatal("expected status_code key in http family schema")
	}
	if statusCount != 2 {
		t.Errorf("expected status_code count=2 across http+https members, got %d", statusCount)
	}
}

func TestStatsEnrichmentSchemaSearchPerService(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSchema(context.Background(), callTool(map[string]any{
		"service": "ftp",
		"search":  "protocol",
	}))
	assertNoError(t, result, err)

	keys := envResults(t, result)
	if len(keys) != 1 {
		t.Errorf("expected 1 key matching 'protocol' in ftp, got %d", len(keys))
	}
	if len(keys) > 0 {
		entry := keys[0].(map[string]any)
		if entry["key"] != "protocol" {
			t.Errorf("expected key=protocol, got %v", entry["key"])
		}
	}
}

// ---------------------------------------------------------------------------
// meow_host
// ---------------------------------------------------------------------------

func TestHostDetail(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleHost(context.Background(), callTool(map[string]any{
		"ip": "10.0.0.1",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["ip"] != "10.0.0.1" {
		t.Errorf("expected ip=10.0.0.1, got %v", data["ip"])
	}
	if data["country_code"] != "FR" {
		t.Errorf("expected country=FR, got %v", data["country_code"])
	}

	services, ok := data["services"].([]any)
	if !ok || len(services) != 3 {
		t.Errorf("expected 3 services, got %v", data["services"])
	}

	certs, ok := data["certificates"].([]any)
	if !ok || len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %v", data["certificates"])
	}

	domains, ok := data["domains"].([]any)
	if !ok || len(domains) != 2 {
		t.Errorf("expected 2 domains, got %v", data["domains"])
	}
}

func TestHostDetailNotFound(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleHost(context.Background(), callTool(map[string]any{
		"ip": "99.99.99.99",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for nonexistent host")
	}
}

func TestHostEnrichmentParsed(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleHost(context.Background(), callTool(map[string]any{
		"ip": "10.0.0.1",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	services := data["services"].([]any)

	// FTP service (port 21) should have enrichment.anonymous_login parsed
	for _, s := range services {
		svc := s.(map[string]any)
		if int(svc["port"].(float64)) == 21 {
			if svc["enrichment.anonymous_login"] != true {
				t.Error("expected enrichment.anonymous_login=true for FTP")
			}
			return
		}
	}
	t.Error("FTP service not found")
}

// ---------------------------------------------------------------------------
// meow_stats
// ---------------------------------------------------------------------------

func TestStats(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleStats(context.Background(), callTool(nil))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if int(data["total_hosts"].(float64)) != 3 {
		t.Errorf("expected 3 hosts, got %v", data["total_hosts"])
	}
	if int(data["total_services"].(float64)) != 6 {
		t.Errorf("expected 6 services, got %v", data["total_services"])
	}
	if int(data["total_certificates"].(float64)) != 2 {
		t.Errorf("expected 2 certificates, got %v", data["total_certificates"])
	}

	enrichment := data["enrichment"].(map[string]any)
	if int(enrichment["enriched"].(float64)) != 6 {
		t.Errorf("expected 6 enriched, got %v", enrichment["enriched"])
	}

	topSvc := data["top_services"].([]any)
	if len(topSvc) == 0 {
		t.Error("expected non-empty top_services")
	}
}

// ---------------------------------------------------------------------------
// meow_pivot
// ---------------------------------------------------------------------------

func TestPivotBannerHash(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "banner_hash",
		"value": "hash_ssh_89",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 2 {
		t.Errorf("expected 2 services with same banner hash, got %d", count)
	}
}

func TestPivotJARM(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "jarm",
		"value": "jarm_fingerprint_abc",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 1 {
		t.Errorf("expected 1 service with JARM, got %d", count)
	}
}

func TestPivotCert(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "cert",
		"value": "abc123def456",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 1 {
		t.Errorf("expected 1 service with cert, got %d", count)
	}
}

func TestPivotProduct(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "product",
		"value": "OpenSSH",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 2 {
		t.Errorf("expected 2 OpenSSH services, got %d", count)
	}
}

func TestPivotASN(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "asn",
		"value": "12345",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 2 {
		t.Errorf("expected 2 hosts in ASN 12345, got %d", count)
	}
}

func TestPivotInvalidASN(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handlePivot(context.Background(), callTool(map[string]any{
		"by":    "asn",
		"value": "notanumber",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for invalid ASN")
	}
}

// ---------------------------------------------------------------------------
// meow_certs
// ---------------------------------------------------------------------------

func TestCertsAll(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCerts(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	count := int(data["count"].(float64))
	if count != 2 {
		t.Errorf("expected 2 certs, got %d", count)
	}
}

func TestCertsFilterSelfSigned(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCerts(context.Background(), callTool(map[string]any{
		"filter": "self_signed",
	}))
	assertNoError(t, result, err)

	certs := envResults(t, result)
	if len(certs) != 1 {
		t.Errorf("expected 1 self-signed cert, got %d", len(certs))
	}
	cert := certs[0].(map[string]any)
	if cert["subject_cn"] != "localhost" {
		t.Errorf("expected localhost cert, got %v", cert["subject_cn"])
	}
	if cert["self_signed"] != true {
		t.Error("expected self_signed=true")
	}
}

func TestCertsFilterExpired(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCerts(context.Background(), callTool(map[string]any{
		"filter": "expired",
	}))
	assertNoError(t, result, err)

	certs := envResults(t, result)
	if len(certs) != 1 {
		t.Errorf("expected 1 expired cert, got %d", len(certs))
	}
	cert := certs[0].(map[string]any)
	if cert["status"] != "expired" {
		t.Errorf("expected status=expired, got %v", cert["status"])
	}
}

func TestCertsFilterWeakKey(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCerts(context.Background(), callTool(map[string]any{
		"filter": "weak_key",
		"fields": "fingerprint,subject_cn,bits",
	}))
	assertNoError(t, result, err)

	certs := envResults(t, result)
	if len(certs) != 1 {
		t.Errorf("expected 1 weak key cert, got %d", len(certs))
	}
	cert := certs[0].(map[string]any)
	bits := int(cert["bits"].(float64))
	if bits >= 2048 {
		t.Errorf("expected bits < 2048, got %d", bits)
	}
}

func TestCertsSearch(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCerts(context.Background(), callTool(map[string]any{
		"query": "example.com",
	}))
	assertNoError(t, result, err)

	certs := envResults(t, result)
	if len(certs) != 1 {
		t.Errorf("expected 1 cert matching example.com, got %d", len(certs))
	}
}

// ---------------------------------------------------------------------------
// meow_domains
// ---------------------------------------------------------------------------

func TestDomainsListAll(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDomains(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	domains := envResults(t, result)
	if len(domains) != 1 {
		t.Errorf("expected 1 domain, got %d", len(domains))
	}
	d := domains[0].(map[string]any)
	if d["domain"] != "example.com" {
		t.Errorf("expected example.com, got %v", d["domain"])
	}
	if int(d["services_count"].(float64)) != 2 {
		t.Errorf("expected 2 services for example.com, got %v", d["services_count"])
	}
}

func TestDomainsDetail(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDomains(context.Background(), callTool(map[string]any{
		"domain": "example.com",
	}))
	assertNoError(t, result, err)

	// Detail mode: results = list of services for the domain.
	services := envResults(t, result)
	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

func TestDomainsFilterQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDomains(context.Background(), callTool(map[string]any{
		"query": "nonexistent",
	}))
	assertNoError(t, result, err)

	if envCount(t, result) != 0 {
		t.Error("expected 0 domains for nonexistent query")
	}
}

func TestDomainsFilterProtocol(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDomains(context.Background(), callTool(map[string]any{
		"protocol": "https",
	}))
	assertNoError(t, result, err)

	if got := envCount(t, result); got != 1 {
		t.Errorf("expected 1 domain with https, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// meow_export
// ---------------------------------------------------------------------------

func TestExportIPList(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"type":  "ip_list",
	}))
	assertNoError(t, result, err)

	// ip_list entries are wrapped as results = [{ "value": "ip:port" }, ...]
	lines := envResults(t, result)
	if len(lines) != 2 {
		t.Errorf("expected 2 ip:port entries, got %d", len(lines))
	}
	if first := lines[0].(map[string]any); first["value"] == nil {
		t.Errorf("expected 'value' field on ip_list entry, got %v", first)
	}
}

func TestExportServices(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"query": "port:443",
		"type":  "services",
	}))
	assertNoError(t, result, err)

	services := envResults(t, result)
	if len(services) != 1 {
		t.Errorf("expected 1 service, got %d", len(services))
	}
}

func TestExportHosts(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"query": "country:FR",
		"type":  "hosts",
	}))
	assertNoError(t, result, err)

	hosts := envResults(t, result)
	if len(hosts) != 2 {
		t.Errorf("expected 2 FR hosts, got %d", len(hosts))
	}
}

func TestExportNoFilter(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"type": "ip_list",
	}))
	assertNoError(t, result, err)

	lines := envResults(t, result)
	if len(lines) != 6 {
		t.Errorf("expected 6 ip:port entries (all services), got %d", len(lines))
	}
}

func TestExportInvalidQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"query": "port:",
		"type":  "ip_list",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for invalid query")
	}
}

// ---------------------------------------------------------------------------
// meow_dns
// ---------------------------------------------------------------------------

func TestDNSForward(t *testing.T) {
	h := setupTestMCP(t)
	// Use a well-known domain
	result, err := h.handleDNS(context.Background(), callTool(map[string]any{
		"query": "localhost",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["query"] != "localhost" {
		t.Errorf("expected query=localhost, got %v", data["query"])
	}
}

func TestDNSReverse(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDNS(context.Background(), callTool(map[string]any{
		"query": "127.0.0.1",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["query"] != "127.0.0.1" {
		t.Errorf("expected query=127.0.0.1, got %v", data["query"])
	}
}

func TestDNSMissing(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDNS(context.Background(), callTool(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for missing query")
	}
}

// ---------------------------------------------------------------------------
// meow_status
// ---------------------------------------------------------------------------

func TestStatus(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleStatus(context.Background(), callTool(nil))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if int(data["hosts"].(float64)) != 3 {
		t.Errorf("expected 3 hosts, got %v", data["hosts"])
	}
	if int(data["services"].(float64)) != 6 {
		t.Errorf("expected 6 services, got %v", data["services"])
	}
	if int(data["certificates"].(float64)) != 2 {
		t.Errorf("expected 2 certificates, got %v", data["certificates"])
	}

	enrichment := data["enrichment"].(map[string]any)
	if int(enrichment["enriched"].(float64)) != 6 {
		t.Errorf("expected 6 enriched, got %v", enrichment["enriched"])
	}

	if data["enrichment_rate"] != "100.0%" {
		t.Errorf("expected 100.0%% enrichment rate, got %v", data["enrichment_rate"])
	}

	if int(data["domains"].(float64)) != 1 {
		t.Errorf("expected 1 domain, got %v", data["domains"])
	}

	breakdown := data["service_breakdown"].([]any)
	if len(breakdown) == 0 {
		t.Error("expected non-empty service_breakdown")
	}
}

// ---------------------------------------------------------------------------
// meow_scan
// ---------------------------------------------------------------------------

func TestScanMissingTarget(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleScan(context.Background(), callTool(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for missing target")
	}
}

func TestScanNoScanners(t *testing.T) {
	h := setupTestMCP(t)
	// scanTracker has no active scanners by default
	result, err := h.handleScan(context.Background(), callTool(map[string]any{
		"target": "10.0.0.0/24",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for no active scanners")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "no active scanners") {
		t.Errorf("expected 'no active scanners' in error, got: %s", text)
	}
}

func TestScanSuccess(t *testing.T) {
	h := setupTestMCP(t)
	pub := &mockPublisher{}
	h.nc = pub

	// Register a fake scanner so HasActiveScanners() returns true
	h.scanTracker.UpdateHeartbeat(&ScannerHeartbeat{
		NodeID:   "test-node",
		Hostname: "test-host",
		Status:   "idle",
	})

	result, err := h.handleScan(context.Background(), callTool(map[string]any{
		"target": "10.0.0.0/24",
		"ports":  "1-1024",
		"rate":   float64(5000),
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["request_id"] == nil || data["request_id"] == "" {
		t.Error("expected non-empty request_id")
	}
	if data["message"] != "scan request submitted" {
		t.Errorf("expected message='scan request submitted', got %v", data["message"])
	}
	if data["target"] != "10.0.0.0/24" {
		t.Errorf("expected target=10.0.0.0/24, got %v", data["target"])
	}

	// Verify NATS message was published
	msg := pub.lastMessage()
	if msg == nil {
		t.Fatal("expected a NATS message to be published")
	}
	if msg.Subject != TopicScanRequest {
		t.Errorf("expected subject=%s, got %s", TopicScanRequest, msg.Subject)
	}

	// Verify the published payload
	var scanReq ScanRequest
	if err := json.Unmarshal(msg.Data, &scanReq); err != nil {
		t.Fatalf("unmarshal scan request: %v", err)
	}
	if scanReq.Target != "10.0.0.0/24" {
		t.Errorf("expected target=10.0.0.0/24, got %s", scanReq.Target)
	}
	if scanReq.Ports != "1-1024" {
		t.Errorf("expected ports=1-1024, got %s", scanReq.Ports)
	}
	if scanReq.RateLimit != 5000 {
		t.Errorf("expected rate_limit=5000, got %d", scanReq.RateLimit)
	}
}

func TestScanPublishError(t *testing.T) {
	h := setupTestMCP(t)
	h.nc = &mockPublisher{err: fmt.Errorf("connection closed")}

	h.scanTracker.UpdateHeartbeat(&ScannerHeartbeat{
		NodeID:   "test-node",
		Hostname: "test-host",
		Status:   "idle",
	})

	result, err := h.handleScan(context.Background(), callTool(map[string]any{
		"target": "10.0.0.0/24",
	}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for publish failure")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "failed to publish") {
		t.Errorf("expected 'failed to publish' in error, got: %s", text)
	}
}

// ---------------------------------------------------------------------------
// meow_status — scanners integration (formerly meow_scanners)
// ---------------------------------------------------------------------------

func TestStatusScannersEmpty(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleStatus(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	scanners := data["scanners"].(map[string]any)
	if int(scanners["count"].(float64)) != 0 {
		t.Errorf("expected 0 scanners, got %v", scanners["count"])
	}
}

func TestStatusScannersActive(t *testing.T) {
	h := setupTestMCP(t)
	h.scanTracker.UpdateHeartbeat(&ScannerHeartbeat{
		NodeID:       "node-1",
		Hostname:     "scanner-host",
		Status:       "scanning",
		ScanID:       "scan-abc",
		Transport:    "afpacket",
		PacketsSent:  1000,
		PacketsTotal: 5000,
	})

	result, err := h.handleStatus(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	scannersData := data["scanners"].(map[string]any)
	if int(scannersData["count"].(float64)) != 1 {
		t.Errorf("expected 1 scanner, got %v", scannersData["count"])
	}
	nodes := scannersData["nodes"].([]any)
	s := nodes[0].(map[string]any)
	if s["node_id"] != "node-1" {
		t.Errorf("expected node_id=node-1, got %v", s["node_id"])
	}
	if s["status"] != "scanning" {
		t.Errorf("expected status=scanning, got %v", s["status"])
	}
	if s["scan_id"] != "scan-abc" {
		t.Errorf("expected scan_id=scan-abc, got %v", s["scan_id"])
	}
	if s["transport"] != "afpacket" {
		t.Errorf("expected transport=afpacket, got %v", s["transport"])
	}
	if int(s["packets_sent"].(float64)) != 1000 {
		t.Errorf("expected packets_sent=1000, got %v", s["packets_sent"])
	}
	if int(s["packets_total"].(float64)) != 5000 {
		t.Errorf("expected packets_total=5000, got %v", s["packets_total"])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Field filtering helpers
// ---------------------------------------------------------------------------

func TestParseFieldsParam(t *testing.T) {
	if parseFieldsParam("") != nil {
		t.Error("empty string should return nil")
	}
	if parseFieldsParam("  ,  , ") != nil {
		t.Error("whitespace-only should return nil")
	}
	got := parseFieldsParam("ip, port ,service")
	if len(got) != 3 || !got["ip"] || !got["port"] || !got["service"] {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestResolveFields(t *testing.T) {
	defaults := []string{"a", "b", "c"}
	// No user fields → defaults
	set := resolveFields("", defaults)
	if len(set) != 3 || !set["a"] || !set["b"] || !set["c"] {
		t.Errorf("expected defaults, got %v", set)
	}
	// User override
	set = resolveFields("x,y", defaults)
	if len(set) != 2 || !set["x"] || !set["y"] {
		t.Errorf("expected user fields, got %v", set)
	}
}

func TestFilterRow(t *testing.T) {
	row := map[string]any{"ip": "1.2.3.4", "port": 80, "banner": "long"}
	// Nil allowed → pass-through
	if got := filterRow(row, nil); len(got) != 3 {
		t.Errorf("nil allowed should pass-through, got %v", got)
	}
	// Filter
	allowed := map[string]bool{"ip": true, "port": true}
	got := filterRow(row, allowed)
	if len(got) != 2 || got["banner"] != nil {
		t.Errorf("expected 2 fields without banner, got %v", got)
	}
}

func TestHasFieldPrefix(t *testing.T) {
	fields := map[string]bool{"ip": true, "enrichment.anon": true}
	if !hasFieldPrefix(fields, "enrichment.") {
		t.Error("should find enrichment. prefix")
	}
	if hasFieldPrefix(fields, "http.") {
		t.Error("should not find http. prefix")
	}
}

// ---------------------------------------------------------------------------
// Field filtering integration
// ---------------------------------------------------------------------------

func TestSearchServicesFieldsDefault(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:22",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	services := envResults(t, result)
	if len(services) == 0 {
		t.Fatal("expected services")
	}
	svc := services[0].(map[string]any)
	// Default should include ip, port, service but NOT banner
	if svc["ip"] == nil {
		t.Error("expected ip in default fields")
	}
	if svc["banner"] != nil {
		t.Error("banner should not be in default fields")
	}
}

func TestSearchServicesFieldsCustom(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query":  "port:22",
		"mode":   "services",
		"fields": "ip,port,banner",
	}))
	assertNoError(t, result, err)

	services := envResults(t, result)
	if len(services) == 0 {
		t.Fatal("expected services")
	}
	svc := services[0].(map[string]any)
	// Custom should include banner but NOT service
	if svc["banner"] == nil {
		t.Error("expected banner in custom fields")
	}
	if svc["service"] != nil {
		t.Error("service should not be in custom fields")
	}
}

// TestSearchServicesHTTPTitleProjection guards the fields projection bug: the
// public dotted name http.title must be returnable (the row key used to be the
// underscore http_title, which filterRow could never match).
func TestSearchServicesHTTPTitleProjection(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query":  "port:443",
		"mode":   "services",
		"fields": "ip,port,http.title",
	}))
	assertNoError(t, result, err)

	services := envResults(t, result)
	if len(services) == 0 {
		t.Fatal("expected services")
	}
	svc := services[0].(map[string]any)
	if svc["http.title"] != "Welcome" {
		t.Errorf("expected http.title=Welcome, got %v", svc["http.title"])
	}
	// service was not requested → must be pruned.
	if svc["service"] != nil {
		t.Error("service should be filtered out when not in fields")
	}
}

// TestSearchServicesTotal verifies the envelope reports the full match count
// across all pages, not just the current page length.
func TestSearchServicesTotal(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"mode":  "services",
		"limit": float64(1),
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total, ok := data["total"].(float64)
	if !ok {
		t.Fatalf("envelope missing total field: %v", data)
	}
	if int(total) != 2 {
		t.Errorf("expected total=2 SSH services, got %v", total)
	}
	if got := envCount(t, result); got != 1 {
		t.Errorf("expected count=1 (limited to 1), got %d", got)
	}
	if !envTruncated(t, result) {
		t.Error("expected truncated=true (1 returned of 2 total)")
	}
}

// TestSearchServicesEnrichmentOptIn verifies the enrichment_data JSON is not
// surfaced when the caller requests only cheap columns (the dynamic SELECT skips
// reading it entirely).
func TestSearchServicesEnrichmentOptIn(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query":  "port:22",
		"mode":   "services",
		"fields": "ip,port",
	}))
	assertNoError(t, result, err)

	for _, s := range envResults(t, result) {
		svc := s.(map[string]any)
		if svc["enrichment_keys"] != nil {
			t.Error("enrichment_keys should be absent when fields=ip,port")
		}
		if hasEnrichmentKey(svc) {
			t.Error("no enrichment.* values should appear when fields=ip,port")
		}
	}
}

func hasEnrichmentKey(m map[string]any) bool {
	for k := range m {
		if len(k) > len("enrichment.") && k[:len("enrichment.")] == "enrichment." {
			return true
		}
	}
	return false
}

func TestSearchServicesEnrichmentKeys(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:22",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	services := envResults(t, result)
	if len(services) == 0 {
		t.Fatal("expected services")
	}
	// At least one SSH service should have enrichment_keys
	found := false
	for _, s := range services {
		svc := s.(map[string]any)
		if svc["enrichment_keys"] != nil {
			found = true
			keys := svc["enrichment_keys"].([]any)
			if len(keys) == 0 {
				t.Error("enrichment_keys should not be empty when present")
			}
		}
	}
	if !found {
		t.Error("expected at least one service with enrichment_keys")
	}
}

func TestHostSectionsFilter(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleHost(context.Background(), callTool(map[string]any{
		"ip":       "10.0.0.1",
		"sections": "services",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["services"] == nil {
		t.Error("expected services section")
	}
	if data["certificates"] != nil {
		t.Error("certificates should be omitted when sections=services")
	}
	if data["domains"] != nil {
		t.Error("domains should be omitted when sections=services")
	}
}

func TestStatsFieldsDefault(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleStats(context.Background(), callTool(nil))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	// Defaults should include top_services but NOT cloud_providers
	if data["top_services"] == nil {
		t.Error("expected top_services in default stats")
	}
	if data["cloud_providers"] != nil {
		t.Error("cloud_providers should not be in default stats")
	}
	if data["top_products"] != nil {
		t.Error("top_products should not be in default stats")
	}
}

func TestStatsFieldsCustom(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleStats(context.Background(), callTool(map[string]any{
		"fields": "total_hosts,cloud_providers",
	}))
	assertNoError(t, result, err)

	data := envFirst(t, result)
	if data["total_hosts"] == nil {
		t.Error("expected total_hosts")
	}
	if data["cloud_providers"] == nil {
		t.Error("expected cloud_providers when explicitly requested")
	}
	if data["top_services"] != nil {
		t.Error("top_services should not appear when not requested")
	}
}
