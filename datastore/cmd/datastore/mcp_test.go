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

	seedTestData(t, db)

	t.Cleanup(func() { db.Close() })
	return &mcpHandler{
		db:          &DB{DB: db},
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

// ---------------------------------------------------------------------------
// meow_search
// ---------------------------------------------------------------------------

func TestSearchHostsBasic(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "country:FR",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 FR hosts, got %d", total)
	}
}

func TestSearchHostsByPort(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:22",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 hosts with port 22, got %d", total)
	}
}

func TestSearchHostsCIDR(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "ip:10.0.0.0/24",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 3 {
		t.Errorf("expected 3 hosts in 10.0.0.0/24, got %d", total)
	}
}

func TestSearchServicesMode(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 SSH services, got %d", total)
	}
}

func TestSearchCompoundQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:443 and country:FR",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 1 {
		t.Errorf("expected 1 host with port 443 in FR, got %d", total)
	}
}

func TestSearchSetOperator(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:{22,443}",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 hosts with port 22 or 443, got %d", total)
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

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	count := int(data["count"].(float64))
	page := int(data["page"].(float64))
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
	if count != 1 {
		t.Errorf("expected count=1, got %d", count)
	}
	if page != 2 {
		t.Errorf("expected page=2, got %d", page)
	}
}

// ---------------------------------------------------------------------------
// meow_count
// ---------------------------------------------------------------------------

func TestCountHosts(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "country:FR",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 FR hosts, got %d", total)
	}
}

func TestCountServices(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "service:ssh",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected 2 SSH services, got %d", total)
	}
}

func TestCountCompound(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{
		"query": "port:443 and country:FR",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 1 {
		t.Errorf("expected 1 host with port 443 in FR, got %d", total)
	}
}

func TestCountEmptyQuery(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleCount(context.Background(), callTool(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected tool error for missing query")
	}
}

func TestCountInvalidQuery(t *testing.T) {
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
// meow_host
// ---------------------------------------------------------------------------

func TestHostDetail(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleHost(context.Background(), callTool(map[string]any{
		"ip": "10.0.0.1",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
	certs := data["certs"].([]any)
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

	data := parseResult(t, result)
	certs := data["certs"].([]any)
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

	data := parseResult(t, result)
	certs := data["certs"].([]any)
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

	data := parseResult(t, result)
	certs := data["certs"].([]any)
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

	data := parseResult(t, result)
	total := int(data["total"].(float64))
	if total != 1 {
		t.Errorf("expected 1 domain, got %d", total)
	}
	domains := data["domains"].([]any)
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

	data := parseResult(t, result)
	if data["domain"] != "example.com" {
		t.Errorf("expected domain=example.com, got %v", data["domain"])
	}
	services := data["services"].([]any)
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

	data := parseResult(t, result)
	if int(data["total"].(float64)) != 0 {
		t.Error("expected 0 domains for nonexistent query")
	}
}

func TestDomainsFilterProtocol(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleDomains(context.Background(), callTool(map[string]any{
		"protocol": "https",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	if int(data["total"].(float64)) != 1 {
		t.Errorf("expected 1 domain with https, got %v", data["total"])
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

	// ip_list returns plain text, not JSON
	text := result.Content[0].(mcp.TextContent).Text
	lines := splitNonEmpty(text)
	if len(lines) != 2 {
		t.Errorf("expected 2 ip:port lines, got %d: %q", len(lines), text)
	}
}

func TestExportServices(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"query": "port:443",
		"type":  "services",
	}))
	assertNoError(t, result, err)

	var services []any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &services); err != nil {
		t.Fatalf("json: %v", err)
	}
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

	var hosts []any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &hosts); err != nil {
		t.Fatalf("json: %v", err)
	}
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

	text := result.Content[0].(mcp.TextContent).Text
	lines := splitNonEmpty(text)
	if len(lines) != 6 {
		t.Errorf("expected 6 ip:port lines (all services), got %d", len(lines))
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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
// meow_scanners
// ---------------------------------------------------------------------------

func TestScannersEmpty(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleScanners(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	if int(data["count"].(float64)) != 0 {
		t.Errorf("expected 0 scanners, got %v", data["count"])
	}
}

func TestScannersActive(t *testing.T) {
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

	result, err := h.handleScanners(context.Background(), callTool(map[string]any{}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	if int(data["count"].(float64)) != 1 {
		t.Errorf("expected 1 scanner, got %v", data["count"])
	}
	scanners := data["scanners"].([]any)
	s := scanners[0].(map[string]any)
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
// helpers
// ---------------------------------------------------------------------------

func splitNonEmpty(s string) []string {
	var lines []string
	for _, line := range splitLines(s) {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
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

	data := parseResult(t, result)
	services := data["services"].([]any)
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

	data := parseResult(t, result)
	services := data["services"].([]any)
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

func TestSearchServicesEnrichmentKeys(t *testing.T) {
	h := setupTestMCP(t)
	result, err := h.handleSearch(context.Background(), callTool(map[string]any{
		"query": "port:22",
		"mode":  "services",
	}))
	assertNoError(t, result, err)

	data := parseResult(t, result)
	services := data["services"].([]any)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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

	data := parseResult(t, result)
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
