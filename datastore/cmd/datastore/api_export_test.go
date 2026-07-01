package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
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

// bannerWithComma exercises CSV quoting (RFC 4180) and field integrity.
const bannerWithComma = `Server: nginx, "edge", v1.0`

// setupExportTestAPI builds an in-memory DB seeded with two hosts in distinct
// countries, each with a service, a certificate and a domain, and registers the
// /api/export route. The cross-country layout lets us assert that filters are
// actually applied (notably for certificates and domains).
func setupExportTestAPI(t *testing.T) *gin.Engine {
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

	stmts := []string{
		`INSERT INTO hosts (ip, country_code, asn, as_org, cloud_provider, cloud_type, city, first_seen, last_scan, open_ports_count, services_count)
		 VALUES ('1.1.1.1', 'FR', 100, 'FrOrg', 'aws', 'cloud', 'Paris', 1000, 2000, 1, 1)`,
		`INSERT INTO hosts (ip, country_code, asn, as_org, first_seen, last_scan, open_ports_count, services_count)
		 VALUES ('2.2.2.2', 'US', 200, 'UsOrg', 1000, 2000, 1, 1)`,

		`INSERT INTO services (ip, port, service, product, version, banner, detected_at, enrichment_status)
		 VALUES ('1.1.1.1', 443, 'https', 'nginx', '1.0', '` + bannerWithComma + `', 1000, 'enriched')`,
		`INSERT INTO services (ip, port, service, product, detected_at, enrichment_status)
		 VALUES ('2.2.2.2', 22, 'ssh', 'OpenSSH', 1000, 'enriched')`,

		`INSERT INTO certificates (fingerprint_sha256, subject_cn, subject_org, issuer_cn, issuer_org, names, not_before, not_after, serial_number, is_self_signed, is_ca, first_seen, last_seen)
		 VALUES ('fprFR', 'fr.example.com', 'FrOrg', 'Lets Encrypt', 'LE', '["fr.example.com"]', 1000, 1900000000, 'AA', 0, 0, 1000, 2000)`,
		`INSERT INTO certificates (fingerprint_sha256, subject_cn, subject_org, issuer_cn, issuer_org, names, not_before, not_after, serial_number, is_self_signed, is_ca, first_seen, last_seen)
		 VALUES ('fprUS', 'us.example.com', 'UsOrg', 'Lets Encrypt', 'LE', '["us.example.com"]', 1000, 1900000000, 'BB', 0, 0, 1000, 2000)`,

		`INSERT INTO service_certificates (ip, port, cert_fingerprint, chain_position, first_seen, last_seen)
		 VALUES ('1.1.1.1', 443, 'fprFR', 0, 1000, 2000)`,
		`INSERT INTO service_certificates (ip, port, cert_fingerprint, chain_position, first_seen, last_seen)
		 VALUES ('2.2.2.2', 22, 'fprUS', 0, 1000, 2000)`,

		`INSERT INTO host_domains (ip, domain, source, discovered_port, first_seen, last_seen)
		 VALUES ('1.1.1.1', 'fr.example.com', 'certificate', 443, 1000, 2000)`,
		`INSERT INTO host_domains (ip, domain, source, discovered_port, first_seen, last_seen)
		 VALUES ('2.2.2.2', 'us.example.com', 'certificate', 22, 1000, 2000)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v\nstmt: %s", err, s)
		}
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := &API{db: wdb}
	r.GET("/api/export", api.exportData)
	r.GET("/api/certificates", api.searchCertificates)
	r.GET("/api/search", api.searchQuery)
	t.Cleanup(func() { db.Close() })
	return r
}

// doExport performs GET /api/export with the given query params.
func doExport(r *gin.Engine, params map[string]string) *httptest.ResponseRecorder {
	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/export?"+v.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// --- Validation ---

func TestExportInvalidFormat(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"format": "xml"})
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad format, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportInvalidType(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"type": "garbage"})
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad type, got %d: %s", w.Code, w.Body.String())
	}
}

// txt must validate the type too (regression: txt used to ignore type and
// silently return an ip:port list with HTTP 200).
func TestExportTxtInvalidType(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"format": "txt", "type": "garbage"})
	if w.Code != 400 {
		t.Fatalf("expected 400 for txt+bad type, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Certificate filters actually apply (A1 bug fix) ---

func TestExportCertificatesFilterByCountry(t *testing.T) {
	r := setupExportTestAPI(t)

	// Without filter: both certs present.
	w := doExport(r, map[string]string{"type": "certificates"})
	all := decodeExportData(t, w)
	if len(all) != 2 {
		t.Fatalf("expected 2 certs unfiltered, got %d: %s", len(all), w.Body.String())
	}

	// country=US must return only the US-linked certificate.
	w = doExport(r, map[string]string{"type": "certificates", "country": "US"})
	got := decodeExportData(t, w)
	if len(got) != 1 {
		t.Fatalf("expected 1 cert for country=US, got %d: %s", len(got), w.Body.String())
	}
	if fp, _ := got[0]["fingerprint_sha256"].(string); fp != "fprUS" {
		t.Fatalf("expected fprUS, got %q", fp)
	}
	// Enriched columns must be present.
	for _, k := range []string{"subject_org", "issuer_org", "names", "host_count", "is_self_signed"} {
		if _, ok := got[0][k]; !ok {
			t.Errorf("certificate export missing enriched field %q", k)
		}
	}
}

// --- txt is type-aware (A2) ---

func TestExportTxtTypeAware(t *testing.T) {
	r := setupExportTestAPI(t)

	cases := []struct {
		dtype    string
		contains string
		reject   string // must NOT be present
	}{
		{"hosts", "1.1.1.1\n", "1.1.1.1:"}, // bare IP, never ip:port
		{"services", "1.1.1.1:443", ""},    // ip:port
		{"domains", "fr.example.com", ""},  // domain
		{"certificates", "fprFR", ""},      // fingerprint
	}
	for _, tc := range cases {
		t.Run(tc.dtype, func(t *testing.T) {
			w := doExport(r, map[string]string{"format": "txt", "type": tc.dtype})
			if w.Code != 200 {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, tc.contains) {
				t.Errorf("txt/%s: expected to contain %q, got:\n%s", tc.dtype, tc.contains, body)
			}
			if tc.reject != "" && strings.Contains(body, tc.reject) {
				t.Errorf("txt/%s: should not contain %q, got:\n%s", tc.dtype, tc.reject, body)
			}
		})
	}
}

// --- domains export (B1) ---

func TestExportDomainsJSON(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"type": "domains"})
	data := decodeExportData(t, w)
	if len(data) != 2 {
		t.Fatalf("expected 2 domains, got %d: %s", len(data), w.Body.String())
	}
	found := false
	for _, d := range data {
		if d["domain"] == "fr.example.com" {
			found = true
			if _, ok := d["ip_count"]; !ok {
				t.Error("domain export missing ip_count")
			}
			if _, ok := d["ips"]; !ok {
				t.Error("domain export missing ips")
			}
		}
	}
	if !found {
		t.Errorf("fr.example.com not found in domains export: %s", w.Body.String())
	}

	// Filtered by country: only the FR domain.
	w = doExport(r, map[string]string{"type": "domains", "country": "FR"})
	got := decodeExportData(t, w)
	if len(got) != 1 || got[0]["domain"] != "fr.example.com" {
		t.Fatalf("expected only fr.example.com for country=FR, got %s", w.Body.String())
	}
}

// A host-level MeowQL query (e.g. country:FR) compiles service-centric to
// reference the hosts alias; the hosts export services sub-fetch must join hosts
// so ports are still populated (regression: they used to come back empty).
func TestExportHostsPortsWithHostQuery(t *testing.T) {
	r := setupExportTestAPI(t)

	// JSON: host 1.1.1.1 (FR) must still carry its service on port 443.
	data := decodeExportData(t, doExport(r, map[string]string{"type": "hosts", "q": "country:FR"}))
	if len(data) != 1 {
		t.Fatalf("expected 1 FR host, got %d", len(data))
	}
	svcs, _ := data[0]["services"].([]any)
	if len(svcs) == 0 {
		t.Fatalf("host lost its services under host-level query: %v", data[0])
	}

	// CSV: the ports column must be non-empty.
	w := doExport(r, map[string]string{"format": "csv", "type": "hosts", "q": "country:FR"})
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	portsIdx := len(records[0]) - 1 // "ports" is the last column
	if records[0][portsIdx] != "ports" {
		t.Fatalf("last column is not 'ports': %v", records[0])
	}
	if len(records) < 2 || records[1][portsIdx] == "" {
		t.Errorf("ports column empty under host-level query; rows=%v", records[1:])
	}
}

// --- CSV correctness (C3) ---

func TestExportServicesCSV(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"format": "csv", "type": "services"})
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("expected text/csv content-type, got %q", ct)
	}

	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("CSV does not parse cleanly: %v\n%s", err, w.Body.String())
	}
	if len(records) < 2 {
		t.Fatalf("expected header + rows, got %d records", len(records))
	}

	header := records[0]
	wantCols := map[string]int{}
	for i, h := range header {
		wantCols[h] = i
	}
	for _, col := range []string{"banner", "country_code", "cloud_provider"} {
		if _, ok := wantCols[col]; !ok {
			t.Errorf("services CSV header missing column %q (header=%v)", col, header)
		}
	}

	// The banner containing a comma and quotes must survive round-trip intact.
	var bannerOK bool
	bIdx := wantCols["banner"]
	for _, row := range records[1:] {
		if row[0] == "1.1.1.1" && row[bIdx] == bannerWithComma {
			bannerOK = true
		}
	}
	if !bannerOK {
		t.Errorf("banner with comma/quotes was not preserved through CSV; records=%v", records[1:])
	}
}

// --- JSON empty returns [] not null (A3) ---

func TestExportJSONEmpty(t *testing.T) {
	r := setupExportTestAPI(t)
	w := doExport(r, map[string]string{"type": "hosts", "country": "ZZ"})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Data  []map[string]any `json:"data"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 0 {
		t.Errorf("expected count 0, got %d", resp.Count)
	}
	// data must be present as an array, not JSON null.
	if !strings.Contains(w.Body.String(), `"data":[]`) {
		t.Errorf("expected empty data array, got %s", w.Body.String())
	}
}

// decodeExportData extracts the .data array from a JSON export response.
func decodeExportData(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal export: %v\n%s", err, w.Body.String())
	}
	return resp.Data
}

// --- A1: the requested limit is honored, no hard cap (Plan 2) ---

func TestSearchLimitNotCapped(t *testing.T) {
	r := setupExportTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/search?limit=100000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Limit != 100000 {
		t.Errorf("requested limit 100000 should be honored, got %d (still capped?)", resp.Limit)
	}
}

// --- A2: certificate pagination via offset, with a total count ---

func TestCertificatesPagination(t *testing.T) {
	r := setupExportTestAPI(t)

	get := func(page int) (fp string, total int) {
		u := "/api/certificates?limit=1&page=" + strconv.Itoa(page)
		req := httptest.NewRequest(http.MethodGet, u, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("page %d: expected 200, got %d: %s", page, w.Code, w.Body.String())
		}
		var resp struct {
			Certificates []map[string]any `json:"certificates"`
			Total        int              `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Certificates) != 1 {
			t.Fatalf("page %d: expected 1 cert, got %d", page, len(resp.Certificates))
		}
		f, _ := resp.Certificates[0]["fingerprint_sha256"].(string)
		return f, resp.Total
	}

	fp1, total1 := get(1)
	fp2, total2 := get(2)
	if total1 != 2 || total2 != 2 {
		t.Errorf("expected total 2 on both pages, got %d and %d", total1, total2)
	}
	if fp1 == fp2 {
		t.Errorf("pages 1 and 2 returned the same cert %q (offset not applied)", fp1)
	}
}

// --- A3: export pagination via offset ---

func TestExportPagination(t *testing.T) {
	r := setupExportTestAPI(t)

	page := func(p int) map[string]any {
		w := doExport(r, map[string]string{"type": "services", "limit": "1", "page": strconv.Itoa(p)})
		data := decodeExportData(t, w)
		if len(data) != 1 {
			t.Fatalf("page %d: expected 1 service, got %d", p, len(data))
		}
		return data[0]
	}
	key := func(m map[string]any) string { return fmt.Sprintf("%v:%v", m["ip"], m["port"]) }
	if key(page(1)) == key(page(2)) {
		t.Errorf("export pages 1 and 2 returned the same row (offset not applied)")
	}
}
