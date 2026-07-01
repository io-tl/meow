package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"meow/datastore"
	_ "modernc.org/sqlite"
)

// setupCertTestAPI seeds four certificates spanning the status/algorithm space
// and registers the certificate list + summary endpoints.
//
//	A: valid       (future, not self-signed) RSA 2048, Lets Encrypt
//	B: expired     (past)                    RSA 2048, Lets Encrypt
//	C: self-signed + CA (future)             ECDSA 256, localhost
//	D: self-signed (future)                  RSA 1024, localhost
func setupCertTestAPI(t *testing.T) *gin.Engine {
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
	if err := migrateCertHostCount(wdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const future = 1900000000 // ~2030
	const past = 1000000000   // ~2001
	stmts := []string{
		certInsert("certA", "a.example", "Lets Encrypt", 0, 0, future, "RSA", 2048),
		certInsert("certB", "b.example", "Lets Encrypt", 0, 0, past, "RSA", 2048),
		certInsert("certC", "c.example", "localhost", 1, 1, future, "ECDSA", 256),
		certInsert("certD", "d.example", "localhost", 1, 0, future, "RSA", 1024),
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v\nstmt: %s", err, s)
		}
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := &API{db: wdb}
	r.GET("/api/certificates", api.searchCertificates)
	r.GET("/api/stats/certificates", api.getCertificatesSummary)
	t.Cleanup(func() { db.Close() })
	return r
}

func certInsert(fp, cn, issuer string, selfSigned, isCA, notAfter int, algo string, bits int) string {
	return fmt.Sprintf(`INSERT INTO certificates (fingerprint_sha256, subject_cn, issuer_cn, names,
		not_before, not_after, is_self_signed, is_ca, public_key_algorithm, public_key_bits, first_seen, last_seen)
		VALUES ('%s', '%s', '%s', '["%s"]', 1000, %d, %d, %d, '%s', %d, 1000, 2000)`,
		fp, cn, issuer, cn, notAfter, selfSigned, isCA, algo, bits)
}

func getCerts(t *testing.T, r *gin.Engine, q string) (certs []map[string]any, total int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/certificates?"+q, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("q=%q: expected 200, got %d: %s", q, w.Code, w.Body.String())
	}
	var resp struct {
		Certificates []map[string]any `json:"certificates"`
		Total        int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp.Certificates, resp.Total
}

func TestCertStatusFilters(t *testing.T) {
	r := setupCertTestAPI(t)
	cases := []struct {
		status string
		total  int
	}{
		{"", 4},
		{"expired", 1},
		{"valid", 1},
		{"self-signed", 2},
		{"ca", 1},
	}
	for _, tc := range cases {
		q := ""
		if tc.status != "" {
			q = "status=" + tc.status
		}
		_, total := getCerts(t, r, q)
		if total != tc.total {
			t.Errorf("status=%q: total=%d, want %d", tc.status, total, tc.total)
		}
	}
}

func TestCertAlgoFilter(t *testing.T) {
	r := setupCertTestAPI(t)
	if _, total := getCerts(t, r, "algo=ECDSA"); total != 1 {
		t.Errorf("algo=ECDSA total=%d, want 1", total)
	}
	if _, total := getCerts(t, r, "algo=RSA"); total != 3 {
		t.Errorf("algo=RSA total=%d, want 3", total)
	}
}

func TestCertSortAndPagination(t *testing.T) {
	r := setupCertTestAPI(t)

	// not_after ascending → the expired cert (earliest) comes first.
	certs, total := getCerts(t, r, "sort=not_after&order=asc&limit=1&page=1")
	if total != 4 {
		t.Fatalf("total=%d, want 4", total)
	}
	if fp, _ := certs[0]["fingerprint_sha256"].(string); fp != "certB" {
		t.Errorf("first by not_after asc = %q, want certB", fp)
	}

	// Distinct pages must not overlap (deterministic ordering with tiebreaker).
	p1, _ := getCerts(t, r, "limit=2&page=1")
	p2, _ := getCerts(t, r, "limit=2&page=2")
	seen := map[string]bool{}
	for _, c := range append(p1, p2...) {
		fp, _ := c["fingerprint_sha256"].(string)
		if seen[fp] {
			t.Errorf("fingerprint %q appears on both pages", fp)
		}
		seen[fp] = true
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 distinct certs across 2 pages, got %d", len(seen))
	}
}

// Empty table: COUNT/SUM must not blow up on NULL (regression from smoke test).
func TestCertSummaryEmpty(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(datastore.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := migrateCertHostCount(&DB{DB: db}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/stats/certificates", (&API{db: &DB{DB: db}}).getCertificatesSummary)
	t.Cleanup(func() { db.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/stats/certificates", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("empty summary: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var s map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"total", "valid", "expired", "self_signed", "ca"} {
		if s[k].(float64) != 0 {
			t.Errorf("empty summary %s = %v, want 0", k, s[k])
		}
	}
}

func TestCertSummary(t *testing.T) {
	r := setupCertTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/stats/certificates", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var s struct {
		Total      int `json:"total"`
		Valid      int `json:"valid"`
		Expired    int `json:"expired"`
		SelfSigned int `json:"self_signed"`
		CA         int `json:"ca"`
		TopIssuers []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"top_issuers"`
		TopAlgorithms []struct {
			Name  string `json:"name"`
			Algo  string `json:"algo"`
			Count int    `json:"count"`
		} `json:"top_algorithms"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Total != 4 || s.Valid != 1 || s.Expired != 1 || s.SelfSigned != 2 || s.CA != 1 {
		t.Errorf("summary counts = total:%d valid:%d expired:%d self:%d ca:%d; want 4/1/1/2/1",
			s.Total, s.Valid, s.Expired, s.SelfSigned, s.CA)
	}
	if len(s.TopIssuers) != 2 {
		t.Errorf("expected 2 issuer facets, got %d", len(s.TopIssuers))
	}
	// "RSA 2048" (certA+certB) must be the top algorithm facet, labeled with bits.
	if len(s.TopAlgorithms) == 0 || s.TopAlgorithms[0].Name != "RSA 2048" || s.TopAlgorithms[0].Count != 2 {
		t.Errorf("top algorithm = %+v, want {RSA 2048, count 2}", s.TopAlgorithms)
	}
}
