package main

import (
	"database/sql"
	"testing"

	"meow/datastore"
	_ "modernc.org/sqlite"
)

// certHostCount reads the denormalized host_count for a fingerprint.
func certHostCount(t *testing.T, db *DB, fp string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT host_count FROM certificates WHERE fingerprint_sha256 = ?", fp).Scan(&n); err != nil {
		t.Fatalf("read host_count: %v", err)
	}
	return n
}

func newHostCountTestDB(t *testing.T) *DB {
	t.Helper()
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(datastore.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	db := &DB{DB: raw}
	if err := migrateCertHostCount(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// service_certificates has FKs to services(ip,port) and certificates; seed the
	// referenced hosts/services (PRAGMA foreign_keys is ON via schema.sql).
	seed := []string{
		`INSERT INTO hosts (ip, first_seen, last_scan) VALUES ('10.0.0.1', 1000, 2000)`,
		`INSERT INTO hosts (ip, first_seen, last_scan) VALUES ('10.0.0.2', 1000, 2000)`,
		`INSERT INTO services (ip, port, service, detected_at) VALUES ('10.0.0.1', 443, 'https', 1000)`,
		`INSERT INTO services (ip, port, service, detected_at) VALUES ('10.0.0.1', 8443, 'https', 1000)`,
		`INSERT INTO services (ip, port, service, detected_at) VALUES ('10.0.0.2', 443, 'https', 1000)`,
		`INSERT INTO certificates (fingerprint_sha256, subject_cn, not_before, not_after) VALUES ('fp1', 'a.example', 1000, 1900000000)`,
	}
	for _, s := range seed {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("seed: %v\nstmt: %s", err, s)
		}
	}
	t.Cleanup(func() { raw.Close() })
	return db
}

func link(t *testing.T, db *DB, ip string, port int) {
	t.Helper()
	if _, err := db.Exec(`INSERT OR IGNORE INTO service_certificates (ip, port, cert_fingerprint, chain_position)
		VALUES (?, ?, 'fp1', 0)`, ip, port); err != nil {
		t.Fatalf("link %s:%d: %v", ip, port, err)
	}
}

func unlink(t *testing.T, db *DB, ip string, port int) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM service_certificates WHERE ip = ? AND port = ? AND cert_fingerprint = 'fp1'`, ip, port); err != nil {
		t.Fatalf("unlink %s:%d: %v", ip, port, err)
	}
}

// Triggers count DISTINCT ip: multiple ports on one host count once, and the
// count only drops to zero when the last port for a host is removed.
func TestCertHostCountTriggers(t *testing.T) {
	db := newHostCountTestDB(t)

	if got := certHostCount(t, db, "fp1"); got != 0 {
		t.Fatalf("fresh cert host_count = %d, want 0", got)
	}

	link(t, db, "10.0.0.1", 443)
	if got := certHostCount(t, db, "fp1"); got != 1 {
		t.Fatalf("after 1st host host_count = %d, want 1", got)
	}

	// Same host, different port: distinct-ip count must stay 1.
	link(t, db, "10.0.0.1", 8443)
	if got := certHostCount(t, db, "fp1"); got != 1 {
		t.Fatalf("same host 2nd port host_count = %d, want 1", got)
	}

	// Idempotent re-link (INSERT OR IGNORE) must not double count.
	link(t, db, "10.0.0.1", 443)
	if got := certHostCount(t, db, "fp1"); got != 1 {
		t.Fatalf("duplicate link host_count = %d, want 1", got)
	}

	// Second distinct host.
	link(t, db, "10.0.0.2", 443)
	if got := certHostCount(t, db, "fp1"); got != 2 {
		t.Fatalf("two hosts host_count = %d, want 2", got)
	}

	// Remove one port of host 1: still present via the other port.
	unlink(t, db, "10.0.0.1", 443)
	if got := certHostCount(t, db, "fp1"); got != 2 {
		t.Fatalf("host still has a port, host_count = %d, want 2", got)
	}

	// Remove the last port of host 1: now down to 1.
	unlink(t, db, "10.0.0.1", 8443)
	if got := certHostCount(t, db, "fp1"); got != 1 {
		t.Fatalf("host 1 fully removed, host_count = %d, want 1", got)
	}

	unlink(t, db, "10.0.0.2", 443)
	if got := certHostCount(t, db, "fp1"); got != 0 {
		t.Fatalf("all removed, host_count = %d, want 0", got)
	}
}

// migrateCertHostCount must recompute host_count from pre-existing links when the
// column is first added (the upgrade path for an existing database).
func TestCertHostCountBackfill(t *testing.T) {
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	raw.SetMaxOpenConns(1)
	t.Cleanup(func() { raw.Close() })

	// Simulate a legacy database: certificates without the host_count column and
	// no triggers, pre-populated with links.
	legacy := []string{
		`CREATE TABLE certificates (fingerprint_sha256 TEXT PRIMARY KEY, subject_cn TEXT, not_after INTEGER)`,
		`CREATE TABLE service_certificates (ip TEXT, port INTEGER, cert_fingerprint TEXT, chain_position INTEGER,
			PRIMARY KEY (ip, port, cert_fingerprint))`,
		`INSERT INTO certificates VALUES ('fp1', 'a', 1900000000)`,
		`INSERT INTO service_certificates VALUES ('10.0.0.1', 443, 'fp1', 0)`,
		`INSERT INTO service_certificates VALUES ('10.0.0.1', 8443, 'fp1', 0)`, // same host, 2nd port
		`INSERT INTO service_certificates VALUES ('10.0.0.2', 443, 'fp1', 0)`,
	}
	for _, s := range legacy {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("legacy seed: %v", err)
		}
	}

	db := &DB{DB: raw}
	if err := migrateCertHostCount(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 2 distinct hosts despite 3 links.
	if got := certHostCount(t, db, "fp1"); got != 2 {
		t.Fatalf("backfilled host_count = %d, want 2", got)
	}
}
