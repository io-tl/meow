package main

import (
	"database/sql"
	"testing"

	"meow/datastore"
	_ "modernc.org/sqlite"
)

func TestGetEnrichmentStatusCountsEmptyServices(t *testing.T) {
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()

	if _, err := raw.Exec(datastore.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}

	db := &DB{DB: raw}
	enriched, pending, failed, skipped, err := db.getEnrichmentStatusCounts()
	if err != nil {
		t.Fatalf("getEnrichmentStatusCounts: %v", err)
	}
	if enriched != 0 || pending != 0 || failed != 0 || skipped != 0 {
		t.Fatalf("expected all zero counts, got enriched=%d pending=%d failed=%d skipped=%d", enriched, pending, failed, skipped)
	}
}
