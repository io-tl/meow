package main

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"
	"meow/datastore"
	_ "modernc.org/sqlite"
)

// DB represents the database connection
type DB struct {
	*sql.DB
}

// initDB initializes the SQLite database
func initDB(cfg *Config) (*DB, error) {
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, err
	}

	// Set connection pool limits for SQLite
	// SQLite works best with limited concurrent writes
	db.SetMaxOpenConns(1)  // Only one write at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}

	// Set pragmas for performance
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		return nil, err
	}

	if _, err := db.Exec("PRAGMA cache_size=-64000"); err != nil { // 64MB
		return nil, err
	}

	// Set busy timeout to 30 seconds (30000ms) to handle high concurrency
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

// runMigrations runs database migrations from embedded schema.sql
func runMigrations(db *DB) error {
	// Execute embedded schema (SQLite supports multiple statements separated by semicolons)
	if _, err := db.Exec(datastore.SchemaSQL); err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	log.Info().Msg("Database schema loaded successfully")

	// Run additive migrations for existing databases
	if err := migrateEnrichmentFields(db); err != nil {
		log.Warn().Err(err).Msg("Failed to run enrichment fields migration (non-fatal)")
	}

	return nil
}

// migrateEnrichmentFields adds protocol/version/banner columns to service_enrichments
// and backfills them from existing enrichment_data JSON.
func migrateEnrichmentFields(db *DB) error {
	// Check if the columns already exist via PRAGMA table_info
	hasProtocol, err := tableHasColumn(db, "service_enrichments", "protocol")
	if err != nil {
		return fmt.Errorf("failed to check table columns: %w", err)
	}

	if hasProtocol {
		// Columns already exist, just run backfill for any rows still missing data
		result, err := db.Exec(`
			UPDATE service_enrichments SET
				protocol = json_extract(enrichment_data, '$.protocol'),
				version = json_extract(enrichment_data, '$.version'),
				banner = json_extract(enrichment_data, '$.banner')
			WHERE protocol IS NULL AND enrichment_data IS NOT NULL AND enrichment_data != '{}' AND enrichment_data != '' AND json_valid(enrichment_data)
		`)
		if err != nil {
			return fmt.Errorf("failed to backfill enrichment fields: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected > 0 {
			log.Info().Int64("rows", affected).Msg("Backfilled enrichment protocol/version/banner fields")
		}
		return nil
	}

	// Add new columns
	alterStatements := []string{
		"ALTER TABLE service_enrichments ADD COLUMN protocol TEXT",
		"ALTER TABLE service_enrichments ADD COLUMN version TEXT",
		"ALTER TABLE service_enrichments ADD COLUMN banner TEXT",
	}
	for _, stmt := range alterStatements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to alter table: %w", err)
		}
	}
	log.Info().Msg("Added protocol/version/banner columns to service_enrichments")

	// Create indexes
	indexStatements := []string{
		"CREATE INDEX IF NOT EXISTS idx_service_enrichments_protocol ON service_enrichments(protocol) WHERE protocol IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_service_enrichments_version ON service_enrichments(version) WHERE version IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_service_enrichments_banner ON service_enrichments(banner) WHERE banner IS NOT NULL",
	}
	for _, stmt := range indexStatements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Backfill from existing JSON data using json_extract
	result, err := db.Exec(`
		UPDATE service_enrichments SET
			protocol = json_extract(enrichment_data, '$.protocol'),
			version = json_extract(enrichment_data, '$.version'),
			banner = json_extract(enrichment_data, '$.banner')
		WHERE enrichment_data IS NOT NULL AND enrichment_data != '{}' AND enrichment_data != '' AND json_valid(enrichment_data)
	`)
	if err != nil {
		return fmt.Errorf("failed to backfill enrichment fields: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected > 0 {
		log.Info().Int64("rows", affected).Msg("Backfilled enrichment protocol/version/banner fields")
	}

	return nil
}

// tableHasColumn checks if a table has a specific column using PRAGMA table_info.
// Fully drains and closes the rows before returning to avoid holding the connection.
func tableHasColumn(db *DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dfltValue *string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == column {
			found = true
			// Don't break — drain all rows to release the connection
		}
	}
	return found, rows.Err()
}
