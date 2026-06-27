package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"meow/datastore"
	_ "modernc.org/sqlite"
)

// DB represents the database connection
type DB struct {
	*sql.DB
	verbose bool
}

type LoggedRow struct {
	row   *sql.Row
	db    *DB
	label string
	query string
	args  []any
	start time.Time
}

// initDB initializes the SQLite database
func initDB(cfg *Config) (*DB, error) {
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, err
	}

	// Set connection pool limits for SQLite
	// SQLite works best with limited concurrent writes
	db.SetMaxOpenConns(1) // Only one write at a time
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

	// Memory-map the database file for faster reads (256MB)
	if _, err := db.Exec("PRAGMA mmap_size=268435456"); err != nil {
		log.Warn().Err(err).Msg("PRAGMA mmap_size failed (non-fatal)")
	}

	return &DB{DB: db, verbose: cfg.Debug}, nil
}

func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.QueryContext(context.Background(), query, args...)
}

func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	label := db.sqlCallerLabel()
	db.traceExplain(ctx, label, query, args)

	start := time.Now()
	rows, err := db.DB.QueryContext(ctx, query, args...)
	db.logSQLResult("query", label, query, args, start, err)
	return rows, err
}

func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.QueryRowContext(context.Background(), query, args...)
}

func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	label := db.sqlCallerLabel()
	db.traceExplain(ctx, label, query, args)

	return db.DB.QueryRowContext(ctx, query, args...)
}

func (db *DB) QueryRowLogged(query string, args ...any) *LoggedRow {
	return db.QueryRowContextLogged(context.Background(), query, args...)
}

func (db *DB) QueryRowContextLogged(ctx context.Context, query string, args ...any) *LoggedRow {
	label := db.sqlCallerLabel()
	db.traceExplain(ctx, label, query, args)
	return &LoggedRow{
		row:   db.DB.QueryRowContext(ctx, query, args...),
		db:    db,
		label: label,
		query: query,
		args:  args,
		start: time.Now(),
	}
}

func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.ExecContext(context.Background(), query, args...)
}

func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	label := db.sqlCallerLabel()
	db.traceExplain(ctx, label, query, args)

	start := time.Now()
	result, err := db.DB.ExecContext(ctx, query, args...)
	db.logSQLResult("exec", label, query, args, start, err)
	return result, err
}

func (db *DB) traceExplain(ctx context.Context, label, query string, args []any) {
	if !db.verbose {
		return
	}

	rows, err := db.DB.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		log.Debug().
			Err(err).
			Str("label", label).
			Str("sql", query).
			Interface("args", args).
			Msg("EXPLAIN QUERY PLAN failed")
		return
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			continue
		}
		prefix := ""
		if parent != 0 {
			prefix = "   "
		}
		lines = append(lines, fmt.Sprintf("%s|--%-3d %s", prefix, id, detail))
	}

	if err := rows.Err(); err != nil {
		log.Debug().
			Err(err).
			Str("label", label).
			Str("sql", query).
			Interface("args", args).
			Msg("EXPLAIN QUERY PLAN rows failed")
		return
	}

	log.Debug().
		Str("label", label).
		Str("sql", query).
		Interface("args", args).
		Str("plan", strings.Join(lines, "\n")).
		Msg("EXPLAIN QUERY PLAN")
}

func (db *DB) logSQLResult(kind, label, query string, args []any, start time.Time, err error) {
	evt := log.Debug().
		Str("kind", kind).
		Str("label", label).
		Str("sql", query).
		Interface("args", args).
		Dur("took", time.Since(start))

	if err != nil {
		evt.Err(err).Msg("SQL failed")
		return
	}

	evt.Msg("SQL done")
}

func (db *DB) sqlCallerLabel() string {
	for skip := 2; skip < 12; skip++ {
		pc, file, line, ok := runtime.Caller(skip)
		if !ok {
			break
		}
		if strings.Contains(file, "/datastore/cmd/datastore/db.go") {
			continue
		}
		fn := runtime.FuncForPC(pc)
		name := ""
		if fn != nil {
			name = fn.Name()
			if idx := strings.LastIndex(name, "."); idx != -1 {
				name = name[idx+1:]
			}
		}
		return fmt.Sprintf("%s:%d %s", filepath.Base(file), line, name)
	}
	return "unknown"
}

func (r *LoggedRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	r.db.logSQLResult("query_row", r.label, r.query, r.args, r.start, err)
	return err
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

	// Drop redundant indexes (covered by primary keys)
	for _, idx := range []string{"idx_http_ip", "idx_service_enrichments_ip_port"} {
		db.Exec("DROP INDEX IF EXISTS " + idx)
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

// allowedMigrationTables lists tables that tableHasColumn is allowed to inspect.
// This prevents SQL injection via the table parameter in PRAGMA table_info().
var allowedMigrationTables = map[string]bool{
	"service_enrichments": true,
}

// tableHasColumn checks if a table has a specific column using PRAGMA table_info.
// The table name is validated against an allowlist to prevent SQL injection.
// Fully drains and closes the rows before returning to avoid holding the connection.
func tableHasColumn(db *DB, table, column string) (bool, error) {
	if !allowedMigrationTables[table] {
		return false, fmt.Errorf("table %q not in migration allowlist", table)
	}

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
