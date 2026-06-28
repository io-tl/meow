package main

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

// runMCPStdio runs the datastore as a stdio MCP server: it serves the MCP
// protocol over stdin/stdout and does NOT start the HTTP API, Web UI, or an
// embedded NATS server. It reads the existing SQLite database (--db-path).
//
// meow_scan is unavailable in this mode (no connected scanners) and
// meow_status omits the scanners section — both handlers already nil-guard
// the scan tracker, so nil dependencies are safe here.
//
// All logging goes to stderr; stdout is reserved for the MCP protocol.
func runMCPStdio(cfg *Config) error {
	db, err := initDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := runMigrations(db); err != nil {
		return err
	}

	srv := newMCPServer(db, nil, nil)
	log.Info().Msg("Meow datastore MCP server ready (stdio)")
	return server.ServeStdio(srv)
}
