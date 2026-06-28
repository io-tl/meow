package main

import (
	"flag"
	"fmt"
	"os"
)

type Config struct {
	// NATS connection
	NATSMode string // "embedded" or "client"
	NATSURL  string
	NATSHost string
	NATSPort int

	// NATS authentication
	NATSAuthMode     string // "none", "token", or "user"
	NATSAuthToken    string
	NATSAuthUser     string
	NATSAuthPassword string

	// Consumer
	QueueGroup string

	// Storage
	DBPath string

	// API
	EnableAPI   bool
	APIBind     string
	APIPort     int
	APIPassword string

	// GeoIP
	GeoIPCityPath string
	GeoIPASNPath  string

	// Enrichment
	DomainEnrichThreshold int // Max distinct IPs per domain before skipping enrichment (0 = unlimited)

	// Logging
	Debug bool

	// MCP
	MCPStdio bool // serve MCP over stdio instead of the HTTP API/Web UI
}

func loadConfig() *Config {
	cfg := &Config{}

	// NATS connection
	flag.StringVar(&cfg.NATSURL, "nats-url", "", "NATS server URL (if empty, starts embedded server)")
	flag.StringVar(&cfg.NATSHost, "nats-host", "127.0.0.1", "Listen address for embedded NATS server")
	flag.IntVar(&cfg.NATSPort, "nats-port", 4222, "Port for embedded NATS server")

	// NATS auth (resolved from env after parse)
	var natsToken, natsUser, natsPass string
	flag.StringVar(&natsToken, "nats-token", "", "NATS authentication token (or env: MEOW_NATS_TOKEN)")
	flag.StringVar(&natsUser, "nats-user", "", "NATS username (or env: MEOW_NATS_USER)")
	flag.StringVar(&natsPass, "nats-pass", "", "NATS password (or env: MEOW_NATS_PASS)")

	// Consumer
	flag.StringVar(&cfg.QueueGroup, "queue-group", "datastore-workers", "NATS queue group name")

	// Storage
	flag.StringVar(&cfg.DBPath, "db-path", "./scanner.db", "SQLite database path")

	// API
	var disableAPI bool
	var apiPass string
	flag.BoolVar(&disableAPI, "no-api", false, "Disable REST API and Web UI")
	flag.StringVar(&cfg.APIBind, "api-bind", "127.0.0.1", "API server listen address")
	flag.IntVar(&cfg.APIPort, "api-port", 18080, "API server port")
	flag.StringVar(&apiPass, "api-pass", "", "API password for /api/* endpoints (or env: MEOW_API_PASS)")

	// GeoIP (resolved from env after parse)
	var geoipCity, geoipASN string
	flag.StringVar(&geoipCity, "geoip-city", "", "Path to GeoLite2-City.mmdb (or env: MEOW_GEOIP_CITY)")
	flag.StringVar(&geoipASN, "geoip-asn", "", "Path to GeoLite2-ASN.mmdb (or env: MEOW_GEOIP_ASN)")

	// Enrichment
	flag.IntVar(&cfg.DomainEnrichThreshold, "domain-enrich-threshold", 50, "Skip domain enrichment when domain seen on more than N distinct IPs (0 = unlimited)")

	// Logging
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging (or env: MEOW_DEBUG)")
	flag.BoolVar(&cfg.Debug, "d", false, "Enable debug logging (shorthand)")

	// MCP
	flag.BoolVar(&cfg.MCPStdio, "mcp-stdio", false, "Run as a stdio MCP server (no HTTP API; reads the DB) (or env: MEOW_MCP_STDIO)")

	flag.Usage = printUsage
	flag.Parse()

	// Resolve env vars (flag takes precedence over env; MEOW_* namespace)
	cfg.NATSAuthToken = flagOrEnv(natsToken, "MEOW_NATS_TOKEN")
	cfg.NATSAuthUser = flagOrEnv(natsUser, "MEOW_NATS_USER")
	cfg.NATSAuthPassword = flagOrEnv(natsPass, "MEOW_NATS_PASS")
	cfg.GeoIPCityPath = flagOrEnv(geoipCity, "MEOW_GEOIP_CITY")
	cfg.GeoIPASNPath = flagOrEnv(geoipASN, "MEOW_GEOIP_ASN")
	cfg.APIPassword = flagOrEnv(apiPass, "MEOW_API_PASS")

	// NATS URL: flag takes precedence over env
	if cfg.NATSURL == "" {
		cfg.NATSURL = os.Getenv("MEOW_NATS_URL")
	}

	// MEOW_DEBUG env fallback (flag takes precedence)
	if !cfg.Debug && os.Getenv("MEOW_DEBUG") != "" {
		cfg.Debug = true
	}

	// MEOW_MCP_STDIO env fallback (flag takes precedence)
	if !cfg.MCPStdio && os.Getenv("MEOW_MCP_STDIO") != "" {
		cfg.MCPStdio = true
	}

	// Auto-detect NATS mode
	cfg.NATSMode = "embedded"
	if cfg.NATSURL != "" {
		cfg.NATSMode = "client"
	}

	// Auto-detect auth mode
	cfg.NATSAuthMode = "none"
	if cfg.NATSAuthToken != "" {
		cfg.NATSAuthMode = "token"
	} else if cfg.NATSAuthUser != "" && cfg.NATSAuthPassword != "" {
		cfg.NATSAuthMode = "user"
	}

	cfg.EnableAPI = !disableAPI

	return cfg
}

// flagOrEnv returns the flag value if set (non-empty), otherwise the env var value.
// Flag takes precedence over environment.
func flagOrEnv(flagValue, envKey string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envKey)
}

func printUsage() {
	fmt.Printf(`meow datastore v%s

Usage:
  datastore [flags]

Flags:
  -h, --help         Show help
  -v, --version      Show version
  -d, --debug        Enable debug logging and explain sql (or env: MEOW_DEBUG)

NATS (default: embedded server on 127.0.0.1:4222):
  --nats-url string   Connect to external NATS (e.g., nats://host:4222) (or env: MEOW_NATS_URL)
  --nats-host string  Listen address for embedded server (default: 127.0.0.1)
  --nats-port int     Port for embedded server (default: 4222)
  --nats-token string Auth token (or env: MEOW_NATS_TOKEN)
  --nats-user string  Username (or env: MEOW_NATS_USER)
  --nats-pass string  Password (or env: MEOW_NATS_PASS)

Storage:
  --db-path string    SQLite database path (default: ./scanner.db)

API (default: enabled on 127.0.0.1:18080):
  --no-api            Disable REST API and Web UI
  --api-bind string   API server listen address (default: 127.0.0.1)
  --api-port int      API server port (default: 18080)
  --api-pass string   Require X-API-Key header for /api/* (or env: MEOW_API_PASS)

GeoIP (default: embedded databases):
  --geoip-city string Path to GeoLite2-City.mmdb (or env: MEOW_GEOIP_CITY)
  --geoip-asn string  Path to GeoLite2-ASN.mmdb (or env: MEOW_GEOIP_ASN)

MCP (Model Context Protocol):
  --mcp-stdio         Serve MCP over stdin/stdout instead of the HTTP API/Web UI
                      (reads the DB at --db-path; or env: MEOW_MCP_STDIO)

Advanced:
  --queue-group string          NATS queue group (default: datastore-workers)
  --domain-enrich-threshold int Skip domain enrichment when seen on N+ IPs (default: 50, 0=unlimited)

Examples:
  datastore --debug
  datastore --nats-token="SECRET"
  datastore --api-pass="SECRET" --debug
  datastore --nats-url="nats://prod:4222" --nats-user="admin" --nats-pass="pass"
  datastore --db-path=/data/scan.db --api-port=9090
  datastore --no-api
  datastore --mcp-stdio --db-path=/data/scan.db   # MCP server over stdio

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_NATS_USER   Alternative to --nats-user
  MEOW_NATS_PASS   Alternative to --nats-pass
  MEOW_DEBUG       Alternative to --debug
  MEOW_MCP_STDIO   Alternative to --mcp-stdio
  MEOW_API_PASS    Alternative to --api-pass
  MEOW_GEOIP_CITY  Alternative to --geoip-city
  MEOW_GEOIP_ASN   Alternative to --geoip-asn
`, version)
}
