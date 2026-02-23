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
	Verbose bool
}

func loadConfig() *Config {
	cfg := &Config{}

	// NATS connection
	flag.StringVar(&cfg.NATSURL, "nats-url", "", "NATS server URL (if empty, starts embedded server)")
	flag.StringVar(&cfg.NATSHost, "nats-host", "127.0.0.1", "Listen address for embedded NATS server")
	flag.IntVar(&cfg.NATSPort, "nats-port", 4222, "Port for embedded NATS server")

	// NATS auth (resolved from env after parse)
	var natsToken, natsUser, natsPass string
	flag.StringVar(&natsToken, "nats-token", "", "NATS authentication token (or env: DATASTORE_NATS_TOKEN)")
	flag.StringVar(&natsUser, "nats-user", "", "NATS username (or env: DATASTORE_NATS_USER)")
	flag.StringVar(&natsPass, "nats-pass", "", "NATS password (or env: DATASTORE_NATS_PASSWORD)")

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
	flag.StringVar(&apiPass, "api-pass", "", "API password for /api/* endpoints (or env: DATASTORE_API_PASSWORD)")

	// GeoIP (resolved from env after parse)
	var geoipCity, geoipASN string
	flag.StringVar(&geoipCity, "geoip-city", "", "Path to GeoLite2-City.mmdb (default: embedded)")
	flag.StringVar(&geoipASN, "geoip-asn", "", "Path to GeoLite2-ASN.mmdb (default: embedded)")

	// Enrichment
	flag.IntVar(&cfg.DomainEnrichThreshold, "domain-enrich-threshold", 50, "Skip domain enrichment when domain seen on more than N distinct IPs (0 = unlimited)")

	// Logging
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable debug logging")

	flag.Usage = printUsage
	flag.Parse()

	// Resolve env vars
	cfg.NATSAuthToken = getEnvOrFlag("DATASTORE_NATS_TOKEN", natsToken)
	cfg.NATSAuthUser = getEnvOrFlag("DATASTORE_NATS_USER", natsUser)
	cfg.NATSAuthPassword = getEnvOrFlag("DATASTORE_NATS_PASSWORD", natsPass)
	cfg.GeoIPCityPath = getEnvOrFlag("DATASTORE_GEOIP_CITY", geoipCity)
	cfg.GeoIPASNPath = getEnvOrFlag("DATASTORE_GEOIP_ASN", geoipASN)
	cfg.APIPassword = getEnvOrFlag("DATASTORE_API_PASSWORD", apiPass)

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

// getEnvOrFlag returns environment variable value if set, otherwise returns flag value
func getEnvOrFlag(envKey, flagValue string) string {
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	return flagValue
}

func printUsage() {
	fmt.Printf(`meow datastore v%s - NATS Hub + SQLite Storage + API + Web UI

Usage:
  datastore [flags]

Flags:
  -h, --help         Show this help
  -v, --version      Show version
  -verbose           Enable debug logging

NATS (default: embedded server on 127.0.0.1:4222):
  -nats-url string   Connect to external NATS (e.g., nats://host:4222)
  -nats-host string  Listen address for embedded server (default: 127.0.0.1)
  -nats-port int     Port for embedded server (default: 4222)
  -nats-token string Auth token (or env: DATASTORE_NATS_TOKEN)
  -nats-user string  Username (or env: DATASTORE_NATS_USER)
  -nats-pass string  Password (or env: DATASTORE_NATS_PASSWORD)

Storage:
  -db-path string    SQLite database path (default: ./scanner.db)

API (default: enabled on 127.0.0.1:18080):
  -no-api            Disable REST API and Web UI
  -api-bind string   API server listen address (default: 127.0.0.1)
  -api-port int      API server port (default: 18080)
  -api-pass string   Require X-API-Key header for /api/* (or env: DATASTORE_API_PASSWORD)

GeoIP (default: embedded databases):
  -geoip-city string Path to GeoLite2-City.mmdb (or env: DATASTORE_GEOIP_CITY)
  -geoip-asn string  Path to GeoLite2-ASN.mmdb (or env: DATASTORE_GEOIP_ASN)

Advanced:
  -queue-group string NATS queue group (default: datastore-workers)
  -domain-enrich-threshold int Skip domain enrichment when seen on N+ IPs (default: 50, 0=unlimited)

Examples:
  datastore -verbose
  datastore -nats-token="SECRET"
  datastore -api-pass="SECRET" -verbose
  datastore -nats-url="nats://prod:4222" -nats-user="admin" -nats-pass="pass"
  datastore -db-path=/data/scan.db -api-port=9090
  datastore -no-api

Environment variables:
  DATASTORE_NATS_TOKEN    Alternative to -nats-token
  DATASTORE_NATS_USER     Alternative to -nats-user
  DATASTORE_NATS_PASSWORD Alternative to -nats-pass
  DATASTORE_GEOIP_CITY    Alternative to -geoip-city
  DATASTORE_GEOIP_ASN     Alternative to -geoip-asn
  DATASTORE_API_PASSWORD  Alternative to -api-pass
`, version)
}
