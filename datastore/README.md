# 🐱 Meow Datastore

**Central hub of the Meow network scanner** — Embedded NATS server, SQLite storage, REST API and Web UI.

The datastore collects scan results in real time (open ports, fingerprints, protocol enrichments) via NATS, persists them in SQLite and exposes a full web interface + API for data exploration.

---

## Architecture

```
                        ┌──────────────────────────────────┐
  SynScan ──────────────┤                                  │
   scan.port.open       │         DATASTORE                │
                        │                                  │
  Grabber (finger) ─────┤  Embedded NATS Server            │
   scan.port.fingerprint│  Consumer (3 topics)             │──── Web UI :18080
                        │  SQLite (WAL, single writer)     │──── REST API /api/*
  Grabber (enrich) ─────┤  GeoIP (optional)                │──── MCP /mcp
   scan.port.enriched   │                                  │
                        └──────────────────────────────────┘
```

The datastore subscribes to three NATS topics:

| Topic | Source | Data |
|-------|--------|------|
| `scan.port.open` | SynScan | IP + open port |
| `scan.port.fingerprinted` | Grabber finger | Service, product, version, TLS certificates |
| `scan.port.enriched` | Grabber enrich | Protocol data, HTTP, technologies |

---

## Quick Start

### Build

```bash
go build -o datastore ./cmd/datastore/
```

## Usage

Local usage listen on 127.0.0.1
```
./datastore
```

Listen on NATS *:4222 and API *:18080 
```
./datastore --nats-token=secretnats --nats-host 0.0.0.0 --api-pass apipassword --api-bind 0.0.0.0
```
Listen on NATS *:1337 and API 127.0.0.1:18080 
```
MEOW_NATS_TOKEN=secretnats ./datastore --nats-host 0.0.0.0 --nats-port 1337
```



### Help

```
meow datastore v0.1

Usage:
  datastore [flags]

Flags:
  -h, --help         Show this help
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

Advanced:
  --queue-group string NATS queue group (default: datastore-workers)
  --domain-enrich-threshold int Skip domain enrichment when seen on N+ IPs (default: 50, 0=unlimited)

Examples:
  datastore --debug
  datastore --nats-token="SECRET"
  datastore --api-pass="SECRET" --debug
  datastore --nats-url="nats://prod:4222" --nats-user="admin" --nats-pass="pass"
  datastore --db-path=/data/scan.db --api-port=9090
  datastore --no-api
Environment variables:
  MEOW_NATS_URL       Alternative to --nats-url
  MEOW_NATS_TOKEN     Alternative to --nats-token
  MEOW_NATS_USER      Alternative to --nats-user
  MEOW_NATS_PASS      Alternative to --nats-pass
  MEOW_DEBUG          Alternative to --debug
  MEOW_API_PASS       Alternative to --api-pass
  MEOW_GEOIP_CITY     Alternative to --geoip-city
  MEOW_GEOIP_ASN      Alternative to --geoip-asn
```
---

## Web Interface

Available at `http://localhost:18080` by default.

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/dashboard` | Overview with stats, charts, breakdown by country/service/cloud |
| Hosts | `/hosts` | Browse and search hosts, per-IP details |
| Certificates | `/certificates` | Explore TLS/X.509 certificates |
| Domains | `/domains` | Domain intelligence from discovered hostnames |
| Map | `/map` | Interactive geographic map (Leaflet) |
| Query | `/query` | MeowQL console for advanced queries |
| Scan | `/scan` | On-demand scan launcher |
| Status | `/status` | System monitoring and debug info |

A *mobile-friendly-best-effort* version is also available under `/mobile/*`.

---

## REST API

All endpoints are under `/api/`. If `--api-pass` is set, include the `X-API-Key` header or `?key=` query parameter.

### Hosts

```bash
# Search hosts
curl "http://localhost:18080/api/hosts?q=apache&country=FR&port=443"

# Get host details
curl "http://localhost:18080/api/hosts/192.168.1.1"
```

### Services & Certificates

```bash
# Search services
curl "http://localhost:18080/api/services?service=ssh&product=OpenSSH"

# List certificates
curl "http://localhost:18080/api/certificates?subject=example.com"

# Hosts using a specific certificate
curl "http://localhost:18080/api/certificates/SHA256_FINGERPRINT/hosts"
```

### MeowQL Search

```bash
# Host-centric search
curl "http://localhost:18080/api/search?q=port:443+country:US&limit=50"

# Service-centric search
curl "http://localhost:18080/api/search/services?q=http.title:login"
```

### Statistics

```bash
curl "http://localhost:18080/api/stats/dashboard"
curl "http://localhost:18080/api/stats/countries"
curl "http://localhost:18080/api/stats/services"
curl "http://localhost:18080/api/stats/cloud"
curl "http://localhost:18080/api/stats/technologies"
curl "http://localhost:18080/api/stats/products"
```

### Export

```bash
# JSON export
curl "http://localhost:18080/api/export?format=json&type=hosts"

# GeoMap data
curl "http://localhost:18080/api/geomap?groups=admin,http,mail"
```

### Domains

```bash
curl "http://localhost:18080/api/domains?q=example"
curl "http://localhost:18080/api/domains/stats"
curl "http://localhost:18080/api/domains/example.com/services"
```

---

## MeowQL — Query Language

Search language inspired by Censys/Shodan/fofa.

### Operators

| Syntax | Description | Example |
|--------|-------------|---------|
| `field:value` | Contains | `http.title:login` |
| `field="exact"` | Exact match | `service="ssh"` |
| `field!=value` | Not equal | `country!=US` |
| `field>N` | Greater than | `port>1024` |
| `field<N` | Less than | `http.status<400` |
| `field:*` | Exists (not null) | `cloud:*` |
| `field:{a,b,c}` | Set / IN | `port:{22,80,443}` |
| `field=~regex` | Regex (GLOB) | `product=~Open*` |
| `not expr` / `-field:val` | Negation | `-cloud:aws` |

### Logic

```
expr1 expr2          # Implicit AND (space = AND)
expr1 and expr2      # Explicit AND
expr1 or expr2       # OR
(expr1 or expr2)     # Grouping
```

### Examples

```bash
# SSH servers in France
port:22 country:FR

# HTTPS login pages, excluding AWS
http.title:"login" port:443 -cloud:aws

# Scan a subnet
ip:192.168.1.0/24 service:http

# Wildcard certificates on specific ports
(port:443 or port:8443) tls.cert.cn:"*.example.com"

# FTP with anonymous login
service:ftp enrichment.anonymous_login:true

# Specific technologies
http.headers.X-Powered-By:"PHP" framework:Laravel

# Hosts without any cloud provider in France
-cloud:* country:FR
```

### Available Fields

| Field | Description |
|-------|-------------|
| `ip` | IP address (supports CIDR notation) |
| `port` | Port number |
| `service` | Service name — literal match (ssh, http, ftp...) |
| `protocol` | Protocol family — family-aware: `protocol:smb` matches smb, microsoft-ds, netbios-ssn, cifs |
| `product` | Detected product (OpenSSH, nginx...) |
| `version` | Version string |
| `banner` | Raw banner |
| `country` | Country code |
| `org` / `as_org` | AS organization |
| `asn` | AS number |
| `cloud` | Cloud provider (aws, gcp, azure...) |
| `domain` | Associated domain |
| `http.title` | HTTP page title |
| `http.server` | Server header |
| `http.status` | HTTP status code |
| `http.body` | Body content |
| `http.favicon` | Favicon MD5 hash |
| `tech` | Detected technologies |
| `framework` | Detected framework |
| `tls.cert.cn` | Certificate Subject CN |
| `tls.cert.issuer` | Issuer CN |
| `tls.cert.names` | Subject Alternative Names |
| `tls.jarm` | JARM fingerprint |
| `tls.self_signed` | Self-signed (boolean) |
| `enrichment.*` | JSON enrichment fields |
| `fingerprint.*` | JSON fingerprint fields |
| `http.headers.*` | Specific HTTP headers |

---

## MCP (Model Context Protocol)

12 tools exposed to LLMs (Claude, GPT, etc.) via two transport modes:

**HTTP** — served at `/mcp` alongside the REST API (same `X-API-Key` auth if `--api-pass` is set):

```json
{
  "mcpServers": {
    "meow-datastore": {
      "type": "url",
      "url": "http://127.0.0.1:18080/mcp"
    }
  }
}
```

**stdio** — MCP client spawns the binary directly, no server required, reads DB directly (`meow_scan` unavailable):

```json
{
  "mcpServers": {
    "meow-datastore": {
      "command": "datastore",
      "args": ["--mcp-stdio", "--db-path", "/path/to/scanner.db"]
    }
  }
}
```

### Tools

| Tool | Description |
|------|-------------|
| `meow_search` | MeowQL search (hosts or services mode) |
| `meow_stats` | Dataset overview (counts, top services/countries/cloud/products/tech) |
| `meow_count` | Count-only query — no row data, token-efficient |
| `meow_schema` | Family-aware enrichment schema: list protocol families or inspect fields for a family |
| `meow_host` | Full host profile (services, certificates, domains) |
| `meow_pivot` | Infra correlation by banner_hash, jarm, cert, product, or ASN |
| `meow_certs` | TLS certificate audit (expired, self-signed, expiring soon, weak key) |
| `meow_domains` | Domain intelligence from certificates, SNI, reverse DNS |
| `meow_export` | Export to ip_list / services / hosts for downstream tools |
| `meow_dns` | DNS resolution and reverse lookup with DB cross-reference |
| `meow_status` | System status (pipeline progress, service breakdown, active scanners) |
| `meow_scan` | Submit a SYN scan via NATS — HTTP mode only |

All tools return a unified envelope: `{ "tool": "…", "count": N, "truncated": bool, "results": […] }`.

Protocol families (`protocol:smb` in MeowQL matches smb, microsoft-ds, netbios-ssn, cifs, etc.) are also used by `meow_schema` to group variants under one canonical name.

---

## Configuration

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--debug` | `false` | `MEOW_DEBUG` | Debug logging |
| `--db-path` | `./scanner.db` | | SQLite database path |
| `--nats-host` | `127.0.0.1` | | Embedded NATS server listen address |
| `--nats-port` | `4222` | | Embedded NATS server port |
| `--nats-url` | | `MEOW_NATS_URL` | External NATS URL (disables embedded server) |
| `--nats-token` | | `MEOW_NATS_TOKEN` | NATS authentication token |
| `--nats-user` | | `MEOW_NATS_USER` | NATS username |
| `--nats-pass` | | `MEOW_NATS_PASS` | NATS password |
| `--queue-group` | `datastore-workers` | | NATS queue group |
| `--api-bind` | `127.0.0.1` | | REST API listen address |
| `--api-port` | `18080` | | REST API port |
| `--api-pass` | | `MEOW_API_PASS` | API password (`X-API-Key` header) |
| `--no-api` | `false` | | Disable API and Web UI |
| `--geoip-city` | | `MEOW_GEOIP_CITY` | Path to GeoLite2-City.mmdb |
| `--geoip-asn` | | `MEOW_GEOIP_ASN` | Path to GeoLite2-ASN.mmdb |
| `--domain-enrich-threshold` | `50` | | Skip domain enrichment above N IPs (0=unlimited) |

### Auto-detection

- **NATS**: embedded server by default, switches to client mode when `--nats-url` is provided
- **Auth**: `token` if `--nats-token` is set, `user/pass` if both `--nats-user` and `--nats-pass` are set, otherwise `none`
- **API**: enabled by default, disable with `--no-api`
- **Priority**: CLI flag > `MEOW_*` env var > default (this inverts the previous behavior where env took precedence over flags)

---

## SQLite Schema

| Table | Primary Key | Description |
|-------|------------|-------------|
| `hosts` | `ip` | Scanned hosts with geolocation and cloud detection |
| `services` | `ip + port` | Detected services with JSON fingerprint and enrichment data |
| `http_data` | `ip + port` | HTTP data (title, headers, technologies, CMS) |
| `certificates` | `fingerprint_sha256` | X.509 certificates |
| `service_certificates` | `ip + port + cert` | Service-to-certificate mapping with JARM |
| `host_domains` | `ip + domain` | Domains associated with hosts |
| `service_enrichments` | `ip + port + domain` | Per-domain enrichment results |
| `domains` | `domain` | Domains with DNS records |

Optimizations: WAL mode, 64MB cache, incremental triggers for counters, 25+ indexes.

---

## GeoIP (optional)

The datastore automatically enriches hosts with geolocation data when MaxMind database files are available:

```
GeoLite2-City.mmdb
GeoLite2-ASN.mmdb
```

Includes automatic cloud provider detection (AWS, GCP, Azure, OVH, Hetzner...) based on AS organization.

---

## Requirements

- **Go** 1.22+
- **GeoIP** (optional): MaxMind GeoLite2 database files
- The `synscan` and `grabber` modules feed data to the datastore via NATS

---

## Full Stack Deployment

```bash
# 1. Datastore (starts NATS + API)
./datastore --nats-token="SECRET"

# 2. Grabber fingerprint
./grab finger --nats-token SECRET

# 3. Grabber enrichment
./grab enrich --nats-token SECRET

# 4. SynScan (requires root / CAP_NET_RAW)
sudo ./synscan --target 10.0.0.0/8 --ports 1-10000 \
  --nats-url="nats://localhost:4222" --nats-token="SECRET"

# 5. Open http://localhost:18080 to see results in real time
```
