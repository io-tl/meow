# 🐱 Meow

Modular and distributed network scanning system. Three independent components communicate via **NATS** to scan, identify and enrich network services at scale.

```
 ┌─────────────┐       ┌────────────────────────┐       ┌────────────────────┐
 │   SynScan   │──────>│        Grabber         │──────>│     Datastore      │
 │             │       │                        │       │                    │
 │  TCP SYN    │       │  Fingerprint (nmap)    │       │  NATS Server       │
 │  scanner    │       │  + Enrichment          │       │  SQLite + API      │
 │  high perf  │       │  (60 modules)          │       │  Web UI + MeowQL   │
 └─────────────┘       └────────────────────────┘       └────────────────────┘
        │                         │                              │
        └─────────────────────────┴──────────────────────────────┘
                          NATS (embedded in Datastore)
```

---

## Pipeline 🐾🐾🐾

Data flows automatically between modules through three NATS topics:

```
SynScan                     Grabber                          Datastore
───────                     ───────                          ─────────
 open port ────────> [Fingerprint] ──> identified service ───> storage
   scan.port.open     nmap probes      scan.port.fingerprinted    │
                     [Enrichment]  ──> protocol data ────────> storage
                      enrich modules   scan.port.enriched         │
                                                             SQLite
                                                             REST API
                                                             Web UI
```

---

## Components

### [SynScan](synscan/)

TCP port scanner using forged SYN packets. Detects open ports without completing the TCP handshake.

- **Auto-detected transport**: AF_PACKET > Raw Socket > Connect
- Linux support (AF_PACKET, raw sockets) and Windows (Npcap)
- Deterministic scan with resume token to pick up an interrupted scan
- nmap-style targets: CIDR, octet ranges, combinations
- Daemon mode to receive scan orders via NATS

```bash
sudo ./synscan -t 192.168.1.0/24 -P 100 -r 10000 --nats-token SECRET
```

> Full documentation: **[synscan/README.md](synscan/README.md)**

---

### [Grabber](grabber/)

Service identification and data extraction from discovered services. Combines two stages into a single binary (`grab`).

**Fingerprint** — Identifies services using nmap probes (regex matching, JARM TLS fingerprinting).

**Enrichment** — Extracts protocol-specific data through several modules:

| Category | Modules |
|----------|---------|
| Web | http, ipp, icecast, couchdb, elasticsearch, influxdb |
| Email | smtp, pop3/s, imap/s |
| Databases | mysql, postgres, mongodb, redis, oracle, mssql, cassandra, memcached |
| Directory / DNS | ldap/s, dns, netbios, x11 |
| Remote access | ssh, telnet, vnc, rdp |
| File transfer | ftp, rsync, tftp, nfs, git, afp |
| Messaging | mqtt, amqp, xmpp, irc, mumble, teamspeak, sip |
| Network | smb, snmp, ntp, modbus, coap, openvpn, pptp, upnp |
| Misc | rpc, rtsp, minecraft, ajp13, lpd, mpd, nntp, syslog, banner... |

```bash
./grab finger --nats-token SECRET   # fingerprint
./grab enrich --nats-token SECRET   # enrichment
./grab local  --nats-token SECRET   # both in one process
```

> Full documentation: **[grabber/README.md](grabber/README.md)**

---

### [Datastore](datastore/)

Central hub of the system. Hosts the NATS server, stores results and exposes a web interface.

- **Embedded NATS**: built-in server, no external dependency
- **SQLite**: WAL-optimized storage with incremental triggers
- **REST API**: endpoints for hosts, services, certificates, stats, exports
- **Web UI**: dashboard, host list, certificates, interactive map, advanced queries
- **MeowQL**: query language inspired by Shodan/Censys (`port:443 country:FR http.title:"login"`)
- **MCP**: Model Context Protocol endpoint for AI integration
- **GeoIP**: automatic enrichment (country, ASN, cloud provider)

```bash
./datastore -nats-token SECRET
# Web UI → http://localhost:18080
```

> Full documentation: **[datastore/README.md](datastore/README.md)**

---

## Quick Start

### Build

```bash
# Build everything
make build-all

# Or individually
cd synscan  && go build -o synscan ./cmd/synscan/
cd grabber  && go build -o grab ./cmd/grab/
cd datastore && go build -o datastore ./cmd/datastore/

# Docker build (if docker is installed)
make dist
```

### Local mode (everything on one machine)

```bash
# 1. Datastore — starts NATS server + API
./datastore

# 2. Grabber — fingerprint + enrichment
./grab local

# 3. SynScan — daemon mode (controllable from the Web UI)
sudo ./synscan -d
```

Open **http://localhost:18080** to see results in real time.

### Distributed mode

For large scans, spread components across multiple machines:

```bash
# Machine 1 — Datastore
./datastore -nats-host 0.0.0.0 -nats-token SECRET -api-bind 0.0.0.0 -api-pass APIKEY

# Machine 2 — Grabber (like synscan can be launched multiple times to scale)
./grab finger --nats-url nats://10.0.0.1:4222 --nats-token SECRET
./grab enrich --nats-url nats://10.0.0.1:4222 --nats-token SECRET

# Machine 3 — SynScan
sudo ./synscan -t 10.0.0.0/8 -P 1000 -r 50000 \
    --nats-url nats://10.0.0.1:4222 --nats-token SECRET
```

NATS queue groups allow running multiple instances of each component without duplicate processing.

---

## MCP mode

```json
{
  "mcpServers": {
    "meow-datastore": {
      "type": "http",
      "url": "http://localhost:18080/mcp"
    }
  }
}
```

MCP endpoint to query scan results from a language model

```claude
❯ find me all adminer instances in England and sort them by cloud provider

● meow-datastore - meow_search (MCP)(query: "http.title:adminer and country:GB", mode: "services", limit: 100, fields: "ip,port,service,product,http.title,http.server,http.status,org,city,cloud,version")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "product:adminer and country:GB", mode: "services", limit: 100, fields: "ip,port,service,product,http.title,http.server,http.status,org,city,cloud,version")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "http.title:Adminer and country:GB", mode: "services", limit: 100, fields: "ip,port,service,product,http.title,http.server,http.status,org,city,cloud,version")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● Let's try a broader search — maybe the title contains "adminer" in a different case, or it's in the banner/tech.

● meow-datastore - meow_search (MCP)(query: "tech:adminer and country:GB", mode: "services", limit: 100, fields: "ip,port,service,product,http.title,http.server,http.status,org,city,cloud,version")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "banner:adminer and country:GB", mode: "services", limit: 100, fields: "ip,port,service,product,http.title,http.server,http.status,org,city,cloud,version")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● Let's check how Adminer is indexed in the global dataset, then filter.

● meow-datastore - meow_search (MCP)(query: "http.title:adminer", mode: "services", limit: 5, fields: "ip,port,http.title,product,country,cloud,org")
  ⎿  {
       "count": 5,
       "services": [
     … +36 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "product:adminer", mode: "services", limit: 5, fields: "ip,port,http.title,product,country,cloud,org")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "tech:adminer", mode: "services", limit: 5, fields: "ip,port,http.title,product,country,cloud,org")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● Adminer is present in the dataset via http.title, but none are in GB. Let's check the full 6 results and also try variants (framework, redirect, etc.).

● meow-datastore - meow_search (MCP)(query: "http.title:adminer", mode: "services", limit: 10, fields: "ip,port,http.title,http.server,http.status,product,version,country,city,cloud,org")
  ⎿  {
       "count": 6,
       "services": [
     … +43 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "framework:adminer", mode: "services", limit: 10, fields: "ip,port,http.title,country,cloud,org")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● meow-datastore - meow_search (MCP)(query: "http.redirect:adminer and country:GB", mode: "services", limit: 10, fields: "ip,port,http.title,http.redirect,country,cloud,org")
  ⎿  {
       "count": 0,
       "services": null,
     … +2 lines (ctrl+o to expand)

● No Adminer found in the United Kingdom (GB).

  The dataset contains 6 Adminer instances total, but none are in England. Here is the full breakdown:

  ┌─────┬─────────────────┬──────┬─────────┬──────────┬─────────────────────┐
  │  #  │       IP        │ Port │ Country │  Cloud   │    Organisation     │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 1   │ 144.76.96.202   │ 443  │ DE      │ Hetzner  │ Hetzner Online GmbH │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 2   │ 194.87.215.18   │ 8080 │ RU      │ -        │ Jsc Timeweb         │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 3   │ 194.87.220.5    │ 8081 │ CZ      │ -        │ Timeweb, LLP        │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 4   │ 194.87.202.113  │ 8081 │ CZ      │ -        │ Timeweb, LLP        │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 5   │ 163.172.181.215 │ 8081 │ FR      │ Scaleway │ Scaleway S.a.s.     │
  ├─────┼─────────────────┼──────┼─────────┼──────────┼─────────────────────┤
  │ 6   │ 163.172.240.206 │ 8080 │ FR      │ Scaleway │ Scaleway S.a.s.     │
  └─────┴─────────────────┴──────┴─────────┴──────────┴─────────────────────┘

  Countries represented: Germany (1), Russia (1), Czech Republic (2), France (2) — zero in GB.

  The scans may not have covered UK IP ranges hosting Adminer, or no instances were exposed on
  the scanned ports. Would you like me to list Adminer instances from another country, or broaden
  the search?
```

## Requirements

| Component | Go | OS | Privileges |
|-----------|----|----|------------|
| SynScan | 1.24+ | Linux, Windows | root / CAP_NET_RAW (or connect fallback) |
| Grabber | 1.24+ | Linux, Windows | none |
| Datastore | 1.22+ | Linux, Windows | none |

**Optional**: MaxMind GeoIP databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`) for geographic enrichment.
