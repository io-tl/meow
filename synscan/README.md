# 🐱 Meow SynScan

**High-performance TCP port scanner using forged SYN packets.**

SynScan sends raw TCP SYN packets to detect open ports without completing the full handshake. It integrates into the [Meow](../) pipeline via NATS to automatically feed service fingerprinting and enrichment.

```
          SynScan                    NATS                    Grabber → Datastore
     ┌───────────────┐         ┌────────────┐          ┌──────────────────────┐
     │  SYN packets  │──open──>│ scan.port. │─────────>│ Fingerprint + Enrich │
     │  forge & send │         │   open     │          │   → SQLite + Web UI  │
     └───────────────┘         └────────────┘          └──────────────────────┘
```

---

## Performance

| Transport | Requirements | Platform |
|-----------|-------------|----------|
| AF_PACKET (TPACKET_V3 mmap) | root / CAP_NET_RAW | Linux |
| Raw Socket (sendmmsg/recvmmsg) | root / CAP_NET_RAW | Linux |
| Npcap (wpcap.dll) | Admin + Npcap | Windows |
| TCP connect() fallback | none | Linux / Windows |

Transport is **auto-detected**: the best available method is selected automatically.

---

## Installation

```bash
# Build
go build -o synscan ./cmd/synscan/

# Production build (stripped binary)
go build -ldflags="-s -w" -o synscan ./cmd/synscan/

# Cross-compile for Linux AMD64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o synscan ./cmd/synscan/
```

> Requires **Go 1.24+**. No CGO — static binary.

---

## Quick start

```bash
# Basic /24 scan on common web ports (tries nats://localhost:4222 by default)
sudo ./synscan -t 192.168.1.0/24 -p 80,443

# Top 100 most common ports at 5000 pps
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 5000

# With NATS publishing (full Meow pipeline)
sudo ./synscan -t 192.168.1.0/24 -p 22,80,443,8080 \
    --nats-url nats://10.1.1.1:4222 --nats-token SECRET

# Daemon mode, wait for scan requests via NATS giving datastore scan hability
sudo ./synscan --daemon --nats-url nats://10.1.1.1:4222 --nats-token SECRET
```

---

## Options

```
Usage: synscan [flags]

Flags:
  -t, --target <cidr>       Target CIDR, IP, or nmap-style range (required)
  -p, --ports <ports>       Ports to scan (default: 80,443,22,8080,8443)
  -P, --top-ports <n>       Scan the N most common ports
  -i, --interface <iface>   Network interface (auto-detected if empty)
  -r, --rate-limit <n>      Packets per second (default: 1000)
  -T, --timeout <ms>        Timeout in milliseconds (default: 5000)
  -c, --config <path>       YAML configuration file
      --nats-url <url>      NATS server URL
      --nats-token <token>  NATS auth token
      --resume <token>      Resume an interrupted scan (hex token)
  -d, --daemon              Daemon mode: wait for scan requests via NATS
  -v, --verbose             Verbose output
```

> `-p` and `-P` are mutually exclusive.

---

## Examples

### Local network scan

```bash
sudo ./synscan -t 192.168.1.0/24 -p 22,80,443,3306,5432,8080,8443
```

Output:
```
open    192.168.1.1:80
open    192.168.1.1:443
open    192.168.1.42:22
open    192.168.1.42:3306
open    192.168.1.100:8080
```

### Fast scan on a large scope

```bash
# Full /16 — top 100 ports — 50,000 pps — 10s timeout
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 50000 -T 10000
```

### Nmap-style ranges

```bash
# Octet ranges: 192.168.1.1 through 192.168.3.254
sudo ./synscan -t 192.168.1-3.1-254 -p 80,443

# CIDR combined with ranges
sudo ./synscan -t 10.0.1-5.0/24 -p 22,80
```

### Full pipeline with NATS

```bash
# Terminal 1 — Datastore (starts the embedded NATS server)
./datastore -nats-token SECRET

# Terminal 2 — Grabber fingerprint
./grab finger --nats-token SECRET

# Terminal 3 — Grabber enrichment
./grab enrich --nats-token SECRET

# Terminal 4 — Launch the scan
sudo ./synscan -t 192.168.1.0/24 --top-ports 1000 -r 10000 \
    --nats-url nats://localhost:4222 --nats-token SECRET
```

Discovered ports flow automatically through the pipeline:
`scan.port.open` → fingerprint → `scan.port.fingerprinted` → enrichment → `scan.port.enriched` → SQLite storage + Web UI.

### Resuming an interrupted scan

Scans are **deterministic**: IP and port ordering is reproducible from a fixed seed.

```bash
# Start a scan — a Scan ID is displayed at startup
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 10000
# Scan ID: 17b5c7a2e6e8f55200000000

# Ctrl+C → a resume token is printed
# To resume: synscan [same flags] --resume 17b5c7a2e6e8f5520000b128

# Resume exactly where the scan left off
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 10000 \
    --resume 17b5c7a2e6e8f5520000b128
```

> `--target` and `--ports` flags must be identical when resuming.


### YAML configuration

```yaml
nats:
  url: nats://localhost:4222
  auth:
    token: SECRET

synscan:
  target:
    cidr: 192.168.1.0/24
    ports: "80,443,22,8080,8443"
    # top_ports: 100        # alternative to ports
  network:
    interface: ""            # auto-detect
  performance:
    rate_limit: 10000
    timeout_ms: 5000
```

Priority: **CLI flags** > **config.yaml** > **defaults**

---

## Internals

### Port detection

| Response | State |
|----------|-------|
| SYN+ACK (flags `0x12`) | **open** |
| RST (flags `0x04`) | closed |
| Timeout | filtered |

Only **open** ports are displayed (and published to NATS). Closed/filtered ports are only visible with `-v`.

### Randomization

- **IPs**: randomized traversal by batch (fixed seed for determinism)
- **Ports**: shuffled per IP with seed = `global_seed + ip_counter`
- **Source port**: random pool in the 30000–60000 range

This randomization spreads the load across targets and avoids saturating a single host.

### Response correlation

Each SYN packet is sent from a unique source port drawn from the pool. The response (SYN-ACK or RST) arrives on that same source port, allowing correlation back to the original target via a `pending map`. A deduplication mechanism (`seen map`) prevents duplicates.

---

## System requirements

| Item | Details |
|------|---------|
| Go | 1.24+ |
| OS | Linux (recommended), Windows |
| Privileges | root or `CAP_NET_RAW` for SYN scan, none for connect() fallback |
| CGO | not required — static binary |
| NATS | optional — the scanner works standalone |

### Linux tuning

For high-throughput scans, increase network buffers:

```bash
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -w net.core.wmem_max=8388608
```
