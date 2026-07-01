# 🐈‍⬛ SynScan

**High-performance TCP port scanner**

SynScan sends raw TCP SYN packets to detect open ports without completing the full handshake. It integrates into the **meow** pipeline via NATS to automatically feed service fingerprinting and enrichment.

```
          SynScan                    NATS                       Datastore
<──syn┌───────────────┐         ┌────────────────┐       ┌──────────────────────┐
      │  SYN packets  │──open──>│ scan.port.open │─pub──>│    Fingerprinting    │
ack──>└───────────────┘         └────────────────┘       └──────────────────────┘
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

## Build

```bash
# Build
go build -o synscan ./cmd/synscan/

# Makefile
**make**
```

> Requires **Go 1.25+**

---

## Quick start

```bash
# Basic /24 scan on common web ports (tries nats://localhost:4222 by default)
sudo ./synscan -t 192.168.1.0/24 -p 80,443

# Top 100 most common ports at 5000 pps
sudo ./synscan -t 10.0.0.0/16 -P 100 -r 5000

# With NATS publishing (full Meow pipeline)
sudo ./synscan -t 192.168.1.0/24 -p 22,80,443,8080 \
    --nats-url nats://10.1.1.1:4222 --nats-token SECRET

# Daemon mode, wait for scan requests via NATS giving REST api scan hability
sudo ./synscan --daemon --nats-url nats://10.1.1.1:4222 --nats-token SECRET
```

---

## Options

```
Usage: synscan [flags]

Flags:
  -t, --target string       Target CIDR, IP, or nmap-style range (required)
      --target-file string  File containing one target/range per line
  -p, --ports string        Ports to scan (default: 80,443,22,8080,8443)
  -P, --top-ports int       Scan the N most common ports
  -i, --interface string    Network interface (auto-detected if empty)
  -r, --rate-limit int      Packets per second (default: 1000)
  -T, --timeout int         Timeout in milliseconds (default: 5000)
  -c, --config string       YAML configuration file
      --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
      --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
      --resume string       Resume an interrupted scan (hex token)
      --daemon              Daemon mode: wait for scan requests via NATS
  -d, --debug               Enable debug logging (or env: MEOW_DEBUG)
  -h, --help                Show help
  -v, --version             Show version
```

> `-t` and `--target-file` are mutually exclusive. `-p` and `-P` are also mutually exclusive.

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
# Full /16 — top 100 ports — 50,000 pps 10s timeout
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 50000 -T 10000
```

### Nmap-style ranges

```bash
# Octet ranges: 192.168.1.1 through 192.168.3.254
sudo ./synscan -t 192.168.1-3.1-254 -p 80,443

# CIDR combined with ranges
sudo ./synscan -t 10.0.1-5.0/24 -p 22,80
```

### Targets from file

```bash
cat > scopes.txt <<'EOF'
# comment allowed
192.168.1.0/24
10.0.10-12.1-254
EOF

sudo ./synscan --target-file scopes.txt -p 80,443
```

### Resuming an interrupted scan

Scans are **deterministic**: IP and port ordering is reproducible from a fixed seed.

```bash
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 10000

# Ctrl+C 
# Interrupted at packet 12566/6553400
# To resume: synscan [same flags] --resume 18bdd678443498c700003116

# Resume exactly where the scan left off
sudo ./synscan -t 10.0.0.0/16 --top-ports 100 -r 10000 \
    --resume 18bdd678443498c700003116
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
    # file: scopes.txt      # alternative to cidr
    ports: "80,443,22,8080,8443"
    # top_ports: 100        # alternative to ports
  network:
    interface: ""            # auto-detect
  performance:
    rate_limit: 10000
    timeout_ms: 5000
```

### launching synscan with specified configuration

```
sudo ./synscan -c config.yaml
```

Priority: **CLI flags** > **MEOW_\*** env vars > **config.yaml** > **defaults**

| Environment variable | Equivalent flag |
|----------------------|-----------------|
| `MEOW_NATS_URL` | `--nats-url` |
| `MEOW_NATS_TOKEN` | `--nats-token` |
| `MEOW_DEBUG` | `-d, --debug` |

---

## Internals

### Port detection

| Response | State |
|----------|-------|
| SYN+ACK (flags `0x12`) | **open** |
| RST (flags `0x04`) | closed |
| Timeout | filtered |

Only **open** ports are displayed (and published to NATS). Closed/filtered ports are only visible with `-d`/`--debug`.

### Randomization

- **IPs**: randomized traversal by batch (fixed seed for determinism)
- **Ports**: shuffled per IP with seed = `global_seed + ip_counter`
- **Source port**: random pool in the 30000–60000 range

This randomization spreads the load across targets and avoids saturating a single host.

### Response correlation

Each SYN packet is sent from a unique source port drawn from the pool. The response (SYN-ACK or RST) arrives on that same source port, allowing correlation back to the original target via a `pending map`. A deduplication mechanism (`seen map`) prevents duplicates.

---

### Linux tuning

For high-throughput scans, increase network buffers:

```bash
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -w net.core.wmem_max=8388608
```
