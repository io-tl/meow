# 🐈‍⬛ Grab

Fingerprinting and enrichment modules for the **Meow** pipeline. Identifies services using nmap probes, then extracts protocol-specific data through built-in modules.

```
scan.port.open ──> [ Fingerprint ] ──> scan.port.fingerprinted ──> [ Enrichment ] ──> scan.port.enriched
                    nmap probes           identified service          modules            enrichment data,
                 protocol discovery        version, banner      protocol enrichment      metadata,certs ...
```

## Build

```bash
# Standard
CGO_ENABLED=0 go build -o grab ./cmd/grab/

# Makefile
make

# Be careful with Windows cross-compilation
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -o grab.exe ./cmd/grab/
```

## Usage

### Operating modes

| Mode | Description |
|------|-------------|
| `finger` | Fingerprint service (listens on `scan.port.open` via NATS) |
| `enrich` | Enrichment service (listens on `scan.port.fingerprinted` via NATS) |
| `local` | Fingerprint + enrichment in a single process |
| `debug` | Direct test against a host/port without NATS |
| `modules` | List all available enrichment modules |

### Quick start

```bash
# Fingerprint only (requires a running NATS datastore)
./grab finger --nats-token SECRET

# Enrichment only
./grab enrich --nats-token SECRET

# Both in a single process
./grab local --nats-token SECRET

# With a configuration file
./grab finger -c config.yaml
./grab enrich -c config.yaml
./grab local -c config.yaml

# Connect to a remote NATS server
./grab finger --nats-url nats://10.0.0.1:4222 --nats-token SECRET
```

### Enrichment development using debug mode 

Test fingerprinting or enrichment against a specific target without any NATS infrastructure:

```bash
# Fingerprint a service
./grab debug finger -host 192.168.1.1 -port 22

# Fingerprint a service with verbose output
./grab debug finger -host 192.168.1.1 -port 443 -debug

# Enrich a service
./grab debug enrich -host 192.168.1.1 -port 22 -service ssh

# Enrich a service with sni support
./grab debug enrich -host 10.0.0.1 -port 443 -service https -domain example.com

# Enrich a service with verbose output
./grab debug enrich -host 10.0.0.1 -port 6379 -service redis -debug
```

### List modules

```bash
./grab modules
```

```
MODULE        ALIASES               ENRICH  TIMEOUT
------        -------               ------  -------
afp           apple-filing-proto..  yes     10s
ajp13         ajp                   yes     10s
amqp          rabbitmq              yes     10s
cassandra     cql                   yes     10s
...
ssh           openssh               yes     10s
telnet        -                     yes     10s
vnc           rfb                   yes     10s

```

## Configuration

The `config.yaml` file is **optional**. Without a configuration file, the grabber uses default values and attempts to connect to `nats://localhost:4222`.

**Priority order per parameter:** CLI flag > `MEOW_*` env var > `config.yaml` > default

| Environment variable | Equivalent flag |
|----------------------|-----------------|
| `MEOW_NATS_URL` | `--nats-url` |
| `MEOW_NATS_TOKEN` | `--nats-token` |
| `MEOW_DEBUG` | `-d, --debug` |

```yaml
nats:
  url: "nats://localhost:4222"
  auth:
    token: "SECRET"

fingerprint:
  workers: 500             # concurrent workers
  probe_timeout_ms: 9000   # per nmap probe timeout (ms)
  global_timeout_ms: 30000 # total timeout per port (ms)

enrichment:
  workers: 500             # concurrent workers
  enrich_timeout_ms: 10000 # per module timeout (ms)
  global_timeout_ms: 30000 # hard deadline per job (ms)

logging:
  level: "info"            # debug, info, warn, error
  format: "console"        # console, json
```

```
./grab local -c config.yaml
```

## Enrichment modules

| Category | Modules |
|----------|---------|
| **Web** | `http`, `ipp`, `icecast`, `couchdb`, `elasticsearch`, `influxdb` |
| **Email** | `smtp`, `pop3`, `pop3s`, `imap`, `imaps` |
| **Databases** | `mysql`, `postgres`, `mongodb`, `redis`, `oracle`, `mssql`, `cassandra`, `memcached` |
| **Directory / DNS** | `ldap`, `ldaps`, `dns`, `netbios`, `x11` |
| **Remote access** | `ssh`, `telnet`, `vnc`, `rdp` |
| **File transfer** | `ftp`, `rsync`, `tftp`, `nfs`, `git`, `afp` |
| **Messaging** | `mqtt`, `amqp`, `xmpp`, `irc`, `mumble`, `teamspeak`, `sip` |
| **Network** | `smb`, `snmp`, `ntp`, `modbus`, `coap`, `openvpn`, `pptp`, `upnp` |
| **Other** | `rpc`, `rtsp`, `minecraft`, `ajp13`, `lpd`, `mpd`, `nntp`, `syslog`, `ldp`, `banner`, `ntlm_parser` |

Each module self-registers via `init()` and is automatically available for enrichment. TLS variants (`pop3s`, `imaps`, `ldaps`) are generated through a shared TLS factory.

## NATS pipeline

The grabber integrates into the Meow pipeline through three NATS topics:

```
SynScan                    Grabber                         Datastore
───────                    ───────                         ─────────
scan.port.open ─────> [Fingerprint] ──> scan.port.fingerprinted ──> SQLite
                      [Enrichment] ───> scan.port.enriched ───────> SQLite
```

| Topic | Role |
|-------|------|
| `scan.port.open` | Open ports detected by SynScan (fingerprint input) |
| `scan.port.fingerprinted` | Identified services (fingerprint output / enrichment input) |
| `scan.port.enriched` | Extracted protocol data (enrichment output) |

**Queue groups** (`fingerprint-workers`, `enrichment-workers`) allow running multiple instances without duplicate processing.

## CLI flags

### `grab finger`

```
-c, --config string       Configuration file (default: config.yaml)
-w, --workers int         Number of workers
    --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
    --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
    --probe-timeout int   Per-probe timeout (default: 9000)
    --global-timeout int  Global timeout per port (default: 30000)
-d, --debug               Enable debug logging (or env: MEOW_DEBUG)
```

### `grab enrich`

```
-c, --config string       Configuration file (default: config.yaml)
-w, --workers int         Number of workers
    --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
    --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
    --enrich-timeout int  Per-module timeout (default: 10000)
    --global-timeout int  Hard deadline per job (default: 30000)
-d, --debug               Enable debug logging (or env: MEOW_DEBUG)
```

### `grab local`

```
-c, --config string       Configuration file (default: config.yaml)
-w, --workers int         Number of workers
    --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
    --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
    --probe-timeout int   Per-probe timeout (default: 9000)
    --enrich-timeout int  Per-module timeout (default: 10000)
    --global-timeout int  Global timeout (default: 30000)
-d, --debug               Enable debug logging (or env: MEOW_DEBUG)
```

## Requirements

- **Linux** recommended (native pure-Go PCRE2 support via `go.elara.ws/pcre`)
- **Windows** requires `mingw-w64` for cross-compilation (CGO + embedded PCRE2)
- **NATS** provided by the Datastore module (embedded server)
