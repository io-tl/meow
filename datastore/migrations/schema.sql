-- ============================================================================
-- DATASTORE - SQLITE SCHEMA v3.0
-- Network scanner data storage with optimized indexes and query support
-- ============================================================================

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- ============================================================================
-- TABLE 1: hosts (current snapshot of each IP)
-- ============================================================================
CREATE TABLE IF NOT EXISTS hosts (
  ip TEXT PRIMARY KEY,

  -- Numeric IP for CIDR range queries (IPv4 as 32-bit unsigned integer)
  ip_int INTEGER,

  -- Timestamps (Unix timestamps)
  first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  last_scan INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  -- DNS / Identification (stored as JSON arrays)
  hostnames TEXT,                   -- JSON array of hostnames
  domains TEXT,                     -- JSON array of domains

  -- Network / AS
  asn INTEGER,
  as_org TEXT,
  isp TEXT,

  -- Geolocation
  country_code TEXT,
  country_name TEXT,
  city TEXT,
  timezone TEXT,

  -- Cloud Provider Detection
  cloud_provider TEXT,              -- aws, azure, gcp, digitalocean, hetzner, ovh
  cloud_region TEXT,
  cloud_type TEXT,                  -- cdn, cloud, waf (from cdncheck)

  -- Computed fields (maintained by incremental triggers)
  open_ports_count INTEGER DEFAULT 0,
  services_count INTEGER DEFAULT 0,

  -- Tags (JSON array)
  tags TEXT                         -- JSON array: ["database", "iot", "webcam"]
);

-- ============================================================================
-- TABLE 2: services (current snapshot of services per IP:PORT)
-- ============================================================================
CREATE TABLE IF NOT EXISTS services (
  ip TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),

  -- Service Identification (from initial fingerprint)
  service TEXT,                     -- http, ssh, ftp, mysql, etc.
  product TEXT,                     -- nginx, OpenSSH, Apache
  version TEXT,

  -- Banner (from initial grab)
  banner TEXT,
  banner_hash TEXT,                 -- SHA256 of banner

  -- GRAB INITIAL (rapid fingerprint)
  fingerprint_data TEXT,            -- JSON: Complete initial grab data (RawResponse, NullProbe, JARM)
  detected_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  -- ENRICHMENT (deep analysis)
  enrichment_data TEXT,             -- JSON: Complete enrichment data
  enrichment_status TEXT DEFAULT 'pending' CHECK (enrichment_status IN ('pending', 'enriched', 'failed', 'skipped')),
  enriched_at INTEGER,

  -- Tags (JSON array)
  tags TEXT,

  PRIMARY KEY (ip, port),
  FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

-- ============================================================================
-- TABLE 3: http_data (enriched HTTP/HTTPS data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS http_data (
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,

  -- HTTP Response
  status_code INTEGER,
  server TEXT,                      -- Server header
  title TEXT,                       -- HTML <title>
  body_hash TEXT,                   -- SHA256 of body
  body_preview TEXT,                -- First 1KB of body
  headers TEXT,                     -- JSON: Full HTTP headers
  redirects_to TEXT,                -- Location header

  -- Web Technologies (Wappalyzer)
  technologies TEXT,                -- JSON: [{"name":"WordPress","categories":["CMS"]}]
  cms TEXT,                         -- Main CMS detected
  framework TEXT,                   -- Main framework
  webserver TEXT,                   -- Webserver (nginx, apache, etc.)

  -- Visual
  favicon_md5 TEXT,                 -- MD5 of favicon

  -- TLS/SSL
  uses_ssl INTEGER DEFAULT 0,       -- Boolean: 0 or 1
  cert_fingerprint TEXT,            -- SHA256 of certificate

  -- Timestamps
  scanned_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  PRIMARY KEY (ip, port),
  FOREIGN KEY (ip, port) REFERENCES services(ip, port) ON DELETE CASCADE
);

-- ============================================================================
-- TABLE 4: certificates (X.509 certificate repository)
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificates (
  fingerprint_sha256 TEXT PRIMARY KEY,
  fingerprint_sha1 TEXT,
  fingerprint_md5 TEXT,

  -- Subject
  subject_cn TEXT,
  subject_org TEXT,
  subject_country TEXT,

  -- Issuer
  issuer_cn TEXT,
  issuer_org TEXT,

  -- Names (CN + SANs) - JSON array
  names TEXT,                       -- JSON array of all names (wildcards included)

  -- Validity
  not_before INTEGER,
  not_after INTEGER,
  serial_number TEXT,

  -- Flags
  is_self_signed INTEGER DEFAULT 0, -- Boolean: 0 or 1
  is_ca INTEGER DEFAULT 0,          -- Boolean: 0 or 1

  -- Public Key
  public_key_bits INTEGER,
  public_key_algorithm TEXT,        -- RSA, ECDSA, Ed25519
  signature_algorithm TEXT,         -- sha256WithRSAEncryption, etc.

  -- Full parsed certificate (JSON)
  parsed_cert TEXT,                 -- JSON: Full certificate data

  -- Timestamps
  first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  last_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  -- Tags (JSON array)
  tags TEXT
);

-- ============================================================================
-- TABLE 5: service_certificates (link services <-> certificates)
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_certificates (
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  cert_fingerprint TEXT NOT NULL,

  -- Chain position (0=leaf, 1=intermediate, 2+=root)
  chain_position INTEGER DEFAULT 0,

  -- JARM fingerprint (only for leaf certificate)
  jarm TEXT,                        -- JARM = 62 characters

  -- Timestamps
  first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  last_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  PRIMARY KEY (ip, port, cert_fingerprint),
  FOREIGN KEY (ip, port) REFERENCES services(ip, port) ON DELETE CASCADE,
  FOREIGN KEY (cert_fingerprint) REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE
);

-- ============================================================================
-- TABLE 6: host_domains (IP <-> Domain associations from certificates)
-- ============================================================================
CREATE TABLE IF NOT EXISTS host_domains (
  ip TEXT NOT NULL,
  domain TEXT NOT NULL COLLATE NOCASE,

  -- Source of discovery
  source TEXT NOT NULL DEFAULT 'certificate',  -- 'certificate', 'sni', 'reverse_dns', 'manual'

  -- Port where this domain was discovered (useful for multi-vhost)
  discovered_port INTEGER,

  -- Timestamps
  first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  last_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  PRIMARY KEY (ip, domain),
  FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

-- ============================================================================
-- TABLE 7: service_enrichments (per-domain enrichments for SNI support)
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_enrichments (
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,

  -- Domain used for this enrichment (empty string = direct IP access)
  domain TEXT NOT NULL DEFAULT '' COLLATE NOCASE,

  -- Enrichment data
  enrichment_data TEXT,             -- JSON: Complete enrichment response

  -- Denormalized fields for quick search (all protocols)
  protocol TEXT,                  -- Protocol (from enrichment module: "ssh", "http", "rdp", etc.)
  version TEXT,                   -- Service version (from enrichment "version" field)
  banner TEXT,                    -- Banner/identification (from enrichment "banner" field)

  -- Denormalized HTTP fields for quick search
  status_code INTEGER,
  title TEXT,
  server TEXT,
  redirect_url TEXT,
  content_length INTEGER,

  -- Status
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'enriched', 'failed', 'skipped')),
  error TEXT,

  -- Timestamps
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  enriched_at INTEGER,

  -- Primary key: one enrichment per (ip, port, domain)
  PRIMARY KEY (ip, port, domain),
  FOREIGN KEY (ip, port) REFERENCES services(ip, port) ON DELETE CASCADE
);

-- ============================================================================
-- TABLE 8: domains (web properties - DNS/WHOIS data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS domains (
  domain TEXT COLLATE NOCASE PRIMARY KEY,

  -- Resolved IPs (JSON array)
  ips TEXT,

  -- DNS records (JSON)
  dns_records TEXT,                 -- JSON: A, AAAA, MX, NS, TXT, etc.

  -- WHOIS (JSON)
  whois TEXT,

  -- Discovered subdomains (JSON array)
  subdomains TEXT,

  -- Metadata
  last_resolved INTEGER,
  last_updated INTEGER NOT NULL DEFAULT (strftime('%s','now')),

  -- Tags (JSON array)
  tags TEXT
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================================

-- ============================================================================
-- HOSTS INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_hosts_last_scan ON hosts(last_scan DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country_code) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_asn ON hosts(asn) WHERE asn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_as_org ON hosts(as_org) WHERE as_org IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_cloud ON hosts(cloud_provider, cloud_region) WHERE cloud_provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_cloud_type ON hosts(cloud_type) WHERE cloud_type IS NOT NULL;

-- CIDR range query index
CREATE INDEX IF NOT EXISTS idx_hosts_ip_int ON hosts(ip_int) WHERE ip_int IS NOT NULL;

-- Composite index for common search patterns (country + time ordering)
CREATE INDEX IF NOT EXISTS idx_hosts_country_time ON hosts(country_code, last_scan DESC) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_country_name_cloud ON hosts(country_code, country_name, cloud_provider) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_asn_org ON hosts(asn, as_org) WHERE asn IS NOT NULL;

-- ============================================================================
-- SERVICES INDEXES
-- ============================================================================

-- Time-based index (most frequently used)
CREATE INDEX IF NOT EXISTS idx_services_detected_at ON services(detected_at DESC);

-- Service type + time (composite index for common queries)
CREATE INDEX IF NOT EXISTS idx_services_service_time ON services(service, detected_at DESC) WHERE service IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_services_service_ip ON services(service, ip) WHERE service IS NOT NULL;

-- Product lookup (partial index saves space)
CREATE INDEX IF NOT EXISTS idx_services_product ON services(product, version) WHERE product IS NOT NULL;

-- Banner hash (exact match)
CREATE INDEX IF NOT EXISTS idx_services_banner_hash ON services(banner_hash) WHERE banner_hash IS NOT NULL;

-- Port-based queries (composite with detected_at for ORDER BY without TEMP B-TREE)
CREATE INDEX IF NOT EXISTS idx_services_port_detected ON services(port, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);

-- IP-based queries (for host details)
CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip);

-- Composite: service + port (for "find all SSH on port 2222" type queries)
CREATE INDEX IF NOT EXISTS idx_services_service_port ON services(service, port) WHERE service IS NOT NULL;

-- ============================================================================
-- ENRICHMENT INDEXES (Critical for worker queue)
-- ============================================================================

-- Enrichment queue (compound partial index)
CREATE INDEX IF NOT EXISTS idx_services_enrichment_queue
  ON services(detected_at ASC, service)
  WHERE enrichment_status IN ('pending', 'failed')
    AND service IN ('http', 'https', 'ssl/http', 'ssh', 'ftp', 'smtp', 'smtps', 'pop3', 'pop3s', 'imap', 'imaps');

-- Enriched services (for analytics)
CREATE INDEX IF NOT EXISTS idx_services_enriched_at ON services(enriched_at) WHERE enriched_at IS NOT NULL;

-- Enrichment status stats
CREATE INDEX IF NOT EXISTS idx_services_enrichment_stats ON services(enrichment_status, service) WHERE enrichment_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_services_enrichment_port ON services(enrichment_status, port) WHERE enrichment_status IS NOT NULL;

-- Expression indexes for common MeowQL enrichment boolean filters.
-- These help queries like enrichment.nfs_found:true while preserving ORDER BY detected_at DESC.
CREATE INDEX IF NOT EXISTS idx_services_enrichment_nfs_found_detected
  ON services(json_extract(enrichment_data, '$.nfs_found'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_anonymous_login_detected
  ON services(json_extract(enrichment_data, '$.anonymous_login'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_auth_required_detected
  ON services(json_extract(enrichment_data, '$.auth_required'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_signing_required_detected
  ON services(json_extract(enrichment_data, '$.signing_required'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_default_credentials_detected
  ON services(json_extract(enrichment_data, '$.default_credentials'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_supports_tls_detected
  ON services(json_extract(enrichment_data, '$.supports_tls'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != '';

CREATE INDEX IF NOT EXISTS idx_services_enrichment_shares_detected
  ON services(json_extract(enrichment_data, '$.shares'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != ''
    AND json_extract(enrichment_data, '$.shares') IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_services_enrichment_shares_exists_detected
  ON services(json_type(enrichment_data, '$.shares'), detected_at DESC)
  WHERE enrichment_status = 'enriched'
    AND enrichment_data IS NOT NULL
    AND enrichment_data != ''
    AND json_type(enrichment_data, '$.shares') IS NOT NULL
    AND json_type(enrichment_data, '$.shares') != 'null';

-- ============================================================================
-- HTTP_DATA INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_http_status ON http_data(status_code) WHERE status_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_server ON http_data(server) WHERE server IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_title ON http_data(title) WHERE title IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_tech_stack ON http_data(cms, framework, webserver) WHERE cms IS NOT NULL OR framework IS NOT NULL OR webserver IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_favicon ON http_data(favicon_md5) WHERE favicon_md5 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_ssl ON http_data(uses_ssl, cert_fingerprint) WHERE uses_ssl = 1;
CREATE INDEX IF NOT EXISTS idx_http_scanned_at ON http_data(scanned_at DESC);

-- NOTE: idx_http_ip removed — redundant with PRIMARY KEY (ip, port)

-- ============================================================================
-- CERTIFICATES INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_certs_subject_cn ON certificates(subject_cn) WHERE subject_cn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_subject_org ON certificates(subject_org) WHERE subject_org IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_issuer_cn ON certificates(issuer_cn) WHERE issuer_cn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certificates(not_after) WHERE not_after IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_self_signed ON certificates(is_self_signed) WHERE is_self_signed = 1;
CREATE INDEX IF NOT EXISTS idx_certs_is_ca ON certificates(is_ca) WHERE is_ca = 1;
CREATE INDEX IF NOT EXISTS idx_certs_last_seen ON certificates(last_seen DESC);

-- ============================================================================
-- SERVICE_CERTIFICATES INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_service_certs_cert ON service_certificates(cert_fingerprint);
CREATE INDEX IF NOT EXISTS idx_service_certs_jarm ON service_certificates(jarm) WHERE jarm IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_certs_chain ON service_certificates(chain_position);

-- ============================================================================
-- HOST_DOMAINS INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_host_domains_ip ON host_domains(ip);
CREATE INDEX IF NOT EXISTS idx_host_domains_domain ON host_domains(domain);
CREATE INDEX IF NOT EXISTS idx_host_domains_source ON host_domains(source);
CREATE INDEX IF NOT EXISTS idx_host_domains_port ON host_domains(discovered_port) WHERE discovered_port IS NOT NULL;

-- ============================================================================
-- SERVICE_ENRICHMENTS INDEXES
-- ============================================================================
-- NOTE: idx_service_enrichments_ip_port removed — redundant with PRIMARY KEY (ip, port, domain)
CREATE INDEX IF NOT EXISTS idx_service_enrichments_domain ON service_enrichments(domain) WHERE domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_enrichments_status ON service_enrichments(status);
CREATE INDEX IF NOT EXISTS idx_service_enrichments_pending ON service_enrichments(created_at ASC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_service_enrichments_protocol ON service_enrichments(protocol) WHERE protocol IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_enrichments_version ON service_enrichments(version) WHERE version IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_enrichments_banner ON service_enrichments(banner) WHERE banner IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_enrichments_status_code ON service_enrichments(status_code) WHERE status_code IS NOT NULL;

-- Domain grouping (for /domains page)
CREATE INDEX IF NOT EXISTS idx_service_enrichments_domain_status
  ON service_enrichments(domain, status) WHERE domain != '';

-- Better when filtering by status first, then grouping/paginating by domain
CREATE INDEX IF NOT EXISTS idx_service_enrichments_status_domain
  ON service_enrichments(status, domain) WHERE domain != '';

-- Supports domain detail page ordering without temp sorting
CREATE INDEX IF NOT EXISTS idx_service_enrichments_domain_status_ip_port
  ON service_enrichments(domain, status, ip, port) WHERE domain != '';

-- Worker queue ordering with FIFO
CREATE INDEX IF NOT EXISTS idx_service_enrichments_worker_queue
  ON service_enrichments(created_at ASC, status)
  WHERE status IN ('pending', 'failed');

-- ============================================================================
-- DOMAINS INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_domains_last_updated ON domains(last_updated DESC);

-- ============================================================================
-- TRIGGERS FOR AUTO-UPDATING HOST COUNTS (INCREMENTAL)
-- ============================================================================

-- Trigger: increment counts when a service is added
CREATE TRIGGER IF NOT EXISTS update_host_counts_on_insert
AFTER INSERT ON services
FOR EACH ROW
BEGIN
  UPDATE hosts
  SET
    open_ports_count = open_ports_count + 1,
    services_count = services_count + 1
  WHERE ip = NEW.ip;
END;

-- Trigger: decrement counts when a service is deleted
CREATE TRIGGER IF NOT EXISTS update_host_counts_on_delete
AFTER DELETE ON services
FOR EACH ROW
BEGIN
  UPDATE hosts
  SET
    open_ports_count = MAX(0, open_ports_count - 1),
    services_count = MAX(0, services_count - 1)
  WHERE ip = OLD.ip;
END;

-- Views removed: enrichment_stats, top_services, top_products, stats_by_country,
-- stats_by_asn, top_cms, certificate_stats, expired_certificates, global_stats.
-- All statistics are computed via direct queries in Go code.
