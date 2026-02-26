package main

import (
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// natsPublisher is the minimal interface needed to publish NATS messages.
// Using an interface instead of *nats.Conn allows easy mocking in tests.
type natsPublisher interface {
	Publish(subject string, data []byte) error
}

// newMCPHandler creates a Streamable HTTP handler for the MCP server.
// Mount it on the gin router (e.g. at /mcp).
func newMCPHandler(db *DB, nc natsPublisher, scanTracker *ScannerTracker) http.Handler {
	s := server.NewMCPServer(
		"meow-datastore",
		version,
		server.WithToolCapabilities(false),
		server.WithInstructions(mcpInstructions),
	)

	h := &mcpHandler{
		db:          db,
		nc:          nc,
		scanTracker: scanTracker,
	}
	h.registerTools(s)

	return server.NewStreamableHTTPServer(s, server.WithStateLess(true))
}

// mcpHandler holds the shared state for all MCP tool handlers.
type mcpHandler struct {
	db          *DB
	nc          natsPublisher
	scanTracker *ScannerTracker
}

func (h *mcpHandler) registerTools(s *server.MCPServer) {
	// meow_search — MeowQL search (hosts or services)
	s.AddTool(mcp.NewTool("meow_search",
		mcp.WithDescription(
			"Search the scan results database using the MeowQL query language. "+
				"Supports two modes: 'hosts' (default) returns unique hosts with geo/ASN/cloud metadata, "+
				"'services' returns individual IP:port entries with service fingerprint and HTTP details. "+
				"Results are paginated.\n\n"+
				"MeowQL syntax:\n"+
				"  field:value       — substring match (LIKE)\n"+
				"  field=\"exact\"     — exact match\n"+
				"  field!=value      — not equal\n"+
				"  field:{a,b,c}     — match any in set\n"+
				"  ip:192.168.0.0/24 — CIDR range filter\n"+
				"  field:*           — field is not null/empty\n"+
				"  field>N / field<N — numeric comparison\n"+
				"  expr1 expr2       — implicit AND\n"+
				"  expr1 or expr2    — OR\n"+
				"  not expr          — negation\n"+
				"  (expr1 or expr2)  — grouping\n\n"+
				"Available fields: ip, port, service, product, version, banner, banner_hash, "+
				"country, city, asn, org, cloud, cloud.type, "+
				"http.title, http.server, http.status, http.favicon, http.redirect, framework, tech, "+
				"tls.cert.cn, tls.cert.issuer, tls.cert.expired, tls.self_signed, tls.jarm, "+
				"enrichment (status), enrichment.* (JSON paths like enrichment.anonymous_login).\n\n"+
				"Example queries:\n"+
				"  port:443 and country:FR\n"+
				"  service:ssh and ip:10.0.0.0/8\n"+
				"  http.title:admin and not cloud:aws\n"+
				"  product:nginx and tls.self_signed:1\n"+
				"  service:{http,https} and country:{FR,DE,US}"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("MeowQL query string. Examples: 'port:443 and country:FR', 'service:ssh and ip:10.0.0.0/8', 'http.title:login'"),
		),
		mcp.WithString("mode",
			mcp.Description("Result granularity. 'hosts' (default): one row per unique IP with port/service counts. 'services': one row per IP:port with service fingerprint, banner, and HTTP metadata"),
			mcp.Enum("hosts", "services"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of results per page (default: 50, max: 500)"),
		),
		mcp.WithNumber("page",
			mcp.Description("Page number for pagination, starts at 1 (default: 1). Use with limit to iterate through large result sets"),
		),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of fields to include in each result row (services mode only). "+
				"Default: ip,port,service,product,version,country,cloud,org,enrichment_keys. "+
				"Use 'enrichment.*' fields (e.g. enrichment.anonymous_login,enrichment.shares) to get enrichment values. "+
				"The default enrichment_keys field lists available enrichment attribute names per service."),
		),
	), h.handleSearch)

	// meow_count — Lightweight count query
	s.AddTool(mcp.NewTool("meow_count",
		mcp.WithDescription(
			"Return only the count of matching hosts or services for a MeowQL query, without returning any row data. "+
				"Use this instead of meow_search when you only need to know how many results match a query. "+
				"Much more token-efficient than meow_search for questions like 'how many hosts have port 443 open?'."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("MeowQL query string. Examples: 'port:443 and country:FR', 'service:ssh', 'cloud:aws'"),
		),
		mcp.WithString("mode",
			mcp.Description("Count granularity. 'hosts' (default): count unique hosts. 'services': count individual IP:port entries"),
			mcp.Enum("hosts", "services"),
		),
	), h.handleCount)

	// meow_host — Detailed host information
	s.AddTool(mcp.NewTool("meow_host",
		mcp.WithDescription(
			"Retrieve the complete profile of a single host by IP address. "+
				"Returns all known information in one call: geolocation (country, city), network identity (ASN, org), "+
				"cloud metadata (provider, region, type), timestamps (first_seen, last_scan), "+
				"all open services with fingerprint data and enrichment results (protocol-specific fields like anonymous_login, auth_required, signing_required, default_credentials), "+
				"TLS certificates with expiry/self-signed status and JARM fingerprints, "+
				"and associated domains with their discovery source. "+
				"Use this after meow_search to get full details on a specific target."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IPv4 or IPv6 address to look up (e.g. '10.0.0.1', '2001:db8::1')"),
		),
		mcp.WithString("sections",
			mcp.Description("Comma-separated list of sections to include: services, certificates, domains. "+
				"Default: all three. Use to skip unnecessary sub-queries (e.g. sections=services to only get services)."),
		),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of fields for service/certificate rows. "+
				"Service defaults: port,service,product,version,enrichment.anonymous_login,enrichment.auth_required,enrichment.signing_required,enrichment.default_credentials,enrichment.tls,enrichment.protocol,enrichment.version. "+
				"Certificate defaults: port,fingerprint,subject_cn,issuer_cn,self_signed,expired."),
		),
	), h.handleHost)

	// meow_stats — Overview statistics
	s.AddTool(mcp.NewTool("meow_stats",
		mcp.WithDescription(
			"Get a high-level statistical overview of the entire scan dataset. "+
				"Returns: total host/service/certificate counts, enrichment progress breakdown (enriched/pending/failed/skipped), "+
				"top 15 services by frequency, top 10 countries, cloud provider distribution, "+
				"top 15 products (e.g. nginx, OpenSSH, Apache), and top 10 web technologies (e.g. jQuery, WordPress, React). "+
				"Call this first to understand the dataset scope and guide further queries."),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of stat sections to include. "+
				"Default: total_hosts,total_services,total_certificates,enrichment,top_services,top_countries. "+
				"Additional: cloud_providers,top_products,top_technologies."),
		),
	), h.handleStats)

	// meow_pivot — Cross-correlation between entities
	s.AddTool(mcp.NewTool("meow_pivot",
		mcp.WithDescription(
			"Find all hosts and services sharing a common indicator for infrastructure correlation and threat analysis. "+
				"Pivot types:\n"+
				"  banner_hash: hosts running identical software (same banner SHA256) — useful for identifying cloned deployments\n"+
				"  jarm: hosts with the same TLS fingerprint (JARM hash) — useful for finding C2 servers or load-balanced infrastructure\n"+
				"  cert: hosts sharing the same TLS certificate (SHA256 fingerprint) — reveals shared hosting, CDN backends, wildcard certs\n"+
				"  product: hosts running the same software product name (case-insensitive) — e.g. all 'nginx' or 'OpenSSH' instances\n"+
				"  asn: all hosts in the same Autonomous System Number — e.g. all hosts in a specific ISP or cloud provider network\n\n"+
				"Returns IP, port, service, product, version, country, cloud provider, and ASN org for each match."),
		mcp.WithString("by",
			mcp.Required(),
			mcp.Description("Pivot type: which indicator to correlate on"),
			mcp.Enum("banner_hash", "jarm", "cert", "product", "asn"),
		),
		mcp.WithString("value",
			mcp.Required(),
			mcp.Description("The indicator value to search for. For banner_hash: SHA256 hex string. For jarm: 62-char JARM fingerprint. For cert: certificate SHA256 fingerprint. For product: software name (e.g. 'nginx'). For asn: AS number with or without 'AS' prefix (e.g. '15169' or 'AS15169')"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return (default: 100, max: 1000)"),
		),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of fields per result row. Default: ip,port,service,product,country_code. "+
				"Additional: version,cloud_provider,as_org."),
		),
	), h.handlePivot)

	// meow_certs — Certificate search and analysis
	s.AddTool(mcp.NewTool("meow_certs",
		mcp.WithDescription(
			"Search and audit TLS certificates collected during scanning. "+
				"Supports free-text search across subject CN, issuer CN, SAN names, organization, fingerprint, and serial number. "+
				"Pre-built filters for common security audit checks:\n"+
				"  expired: certificates past their not_after date\n"+
				"  self_signed: certificates where issuer equals subject\n"+
				"  expiring_soon: certificates expiring within the next 30 days\n"+
				"  weak_key: certificates with RSA key size below 2048 bits\n\n"+
				"Returns for each certificate: fingerprint, subject/issuer details, SAN names, key algorithm and size, "+
				"signature algorithm, serial number, validity dates, self-signed/CA flags, expiry status, "+
				"and the number of distinct hosts serving this certificate. "+
				"Results are sorted by host count (most widely deployed first)."),
		mcp.WithString("query",
			mcp.Description("Free-text search across certificate fields: subject CN, issuer CN, SAN names, SHA256 fingerprint, serial number, subject/issuer org. Example: 'example.com', 'Let\\'s Encrypt', 'abc123'"),
		),
		mcp.WithString("filter",
			mcp.Description("Pre-built security audit filter. 'all' (default) returns all certificates, other values apply the named check"),
			mcp.Enum("all", "expired", "self_signed", "expiring_soon", "weak_key"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return (default: 50, max: 500)"),
		),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of fields per certificate. "+
				"Default: fingerprint,subject_cn,issuer_cn,status,self_signed,host_count,not_after. "+
				"Additional: subject_org,issuer_org,names,algorithm,bits,signature_algorithm,serial,is_ca,not_before."),
		),
	), h.handleCerts)

	// meow_domains — Domain intelligence
	s.AddTool(mcp.NewTool("meow_domains",
		mcp.WithDescription(
			"Explore domain names discovered during enrichment (from HTTP Host headers, TLS certificates, reverse DNS). "+
				"Two modes of operation:\n"+
				"  List mode (no 'domain' parameter): returns all known domains with aggregated stats — "+
				"service count, protocols seen (http/https/etc.), sample HTTP title/server/status, last seen timestamp. "+
				"Filterable by substring and protocol.\n"+
				"  Detail mode (with 'domain' parameter): returns every IP:port serving the specified domain, "+
				"with per-service details (protocol, HTTP status/title/server/redirect, banner, version) and host metadata (country, org, cloud). "+
				"Useful for mapping virtual hosting, CDN backends, and domain-to-infrastructure relationships."),
		mcp.WithString("domain",
			mcp.Description("Specific domain to get the full service breakdown for (detail mode). If omitted, returns the domain list (list mode). Example: 'example.com'"),
		),
		mcp.WithString("query",
			mcp.Description("Substring filter for domain names in list mode. Example: 'corp' matches 'corp.example.com', 'mycorpsite.io', etc."),
		),
		mcp.WithString("protocol",
			mcp.Description("Filter domains by enrichment protocol in list mode. Examples: 'http', 'https', 'ssh', 'ftp'"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return (default: 50, max: 500)"),
		),
		mcp.WithString("fields",
			mcp.Description("Comma-separated list of fields per row. "+
				"List mode default: domain,services_count,protocols. Additional: sample_title,sample_server,sample_status_code,last_seen. "+
				"Detail mode default: ip,port,protocol,status_code,title,country. Additional: version,banner,server,redirect_url,content_length,org,cloud."),
		),
	), h.handleDomains)

	// meow_export — Export filtered data
	s.AddTool(mcp.NewTool("meow_export",
		mcp.WithDescription(
			"Export scan results in structured formats suitable for downstream tools and reporting. "+
				"Supports MeowQL filtering to export only matching results. Three export types:\n"+
				"  ip_list: plain-text list of IP:port pairs, one per line — pipe directly to tools like nmap, masscan, nuclei, httpx\n"+
				"  services: JSON array with IP, port, service name, product, and version for each entry\n"+
				"  hosts: JSON array with IP, country, city, ASN, org, cloud provider/type, and open port count per host\n\n"+
				"Default limit is 1000, max 10000. Without a query filter, exports the entire dataset up to the limit."),
		mcp.WithString("query",
			mcp.Description("Optional MeowQL query to filter exported data. Examples: 'service:http and country:FR', 'port:22', 'cloud:aws'. If omitted, exports all data"),
		),
		mcp.WithString("type",
			mcp.Description("Output format. 'ip_list' (default): plain text IP:port lines. 'services': JSON with service details. 'hosts': JSON with host-level summary"),
			mcp.Enum("hosts", "services", "ip_list"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum entries to export (default: 1000, max: 10000)"),
		),
	), h.handleExport)

	// meow_dns — DNS resolution
	s.AddTool(mcp.NewTool("meow_dns",
		mcp.WithDescription(
			"Perform DNS resolution for a domain name or reverse lookup for an IP address. "+
				"For domains: returns A (IPv4), AAAA (IPv6), CNAME, MX (with priority), NS, and TXT records. "+
				"For IPs: returns PTR (reverse DNS) records. "+
				"Additionally checks whether resolved IPs exist in the scan database, "+
				"enabling cross-referencing between DNS data and scan results. "+
				"Useful for validating domain ownership, checking DNS configuration, "+
				"and linking discovered domains back to scanned infrastructure."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Domain name to resolve (e.g. 'example.com') or IP address for reverse lookup (e.g. '8.8.8.8')"),
		),
	), h.handleDNS)

	// meow_scan — Submit a scan request via NATS to connected scanners
	s.AddTool(mcp.NewTool("meow_scan",
		mcp.WithDescription(
			"Submit a new network scan request to connected synscan instances via NATS. "+
				"Requires at least one active scanner (use meow_scanners to check). "+
				"Launches a SYN scan on the specified targets and ports. "+
				"Results will appear in the datastore as the scan progresses."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target specification: CIDR (192.168.1.0/24), range (10.0.0.1-10.0.0.254), or nmap-style (10.0.0-5.1-254). Multiple targets comma-separated"),
		),
		mcp.WithString("ports",
			mcp.Description("Port specification: single (80), range (1-1024), or comma-separated (22,80,443,8080). Default: top 1000 ports"),
		),
		mcp.WithNumber("rate",
			mcp.Description("Packets per second rate limit (default: 10000)"),
		),
	), h.handleScan)

	// meow_scanners — List active scanner instances
	s.AddTool(mcp.NewTool("meow_scanners",
		mcp.WithDescription(
			"List all active synscan instances connected to the NATS bus. "+
				"Shows each scanner's node ID, hostname, status (idle/scanning), current scan progress, "+
				"and transport type. Use this to verify scanner availability before submitting a scan with meow_scan."),
	), h.handleScanners)

	// meow_status — System status
	s.AddTool(mcp.NewTool("meow_status",
		mcp.WithDescription(
			"Get operational status of the datastore: database table row counts (hosts, services, certificates), "+
				"enrichment pipeline progress with completion rate percentage, "+
				"domain and HTTP service counts, "+
				"and per-service enrichment breakdown showing total vs enriched count for each service type. "+
				"Use this to monitor scan progress and identify enrichment gaps (services with low enrichment rates)."),
	), h.handleStatus)
}

const mcpInstructions = `Meow is a network scanner datastore containing results from SYN scans, service fingerprinting, and protocol enrichment. You can query these results using MeowQL.

Recommended workflow:
1. Start with meow_stats to understand the dataset scope (host/service counts, top services, countries)
2. Use meow_count for quick counting (e.g. "how many hosts match port:443?") — much cheaper than meow_search
3. Use meow_search to find specific targets with MeowQL queries (supports hosts and services modes)
4. Use meow_host to drill into a specific IP for full service/cert/domain details
5. Use meow_pivot to correlate infrastructure (hosts sharing same banner, JARM, cert, product, or ASN)
6. Use meow_certs to audit TLS certificates (expired, self-signed, weak keys, expiring soon)
7. Use meow_domains for domain intelligence (virtual hosting, SNI mapping, CDN backends)
8. Use meow_export to extract IP lists or structured data for downstream tools (nmap, nuclei, httpx)
9. Use meow_dns to resolve domains or reverse-lookup IPs and cross-reference with scan data
10. Use meow_status to check enrichment pipeline progress and identify gaps

Field filtering (token optimization):
Most tools accept an optional 'fields' parameter (comma-separated) to control which fields appear in results.
Each tool returns a reduced default set. Pass fields explicitly to get additional data.
- meow_search (services mode): default ip,port,service,product,version,country,cloud,org,enrichment_keys.
  The enrichment_keys field lists available enrichment attribute names per service.
  To get enrichment values, request specific fields like: fields=ip,port,enrichment.anonymous_login,enrichment.shares
- meow_host: use 'sections' (services,certificates,domains) to skip sub-queries. 'fields' controls service/cert row content.
- meow_stats: 'fields' selects stat sections (e.g. fields=total_hosts,top_services). Extra: cloud_providers,top_products,top_technologies.
- meow_pivot: default ip,port,service,product,country_code. Extra: version,cloud_provider,as_org.
- meow_certs: default fingerprint,subject_cn,issuer_cn,status,self_signed,host_count,not_after. Extra: names,algorithm,bits,serial,etc.
- meow_domains: list default domain,services_count,protocols. Detail default ip,port,protocol,status_code,title,country.

MeowQL quick reference:
  field:value          substring match (LIKE)
  field="exact"        exact match
  field!=value         not equal
  field:{a,b,c}        match any value in set
  ip:192.168.0.0/24    CIDR range filter
  field:*              field exists (not null/empty)
  field>N field<N      numeric comparison
  expr1 expr2          implicit AND
  expr1 or expr2       OR
  not expr             negation
  (expr1 or expr2)     grouping with parentheses

Key fields: ip, port, service, product, version, banner, banner_hash,
  country, city, asn, org, cloud, cloud.type,
  http.title, http.server, http.status, http.favicon, http.redirect, framework, tech,
  tls.cert.cn, tls.cert.issuer, tls.cert.expired, tls.self_signed, tls.jarm,
  enrichment (status), enrichment.* (JSON paths like enrichment.anonymous_login, enrichment.auth_required,enrichment.nfs_found,enrichment.shares)`
