package main

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// startMCP creates and runs the MCP server on stdio.
// Blocks until the client disconnects.
func startMCP(db *DB) error {
	s := server.NewMCPServer(
		"meow-datastore",
		version,
		server.WithToolCapabilities(false),
		server.WithInstructions(mcpInstructions),
	)

	h := &mcpHandler{db: db}
	h.registerTools(s)

	return server.ServeStdio(s)
}

// mcpHandler holds the shared state for all MCP tool handlers.
type mcpHandler struct {
	db *DB
}

func (h *mcpHandler) registerTools(s *server.MCPServer) {
	// meow_search — MeowQL search (hosts or services)
	s.AddTool(mcp.NewTool("meow_search",
		mcp.WithDescription("Search scan results using MeowQL query language. "+
			"Returns hosts or services matching the query. "+
			"MeowQL syntax: field:value (contains), field=\"exact\", field!=value, "+
			"field:{a,b,c} (set), ip:CIDR, AND/OR/NOT, parentheses. "+
			"40+ fields: ip, port, service, product, version, banner, country, cloud, asn, org, "+
			"http.title, http.server, http.status, tls.cert.cn, tls.jarm, enrichment.*, etc."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("MeowQL query string (e.g. 'port:443 and country:FR', 'service:ssh and ip:10.0.0.0/8')"),
		),
		mcp.WithString("mode",
			mcp.Description("Search mode: 'hosts' returns unique hosts, 'services' returns individual service entries"),
			mcp.Enum("hosts", "services"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return"),
		),
		mcp.WithNumber("page",
			mcp.Description("Page number for pagination (starts at 1)"),
		),
	), h.handleSearch)

	// meow_host — Detailed host information
	s.AddTool(mcp.NewTool("meow_host",
		mcp.WithDescription("Get complete details for a specific IP: services, certificates, domains, enrichments."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up"),
		),
	), h.handleHost)

	// meow_stats — Overview statistics
	s.AddTool(mcp.NewTool("meow_stats",
		mcp.WithDescription("Get a global overview of scan results: total hosts/services/certificates, "+
			"top services, top countries, cloud providers, enrichment progress, top products, top technologies."),
	), h.handleStats)

	// meow_vulns — Vulnerability pattern detection
	s.AddTool(mcp.NewTool("meow_vulns",
		mcp.WithDescription("Detect common vulnerability patterns across scan results: "+
			"anonymous FTP, exposed databases (Redis/MongoDB/Elasticsearch/Memcached), "+
			"expired/self-signed certificates, weak TLS, telnet, open SNMP, default credentials, etc. "+
			"Returns counts and sample IPs for each finding."),
		mcp.WithString("category",
			mcp.Description("Filter by category"),
			mcp.Enum("all", "auth", "tls", "exposure", "misconfig"),
		),
		mcp.WithString("scope",
			mcp.Description("Optional MeowQL filter to scope the analysis (e.g. 'ip:10.0.0.0/8', 'country:FR')"),
		),
	), h.handleVulns)

	// meow_pivot — Cross-correlation between entities
	s.AddTool(mcp.NewTool("meow_pivot",
		mcp.WithDescription("Find all hosts/services sharing the same indicator. "+
			"Pivot by banner_hash (identical software), jarm (TLS fingerprint), "+
			"cert (shared certificate), product (same product string), or asn (same network)."),
		mcp.WithString("by",
			mcp.Required(),
			mcp.Description("Pivot type"),
			mcp.Enum("banner_hash", "jarm", "cert", "product", "asn"),
		),
		mcp.WithString("value",
			mcp.Required(),
			mcp.Description("Value to pivot on (e.g. SHA256 hash, JARM string, cert fingerprint, product name, ASN number)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return"),
		),
	), h.handlePivot)

	// meow_certs — Certificate search and analysis
	s.AddTool(mcp.NewTool("meow_certs",
		mcp.WithDescription("Search and analyze TLS certificates. "+
			"Filter by subject, issuer, self-signed, expired, weak keys. "+
			"Returns certificate details with host count and expiration status."),
		mcp.WithString("query",
			mcp.Description("Search text (matches subject CN, issuer, names, fingerprint, serial, org)"),
		),
		mcp.WithString("filter",
			mcp.Description("Pre-built filter for common audit checks"),
			mcp.Enum("all", "expired", "self_signed", "expiring_soon", "weak_key"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return"),
		),
	), h.handleCerts)

	// meow_domains — Domain intelligence
	s.AddTool(mcp.NewTool("meow_domains",
		mcp.WithDescription("Domain intelligence from enrichment results. "+
			"List domains with service counts, protocols, HTTP titles. "+
			"Get per-domain service breakdown showing all IPs/ports serving a domain (virtual hosting, CDN, etc)."),
		mcp.WithString("domain",
			mcp.Description("Specific domain to get full service details for. If omitted, lists all domains."),
		),
		mcp.WithString("query",
			mcp.Description("Filter domains by substring match"),
		),
		mcp.WithString("protocol",
			mcp.Description("Filter by protocol (http, https, ssh, etc.)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return"),
		),
	), h.handleDomains)

	// meow_export — Export filtered data
	s.AddTool(mcp.NewTool("meow_export",
		mcp.WithDescription("Export scan results as structured data. "+
			"Supports MeowQL filtering. Types: hosts (IP+geo+cloud), services (IP:port+product), "+
			"ip_list (plain IP:port list for tools)."),
		mcp.WithString("query",
			mcp.Description("MeowQL query to filter exported data"),
		),
		mcp.WithString("type",
			mcp.Description("Export type"),
			mcp.Enum("hosts", "services", "ip_list"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results to return (default 1000)"),
		),
	), h.handleExport)

	// meow_dns — DNS resolution
	s.AddTool(mcp.NewTool("meow_dns",
		mcp.WithDescription("Resolve a domain or reverse-lookup an IP. "+
			"Returns A, AAAA, CNAME, MX, NS, TXT records for domains, PTR for IPs."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Domain name or IP address to resolve"),
		),
	), h.handleDNS)

	// meow_status — System status
	s.AddTool(mcp.NewTool("meow_status",
		mcp.WithDescription("Database statistics and enrichment progress. "+
			"Shows table counts, enrichment status breakdown, top services."),
	), h.handleStatus)
}

const mcpInstructions = `Meow is a network scanner datastore. You can query scan results using MeowQL.

Recommended workflow:
1. Start with meow_stats to understand the scope (how many hosts, top services, etc.)
2. Use meow_search with MeowQL queries to find specific targets
3. Use meow_host to drill into individual hosts
4. Use meow_vulns to find security issues across the dataset
5. Use meow_pivot to correlate hosts sharing the same banner, JARM, cert, or product
6. Use meow_certs to audit TLS certificates (expired, self-signed, weak keys)
7. Use meow_domains for domain intelligence (virtual hosting, SNI mapping)
8. Use meow_export to extract IP lists or structured data for other tools
9. Use meow_dns to resolve domains or reverse-lookup IPs

MeowQL quick reference:
  field:value          contains (LIKE)
  field="exact"        exact match
  field!=value         not equal
  field:{a,b,c}        set (OR)
  ip:192.168.0.0/24    CIDR range
  field:*              field exists
  field>N field<N      numeric comparison
  expr1 expr2          implicit AND
  expr1 or expr2       OR
  not expr             negation
  (expr1 or expr2)     grouping

Key fields: ip, port, service, product, version, banner, banner_hash,
  country, city, asn, org, cloud, cloud.type,
  http.title, http.server, http.status, http.favicon, http.redirect, framework, tech,
  tls.cert.cn, tls.cert.issuer, tls.cert.expired, tls.self_signed, tls.jarm,
  enrichment (status), enrichment.* (JSON paths like enrichment.anonymous_login)`
