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

// newMCPServer builds the MCP server and registers all tools. Shared by the
// HTTP transport (newMCPHandler) and the stdio transport (runMCPStdio).
// nc and scanTracker may be nil (stdio mode): meow_scan then returns a clear
// error and meow_status omits the scanners section (handlers nil-guard).
func newMCPServer(db *DB, nc natsPublisher, scanTracker *ScannerTracker) *server.MCPServer {
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

	return s
}

// newMCPHandler creates a Streamable HTTP handler for the MCP server.
// Mount it on the gin router (e.g. at /mcp).
func newMCPHandler(db *DB, nc natsPublisher, scanTracker *ScannerTracker) http.Handler {
	return server.NewStreamableHTTPServer(newMCPServer(db, nc, scanTracker), server.WithStateLess(true))
}

// mcpHandler holds the shared state for all MCP tool handlers.
type mcpHandler struct {
	db          *DB
	nc          natsPublisher
	scanTracker *ScannerTracker
}

func (h *mcpHandler) registerTools(s *server.MCPServer) {

	s.AddTool(mcp.NewTool("meow_search",
		mcp.WithDescription("Search scan results using MeowQL. Returns hosts (unique IPs) or services (IP:port entries)."),
		mcp.WithString("query", mcp.Required(),
			mcp.Description("MeowQL query. Ex: port:443 country:FR, service:ssh ip:10.0.0.0/8")),
		mcp.WithString("mode",
			mcp.Description("hosts (default) or services"),
			mcp.Enum("hosts", "services")),
		mcp.WithNumber("limit", mcp.Description("Results per page (default 50, max 500)")),
		mcp.WithNumber("page", mcp.Description("Page number, starts at 1")),
		mcp.WithString("fields",
			mcp.Description("Comma-separated fields to return (services mode). Default: ip,port,service,product,version,country,cloud,org,enrichment_keys. Also available: city, banner, http.status, http.title, http.server, http.favicon, and enrichment.<key> for enrichment values. banner and enrichment_data are only read from disk when requested.")),
	), h.handleSearch)

	s.AddTool(mcp.NewTool("meow_stats",
		mcp.WithDescription("Dataset overview: total host/service/certificate counts, enrichment status breakdown, top services and countries (and on request cloud providers, top products, top technologies)."),
		mcp.WithString("fields",
			mcp.Description("Sections to include (default: total_hosts,total_services,total_certificates,enrichment,top_services,top_countries). Extra: cloud_providers,top_products,top_technologies")),
	), h.handleStats)

	s.AddTool(mcp.NewTool("meow_count",
		mcp.WithDescription("Lightweight count-only query: number of matching hosts or services for a MeowQL query, without row data. Much cheaper than meow_search when you only need a count."),
		mcp.WithString("query", mcp.Required(),
			mcp.Description("MeowQL query. Ex: port:443 country:FR")),
		mcp.WithString("mode",
			mcp.Description("Count hosts (default) or services"),
			mcp.Enum("hosts", "services")),
	), h.handleCount)

	s.AddTool(mcp.NewTool("meow_schema",
		mcp.WithDescription("Family-aware enrichment schema discovery. No args: list the protocol FAMILIES present (canonical protocol, member service names seen, enriched count). With protocol/service: union of enrichment fields (keys, types, sample values) across ALL members of that protocol family (e.g. 'smb' covers microsoft-ds, netbios-ssn, cifs)."),
		mcp.WithString("protocol",
			mcp.Description("Canonical protocol family to inspect (e.g. 'smb','nfs','http'). Preferred over 'service'. Resolves all family member service names.")),
		mcp.WithString("service",
			mcp.Description("Service name (e.g. 'mysql','rdp','smb'); resolved to its protocol family. Kept for backward compat — prefer 'protocol'. Empty/'*' = list families.")),
		mcp.WithString("search",
			mcp.Description("Filter enrichment keys by substring (e.g. 'anonymous')")),
	), h.handleSchema)

	s.AddTool(mcp.NewTool("meow_host",
		mcp.WithDescription("Full profile of a single host: geo, ASN, cloud, services with enrichment, certificates, domains."),
		mcp.WithString("ip", mcp.Required(), mcp.Description("IPv4 or IPv6 address")),
		mcp.WithString("sections", mcp.Description("Comma-separated: services,certificates,domains (default: all)")),
		mcp.WithString("fields", mcp.Description("Fields per service/cert row")),
	), h.handleHost)

	s.AddTool(mcp.NewTool("meow_pivot",
		mcp.WithDescription("Find hosts sharing a common indicator for infrastructure correlation."),
		mcp.WithString("by", mcp.Required(),
			mcp.Description("Pivot type"),
			mcp.Enum("banner_hash", "jarm", "cert", "product", "asn")),
		mcp.WithString("value", mcp.Required(), mcp.Description("Indicator value to search for")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 100, max 1000)")),
		mcp.WithString("fields", mcp.Description("Fields per row (default: ip,port,service,product,country_code)")),
	), h.handlePivot)

	s.AddTool(mcp.NewTool("meow_certs",
		mcp.WithDescription("Search/audit TLS certificates. Supports text search and security filters."),
		mcp.WithString("query", mcp.Description("Search across CN, issuer, SANs, fingerprint, serial")),
		mcp.WithString("filter",
			mcp.Description("Security filter"),
			mcp.Enum("all", "expired", "self_signed", "expiring_soon", "weak_key")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 50, max 500)")),
		mcp.WithString("fields", mcp.Description("Fields per cert (default: fingerprint,subject_cn,issuer_cn,status,self_signed,host_count,not_after)")),
	), h.handleCerts)

	s.AddTool(mcp.NewTool("meow_domains",
		mcp.WithDescription("Domain intelligence. Without domain param: list domains with stats. With domain param: all services for that domain."),
		mcp.WithString("domain", mcp.Description("Specific domain for detail mode")),
		mcp.WithString("query", mcp.Description("Substring filter in list mode")),
		mcp.WithString("protocol", mcp.Description("Filter by protocol (http, https, ssh...)")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 50, max 500)")),
		mcp.WithString("fields", mcp.Description("Fields per row")),
	), h.handleDomains)

	s.AddTool(mcp.NewTool("meow_export",
		mcp.WithDescription("Export scan results for downstream tools (nmap, nuclei, httpx)."),
		mcp.WithString("query", mcp.Description("MeowQL filter (optional, exports all if empty)")),
		mcp.WithString("type",
			mcp.Description("Output format"),
			mcp.Enum("ip_list", "services", "hosts", "domains")),
		mcp.WithNumber("limit", mcp.Description("Max entries (default 1000, max 10000)")),
	), h.handleExport)

	s.AddTool(mcp.NewTool("meow_dns",
		mcp.WithDescription("DNS resolution (domain→records) or reverse lookup (IP→PTR). Cross-references with scan database."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Domain name or IP address")),
	), h.handleDNS)

	s.AddTool(mcp.NewTool("meow_scan",
		mcp.WithDescription("Submit SYN scan request to connected scanners via NATS."),
		mcp.WithString("target", mcp.Required(), mcp.Description("CIDR, range, or nmap-style target. Comma-separated for multiple")),
		mcp.WithString("ports", mcp.Description("Port spec: 80, 1-1024, 22,80,443 (default: top 1000)")),
		mcp.WithNumber("rate", mcp.Description("Packets/sec rate limit (default 10000)")),
	), h.handleScan)

	s.AddTool(mcp.NewTool("meow_status",
		mcp.WithDescription("System status: DB counts, enrichment progress, service breakdown, and active scanners."),
	), h.handleStatus)
}

const mcpInstructions = `Meow network scanner datastore. Query scan results with MeowQL.

Workflow: meow_stats (overview) → meow_search to find targets → meow_host for details → meow_pivot to correlate.
Use meow_count for fast counts and meow_schema to discover enrichment fields per service.

MeowQL syntax:
  field:value (contains), field="exact", field!=val, field:{a,b,c} (set), ip:CIDR/24
  field:* (exists), field>N, field<N, expr1 expr2 (AND), expr1 or expr2, not expr, (grouping)

Fields: ip, port, service, product, version, banner, banner_hash, country, city, asn, org, cloud, cloud.type,
  http.title, http.server, http.status, http.favicon, http.redirect, framework, tech,
  tls.cert.cn, tls.cert.issuer, tls.cert.expired, tls.self_signed, tls.jarm,
  enrichment (status), enrichment.* (JSON paths: enrichment.anonymous_login, enrichment.auth_required)

Token optimization: use 'fields' param to limit returned columns. meow_stats with query param = lightweight count.`
