package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"meow/datastore/pkg/meowql"
)

// ---------------------------------------------------------------------------
// meow_search — MeowQL search (hosts or services)
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleSearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	if query == "" {
		return mcp.NewToolResultError("query parameter required"), nil
	}
	mode := req.GetString("mode", "hosts")
	limit := intOrDefault(req.GetInt("limit", 0), 50)
	page := intOrDefault(req.GetInt("page", 0), 1)
	offset := (page - 1) * limit

	if mode == "services" {
		return h.searchServices(ctx, query, limit, offset)
	}
	return h.searchHosts(ctx, query, limit, offset, page)
}

func (h *mcpHandler) searchHosts(ctx context.Context, query string, limit, offset, page int) (*mcp.CallToolResult, error) {
	result := meowql.Compile(query)
	if result.Err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v\nAvailable fields: %s",
			result.Err, strings.Join(meowql.FieldNames(), ", "))), nil
	}

	var total int
	if err := h.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where),
		result.Args...,
	).Scan(&total); err != nil {
		return nil, fmt.Errorf("count query failed: %w", err)
	}

	args := append(result.Args, limit, offset)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT h.ip, h.country_code, h.asn, h.as_org, h.cloud_provider,
		       h.open_ports_count, h.services_count
		FROM hosts h WHERE %s
		ORDER BY h.last_scan DESC LIMIT ? OFFSET ?`, result.Where), args...)
	if err != nil {
		return nil, fmt.Errorf("search query failed: %w", err)
	}
	defer rows.Close()

	var hosts []map[string]any
	for rows.Next() {
		var ip string
		var countryCode, asOrg, cloudProvider sql.NullString
		var asn, openPorts, svcCount sql.NullInt64
		if err := rows.Scan(&ip, &countryCode, &asn, &asOrg, &cloudProvider, &openPorts, &svcCount); err != nil {
			continue
		}
		host := map[string]any{"ip": ip}
		setNullStr(host, "country", countryCode)
		setNullInt(host, "asn", asn)
		setNullStr(host, "org", asOrg)
		setNullStr(host, "cloud", cloudProvider)
		setNullInt(host, "ports", openPorts)
		setNullInt(host, "services", svcCount)
		hosts = append(hosts, host)
	}

	return mcpJSON(map[string]any{
		"total": total,
		"page":  page,
		"count": len(hosts),
		"hosts": hosts,
	})
}

func (h *mcpHandler) searchServices(ctx context.Context, query string, limit, offset int) (*mcp.CallToolResult, error) {
	result := meowql.CompileServiceCentric(query)
	if result.Err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
	}

	var total int
	if err := h.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT COUNT(*) FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND s.enrichment_status != 'pending'`, result.Where),
		result.Args...,
	).Scan(&total); err != nil {
		return nil, fmt.Errorf("count query failed: %w", err)
	}

	args := append(result.Args, limit, offset)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       s.enrichment_status, h.country_code, h.cloud_provider, h.as_org,
		       hd.status_code, hd.title, hd.server
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		LEFT JOIN http_data hd ON hd.ip = s.ip AND hd.port = s.port
		WHERE %s AND s.enrichment_status != 'pending'
		ORDER BY s.detected_at DESC LIMIT ? OFFSET ?`, result.Where), args...)
	if err != nil {
		return nil, fmt.Errorf("search query failed: %w", err)
	}
	defer rows.Close()

	var services []map[string]any
	for rows.Next() {
		var ip string
		var port int
		var svcName, product, version, banner, enrichStatus sql.NullString
		var countryCode, cloudProvider, asOrg sql.NullString
		var httpStatus sql.NullInt64
		var httpTitle, httpServer sql.NullString

		if err := rows.Scan(&ip, &port, &svcName, &product, &version, &banner,
			&enrichStatus, &countryCode, &cloudProvider, &asOrg,
			&httpStatus, &httpTitle, &httpServer); err != nil {
			continue
		}

		svc := map[string]any{"ip": ip, "port": port}
		setNullStr(svc, "service", svcName)
		setNullStr(svc, "product", product)
		setNullStr(svc, "version", version)
		setNullStr(svc, "banner", banner)
		setNullStr(svc, "enrichment", enrichStatus)
		setNullStr(svc, "country", countryCode)
		setNullStr(svc, "cloud", cloudProvider)
		setNullStr(svc, "org", asOrg)
		setNullInt(svc, "http_status", httpStatus)
		setNullStr(svc, "http_title", httpTitle)
		setNullStr(svc, "http_server", httpServer)
		services = append(services, svc)
	}

	return mcpJSON(map[string]any{
		"total":    total,
		"count":    len(services),
		"services": services,
	})
}

// ---------------------------------------------------------------------------
// meow_host — Detailed host information
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleHost(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ip, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError("ip parameter required"), nil
	}

	// Host info
	var countryCode, countryName, city, cloudProvider, cloudRegion, asOrg sql.NullString
	var asn, firstSeen, lastScan, openPorts, svcCount sql.NullInt64
	err = h.db.QueryRowContext(ctx, `
		SELECT country_code, country_name, city, asn, as_org, cloud_provider, cloud_region,
		       first_seen, last_scan, open_ports_count, services_count
		FROM hosts WHERE ip = ?`, ip).Scan(
		&countryCode, &countryName, &city, &asn, &asOrg, &cloudProvider, &cloudRegion,
		&firstSeen, &lastScan, &openPorts, &svcCount)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("host %s not found", ip)), nil
	}

	host := map[string]any{"ip": ip}
	setNullStr(host, "country_code", countryCode)
	setNullStr(host, "country_name", countryName)
	setNullStr(host, "city", city)
	setNullInt(host, "asn", asn)
	setNullStr(host, "as_org", asOrg)
	setNullStr(host, "cloud_provider", cloudProvider)
	setNullStr(host, "cloud_region", cloudRegion)
	setNullInt(host, "first_seen", firstSeen)
	setNullInt(host, "last_scan", lastScan)
	setNullInt(host, "open_ports_count", openPorts)
	setNullInt(host, "services_count", svcCount)

	// Services
	host["services"] = h.queryServices(ctx, ip)

	// Certificates
	host["certificates"] = h.queryCertificates(ctx, ip)

	// Domains
	host["domains"] = h.queryDomains(ctx, ip)

	return mcpJSON(host)
}

func (h *mcpHandler) queryServices(ctx context.Context, ip string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT s.port, s.service, s.product, s.version, s.banner,
		       s.enrichment_status, s.enrichment_data,
		       hd.status_code, hd.title, hd.server, hd.technologies, hd.cms, hd.framework
		FROM services s
		LEFT JOIN http_data hd ON s.ip = hd.ip AND s.port = hd.port
		WHERE s.ip = ? ORDER BY s.port`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var services []map[string]any
	for rows.Next() {
		var port int
		var svcName, product, version, banner, enrichStatus sql.NullString
		var enrichData sql.NullString
		var httpStatus sql.NullInt64
		var httpTitle, httpServer, httpTech, httpCMS, httpFramework sql.NullString

		if err := rows.Scan(&port, &svcName, &product, &version, &banner,
			&enrichStatus, &enrichData,
			&httpStatus, &httpTitle, &httpServer, &httpTech, &httpCMS, &httpFramework); err != nil {
			continue
		}

		svc := map[string]any{"port": port}
		setNullStr(svc, "service", svcName)
		setNullStr(svc, "product", product)
		setNullStr(svc, "version", version)
		setNullStr(svc, "banner", banner)
		setNullStr(svc, "enrichment", enrichStatus)
		setNullInt(svc, "http_status", httpStatus)
		setNullStr(svc, "http_title", httpTitle)
		setNullStr(svc, "http_server", httpServer)
		setNullStr(svc, "cms", httpCMS)
		setNullStr(svc, "framework", httpFramework)

		// Parse enrichment_data JSON for key fields
		if enrichData.Valid && enrichData.String != "" && enrichData.String != "{}" {
			var ed map[string]any
			if json.Unmarshal([]byte(enrichData.String), &ed) == nil {
				// Extract interesting enrichment fields
				for _, key := range []string{
					"anonymous_login", "auth_required", "signing_required",
					"default_credentials", "tls", "protocol", "version",
				} {
					if v, ok := ed[key]; ok {
						svc["enrichment."+key] = v
					}
				}
			}
		}

		services = append(services, svc)
	}
	return services
}

func (h *mcpHandler) queryCertificates(ctx context.Context, ip string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT c.fingerprint_sha256, c.subject_cn, c.issuer_cn, c.names,
		       c.not_before, c.not_after, c.is_self_signed,
		       c.public_key_algorithm, c.public_key_bits,
		       sc.jarm, sc.port
		FROM certificates c
		JOIN service_certificates sc ON c.fingerprint_sha256 = sc.cert_fingerprint
		WHERE sc.ip = ? AND sc.chain_position = 0
		ORDER BY sc.port`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	now := time.Now().Unix()
	var certs []map[string]any
	for rows.Next() {
		var fingerprint, subjectCN, issuerCN, names sql.NullString
		var notBefore, notAfter sql.NullInt64
		var selfSigned sql.NullInt64
		var algo sql.NullString
		var bits sql.NullInt64
		var jarm sql.NullString
		var port int

		if err := rows.Scan(&fingerprint, &subjectCN, &issuerCN, &names,
			&notBefore, &notAfter, &selfSigned,
			&algo, &bits, &jarm, &port); err != nil {
			continue
		}

		cert := map[string]any{"port": port}
		setNullStr(cert, "fingerprint", fingerprint)
		setNullStr(cert, "subject_cn", subjectCN)
		setNullStr(cert, "issuer_cn", issuerCN)
		setNullStr(cert, "names", names)
		setNullStr(cert, "algorithm", algo)
		setNullInt(cert, "bits", bits)
		setNullStr(cert, "jarm", jarm)
		if selfSigned.Valid && selfSigned.Int64 == 1 {
			cert["self_signed"] = true
		}
		if notAfter.Valid {
			cert["not_after"] = notAfter.Int64
			if notAfter.Int64 < now {
				cert["expired"] = true
			}
		}
		certs = append(certs, cert)
	}
	return certs
}

func (h *mcpHandler) queryDomains(ctx context.Context, ip string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT domain, source, discovered_port
		FROM host_domains WHERE ip = ? ORDER BY last_seen DESC`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var domains []map[string]any
	for rows.Next() {
		var domain, source sql.NullString
		var port sql.NullInt64
		if err := rows.Scan(&domain, &source, &port); err != nil {
			continue
		}
		d := map[string]any{}
		setNullStr(d, "domain", domain)
		setNullStr(d, "source", source)
		setNullInt(d, "port", port)
		domains = append(domains, d)
	}
	return domains
}

// ---------------------------------------------------------------------------
// meow_stats — Overview statistics
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleStats(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := map[string]any{}

	// Total counts
	var totalHosts, totalServices, totalCerts int64
	h.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM hosts),
		(SELECT COUNT(*) FROM services),
		(SELECT COUNT(*) FROM certificates)`).Scan(&totalHosts, &totalServices, &totalCerts)
	stats["total_hosts"] = totalHosts
	stats["total_services"] = totalServices
	stats["total_certificates"] = totalCerts

	// Enrichment status
	var enriched, pending, failed, skipped int
	h.db.QueryRowContext(ctx, `SELECT
		SUM(CASE WHEN enrichment_status = 'enriched' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status = 'pending' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status = 'failed' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status NOT IN ('enriched','pending','failed') OR enrichment_status IS NULL THEN 1 ELSE 0 END)
	FROM services`).Scan(&enriched, &pending, &failed, &skipped)
	stats["enrichment"] = map[string]int{
		"enriched": enriched, "pending": pending, "failed": failed, "skipped": skipped,
	}

	// Top services
	stats["top_services"] = h.queryValueCounts(ctx, `
		SELECT service, COUNT(*) FROM services
		WHERE service IS NOT NULL GROUP BY service ORDER BY COUNT(*) DESC LIMIT 15`)

	// Top countries
	stats["top_countries"] = h.queryValueCounts(ctx, `
		SELECT country_code, COUNT(*) FROM hosts
		WHERE country_code IS NOT NULL GROUP BY country_code ORDER BY COUNT(*) DESC LIMIT 10`)

	// Cloud providers
	stats["cloud_providers"] = h.queryValueCounts(ctx, `
		SELECT cloud_provider, COUNT(*) FROM hosts
		WHERE cloud_provider IS NOT NULL GROUP BY cloud_provider ORDER BY COUNT(*) DESC`)

	// Top products
	stats["top_products"] = h.queryValueCounts(ctx, `
		SELECT product, COUNT(*) FROM services
		WHERE product IS NOT NULL AND product != '' GROUP BY product ORDER BY COUNT(*) DESC LIMIT 15`)

	// Top technologies
	stats["top_technologies"] = h.queryValueCounts(ctx, `
		SELECT json_extract(value, '$.name'), COUNT(*) FROM http_data, json_each(technologies)
		WHERE technologies IS NOT NULL AND technologies != ''
		GROUP BY json_extract(value, '$.name') ORDER BY COUNT(*) DESC LIMIT 10`)

	return mcpJSON(stats)
}

// ---------------------------------------------------------------------------
// meow_vulns — Vulnerability pattern detection
// ---------------------------------------------------------------------------

type vulnCheck struct {
	name     string
	category string
	severity string
	query    string
}

var vulnChecks = []vulnCheck{
	// Auth issues
	{"FTP Anonymous Login", "auth", "high", "service:ftp and enrichment.anonymous_login:true"},
	{"VNC No Auth", "auth", "high", "service:vnc and enrichment.auth_required:false"},
	{"Default Credentials", "auth", "critical", "enrichment.default_credentials:true"},
	{"MongoDB No Auth", "auth", "critical", "service:mongodb and enrichment.auth_required:false"},
	{"Redis No Auth", "auth", "critical", "service:redis and enrichment.auth_required:false"},

	// TLS issues
	{"Self-Signed Certificates", "tls", "medium", "tls.self_signed:1"},
	{"Weak Key (RSA < 2048)", "tls", "high", "tls.cert.bits<2048"},

	// Service exposure
	{"Telnet Open", "exposure", "high", "service:telnet"},
	{"Exposed Elasticsearch", "exposure", "high", "service:elasticsearch"},
	{"Exposed Memcached", "exposure", "medium", "service:memcached"},
	{"Exposed Cassandra", "exposure", "medium", "service:cassandra"},
	{"Exposed SNMP", "exposure", "medium", "service:snmp"},

	// Misconfig
	{"SMB Signing Disabled", "misconfig", "medium", "service:smb and enrichment.signing_required:false"},
	{"HTTP Without TLS", "misconfig", "low", "http.ssl:false and port:80"},
}

func (h *mcpHandler) handleVulns(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	category := req.GetString("category", "all")
	scope := req.GetString("scope", "")

	var findings []map[string]any
	for _, vc := range vulnChecks {
		if category != "all" && vc.category != category {
			continue
		}

		q := vc.query
		if scope != "" {
			q = "(" + q + ") and " + scope
		}

		result := meowql.Compile(q)
		if result.Err != nil {
			continue
		}

		var count int
		if err := h.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where),
			result.Args...,
		).Scan(&count); err != nil || count == 0 {
			continue
		}

		// Get sample IPs (up to 5)
		sampleArgs := append(result.Args, 5)
		sampleRows, err := h.db.QueryContext(ctx,
			fmt.Sprintf("SELECT h.ip FROM hosts h WHERE %s LIMIT ?", result.Where),
			sampleArgs...)
		if err != nil {
			continue
		}

		var samples []string
		for sampleRows.Next() {
			var ip string
			if sampleRows.Scan(&ip) == nil {
				samples = append(samples, ip)
			}
		}
		sampleRows.Close()

		findings = append(findings, map[string]any{
			"name":     vc.name,
			"category": vc.category,
			"severity": vc.severity,
			"count":    count,
			"samples":  samples,
		})
	}

	// Expired certificates (special: needs timestamp comparison)
	now := time.Now().Unix()
	expiredQuery := fmt.Sprintf("tls.cert.expired<%d", now)
	if scope != "" {
		expiredQuery = "(" + expiredQuery + ") and " + scope
	}
	result := meowql.Compile(expiredQuery)
	if result.Err == nil {
		var count int
		if h.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where),
			result.Args...,
		).Scan(&count) == nil && count > 0 {
			if category == "all" || category == "tls" {
				findings = append(findings, map[string]any{
					"name":     "Expired Certificates",
					"category": "tls",
					"severity": "high",
					"count":    count,
				})
			}
		}
	}

	return mcpJSON(map[string]any{
		"findings":    findings,
		"total_checks": len(vulnChecks) + 1,
		"scope":       scope,
	})
}

// ---------------------------------------------------------------------------
// meow_pivot — Cross-correlation
// ---------------------------------------------------------------------------

func (h *mcpHandler) handlePivot(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	by, err := req.RequireString("by")
	if err != nil {
		return mcp.NewToolResultError("'by' parameter required"), nil
	}
	value, err := req.RequireString("value")
	if err != nil {
		return mcp.NewToolResultError("'value' parameter required"), nil
	}
	limit := intOrDefault(req.GetInt("limit", 0), 100)

	var query string
	var args []any

	switch by {
	case "banner_hash":
		query = `SELECT s.ip, s.port, s.service, s.product, s.version,
		                h.country_code, h.cloud_provider, h.as_org
		         FROM services s JOIN hosts h ON s.ip = h.ip
		         WHERE s.banner_hash = ? ORDER BY s.ip LIMIT ?`
		args = []any{value, limit}

	case "jarm":
		query = `SELECT sc.ip, sc.port, s.service, s.product, s.version,
		                h.country_code, h.cloud_provider, h.as_org
		         FROM service_certificates sc
		         JOIN services s ON s.ip = sc.ip AND s.port = sc.port
		         JOIN hosts h ON h.ip = sc.ip
		         WHERE sc.jarm = ? ORDER BY sc.ip LIMIT ?`
		args = []any{value, limit}

	case "cert":
		query = `SELECT sc.ip, sc.port, s.service, s.product,
		                h.country_code, h.cloud_provider, h.as_org
		         FROM service_certificates sc
		         JOIN services s ON s.ip = sc.ip AND s.port = sc.port
		         JOIN hosts h ON h.ip = sc.ip
		         WHERE sc.cert_fingerprint = ? ORDER BY sc.ip LIMIT ?`
		args = []any{value, limit}

	case "product":
		query = `SELECT s.ip, s.port, s.service, s.product, s.version,
		                h.country_code, h.cloud_provider, h.as_org
		         FROM services s JOIN hosts h ON s.ip = h.ip
		         WHERE LOWER(s.product) = LOWER(?) ORDER BY s.ip LIMIT ?`
		args = []any{value, limit}

	case "asn":
		asnClean := strings.TrimPrefix(strings.TrimPrefix(value, "AS"), "as")
		asnInt, parseErr := strconv.Atoi(asnClean)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid ASN: %s", value)), nil
		}
		query = `SELECT h.ip, h.country_code, h.cloud_provider, h.as_org,
		                h.open_ports_count, h.services_count
		         FROM hosts h WHERE h.asn = ? ORDER BY h.ip LIMIT ?`
		args = []any{asnInt, limit}

	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown pivot type: %s", by)), nil
	}

	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pivot query failed: %w", err)
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var results []map[string]any
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if rows.Scan(ptrs...) != nil {
			continue
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			if values[i] != nil {
				row[col] = values[i]
			}
		}
		results = append(results, row)
	}

	return mcpJSON(map[string]any{
		"pivot_by": by,
		"value":    value,
		"count":    len(results),
		"results":  results,
	})
}

// ---------------------------------------------------------------------------
// meow_certs — Certificate search and analysis
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleCerts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	filter := req.GetString("filter", "all")
	limit := intOrDefault(req.GetInt("limit", 0), 50)

	whereClause := "WHERE 1=1"
	var args []any

	if query != "" {
		queryLower := "%" + strings.ToLower(query) + "%"
		whereClause += ` AND (
			LOWER(c.subject_cn) LIKE ? OR LOWER(c.issuer_cn) LIKE ? OR
			LOWER(c.names) LIKE ? OR c.fingerprint_sha256 LIKE ? OR
			LOWER(c.subject_org) LIKE ? OR LOWER(c.issuer_org) LIKE ? OR
			c.serial_number LIKE ?)`
		args = append(args, queryLower, queryLower, queryLower, queryLower, queryLower, queryLower, queryLower)
	}

	now := time.Now().Unix()
	thirtyDays := now + 30*24*3600

	switch filter {
	case "expired":
		whereClause += " AND c.not_after < ?"
		args = append(args, now)
	case "self_signed":
		whereClause += " AND c.is_self_signed = 1"
	case "expiring_soon":
		whereClause += " AND c.not_after BETWEEN ? AND ?"
		args = append(args, now, thirtyDays)
	case "weak_key":
		whereClause += " AND c.public_key_bits < 2048"
	}

	args = append(args, limit)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org, c.issuer_cn, c.issuer_org,
		       c.names, c.not_before, c.not_after, c.is_self_signed, c.is_ca,
		       c.public_key_algorithm, c.public_key_bits, c.signature_algorithm,
		       c.serial_number,
		       (SELECT COUNT(DISTINCT ip) FROM service_certificates WHERE cert_fingerprint = c.fingerprint_sha256) as host_count
		FROM certificates c
		%s
		ORDER BY host_count DESC, c.not_after DESC
		LIMIT ?`, whereClause), args...)
	if err != nil {
		return nil, fmt.Errorf("cert query failed: %w", err)
	}
	defer rows.Close()

	var certs []map[string]any
	for rows.Next() {
		var fingerprint string
		var subjectCN, subjectOrg, issuerCN, issuerOrg, names sql.NullString
		var notBefore, notAfter sql.NullInt64
		var selfSigned, isCA sql.NullInt64
		var algo, sigAlgo, serial sql.NullString
		var bits sql.NullInt64
		var hostCount int

		if err := rows.Scan(&fingerprint, &subjectCN, &subjectOrg, &issuerCN, &issuerOrg,
			&names, &notBefore, &notAfter, &selfSigned, &isCA,
			&algo, &bits, &sigAlgo, &serial, &hostCount); err != nil {
			continue
		}

		cert := map[string]any{
			"fingerprint": fingerprint,
			"host_count":  hostCount,
		}
		setNullStr(cert, "subject_cn", subjectCN)
		setNullStr(cert, "subject_org", subjectOrg)
		setNullStr(cert, "issuer_cn", issuerCN)
		setNullStr(cert, "issuer_org", issuerOrg)
		setNullStr(cert, "names", names)
		setNullStr(cert, "algorithm", algo)
		setNullInt(cert, "bits", bits)
		setNullStr(cert, "signature_algorithm", sigAlgo)
		setNullStr(cert, "serial", serial)
		if selfSigned.Valid && selfSigned.Int64 == 1 {
			cert["self_signed"] = true
		}
		if isCA.Valid && isCA.Int64 == 1 {
			cert["is_ca"] = true
		}
		if notAfter.Valid {
			cert["not_after"] = notAfter.Int64
			if notAfter.Int64 < now {
				cert["status"] = "expired"
			} else if notAfter.Int64 < thirtyDays {
				cert["status"] = "expiring_soon"
			} else {
				cert["status"] = "valid"
			}
		}
		if notBefore.Valid {
			cert["not_before"] = notBefore.Int64
		}

		certs = append(certs, cert)
	}

	return mcpJSON(map[string]any{
		"filter": filter,
		"count":  len(certs),
		"certs":  certs,
	})
}

// ---------------------------------------------------------------------------
// meow_domains — Domain intelligence
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleDomains(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain := req.GetString("domain", "")
	limit := intOrDefault(req.GetInt("limit", 0), 50)

	// If a specific domain is given, return its full service breakdown
	if domain != "" {
		return h.domainServices(ctx, domain, limit)
	}

	// Otherwise, list domains with stats
	query := req.GetString("query", "")
	protocol := req.GetString("protocol", "")

	whereClause := "WHERE se.domain != '' AND se.status = 'enriched'"
	var args []any

	if query != "" {
		whereClause += " AND LOWER(se.domain) LIKE ?"
		args = append(args, "%"+strings.ToLower(query)+"%")
	}
	if protocol != "" {
		whereClause += " AND se.protocol = ?"
		args = append(args, protocol)
	}

	// Stats
	var totalDomains int
	h.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(DISTINCT se.domain) FROM service_enrichments se %s", whereClause),
		args...).Scan(&totalDomains)

	args = append(args, limit)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT se.domain, COUNT(*) as services_count,
			GROUP_CONCAT(DISTINCT se.protocol) as protocols,
			MAX(se.title) as sample_title,
			MAX(se.status_code) as sample_status_code,
			MAX(se.server) as sample_server,
			MAX(se.enriched_at) as last_seen
		FROM service_enrichments se
		%s
		GROUP BY se.domain
		ORDER BY services_count DESC
		LIMIT ?`, whereClause), args...)
	if err != nil {
		return nil, fmt.Errorf("domains query failed: %w", err)
	}
	defer rows.Close()

	var domains []map[string]any
	for rows.Next() {
		var d string
		var svcCount int
		var protocols sql.NullString
		var sampleTitle, sampleServer sql.NullString
		var sampleStatus, lastSeen sql.NullInt64

		if err := rows.Scan(&d, &svcCount, &protocols,
			&sampleTitle, &sampleStatus, &sampleServer, &lastSeen); err != nil {
			continue
		}

		entry := map[string]any{
			"domain":         d,
			"services_count": svcCount,
		}
		setNullStr(entry, "protocols", protocols)
		setNullStr(entry, "sample_title", sampleTitle)
		setNullStr(entry, "sample_server", sampleServer)
		setNullInt(entry, "sample_status_code", sampleStatus)
		setNullInt(entry, "last_seen", lastSeen)
		domains = append(domains, entry)
	}

	return mcpJSON(map[string]any{
		"total":   totalDomains,
		"count":   len(domains),
		"domains": domains,
	})
}

func (h *mcpHandler) domainServices(ctx context.Context, domain string, limit int) (*mcp.CallToolResult, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT se.ip, se.port, se.protocol, se.version, se.banner,
			se.status_code, se.title, se.server, se.redirect_url, se.content_length,
			h.country_code, h.as_org, h.cloud_provider
		FROM service_enrichments se
		LEFT JOIN hosts h ON se.ip = h.ip
		WHERE se.domain = ? AND se.status = 'enriched'
		ORDER BY se.ip, se.port
		LIMIT ?`, domain, limit)
	if err != nil {
		return nil, fmt.Errorf("domain services query failed: %w", err)
	}
	defer rows.Close()

	var services []map[string]any
	for rows.Next() {
		var ip string
		var port int
		var protocol, version, banner, title, server, redirectURL sql.NullString
		var countryCode, asOrg, cloudProvider sql.NullString
		var statusCode, contentLength sql.NullInt64

		if err := rows.Scan(&ip, &port, &protocol, &version, &banner,
			&statusCode, &title, &server, &redirectURL, &contentLength,
			&countryCode, &asOrg, &cloudProvider); err != nil {
			continue
		}

		svc := map[string]any{"ip": ip, "port": port}
		setNullStr(svc, "protocol", protocol)
		setNullStr(svc, "version", version)
		setNullStr(svc, "banner", banner)
		setNullInt(svc, "status_code", statusCode)
		setNullStr(svc, "title", title)
		setNullStr(svc, "server", server)
		setNullStr(svc, "redirect_url", redirectURL)
		setNullInt(svc, "content_length", contentLength)
		setNullStr(svc, "country", countryCode)
		setNullStr(svc, "org", asOrg)
		setNullStr(svc, "cloud", cloudProvider)
		services = append(services, svc)
	}

	return mcpJSON(map[string]any{
		"domain":   domain,
		"count":    len(services),
		"services": services,
	})
}

// ---------------------------------------------------------------------------
// meow_export — Export filtered data
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleExport(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	exportType := req.GetString("type", "ip_list")
	limit := intOrDefault(req.GetInt("limit", 0), 1000)

	// Compile MeowQL filter
	var where string
	var args []any
	if query != "" {
		result := meowql.CompileServiceCentric(query)
		if result.Err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
		}
		where = result.Where
		args = result.Args
	} else {
		where = "1=1"
	}

	args = append(args, limit)

	switch exportType {
	case "ip_list":
		rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT DISTINCT s.ip, s.port
			FROM services s INNER JOIN hosts h ON s.ip = h.ip
			WHERE %s ORDER BY s.ip, s.port LIMIT ?`, where), args...)
		if err != nil {
			return nil, fmt.Errorf("export query failed: %w", err)
		}
		defer rows.Close()

		var lines []string
		for rows.Next() {
			var ip string
			var port int
			if rows.Scan(&ip, &port) == nil {
				lines = append(lines, fmt.Sprintf("%s:%d", ip, port))
			}
		}
		return mcp.NewToolResultText(strings.Join(lines, "\n")), nil

	case "services":
		rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT s.ip, s.port, s.service, s.product, s.version
			FROM services s INNER JOIN hosts h ON s.ip = h.ip
			WHERE %s ORDER BY s.ip, s.port LIMIT ?`, where), args...)
		if err != nil {
			return nil, fmt.Errorf("export query failed: %w", err)
		}
		defer rows.Close()

		var services []map[string]any
		for rows.Next() {
			var ip string
			var port int
			var svc, product, version sql.NullString
			if rows.Scan(&ip, &port, &svc, &product, &version) != nil {
				continue
			}
			entry := map[string]any{"ip": ip, "port": port}
			setNullStr(entry, "service", svc)
			setNullStr(entry, "product", product)
			setNullStr(entry, "version", version)
			services = append(services, entry)
		}
		return mcpJSON(services)

	case "hosts":
		// For host export, use host-centric compilation
		var hostWhere string
		var hostArgs []any
		if query != "" {
			result := meowql.Compile(query)
			if result.Err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
			}
			hostWhere = result.Where
			hostArgs = result.Args
		} else {
			hostWhere = "1=1"
		}
		hostArgs = append(hostArgs, limit)

		rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT h.ip, h.country_code, h.city, h.asn, h.as_org,
			       h.cloud_provider, h.cloud_type, h.open_ports_count
			FROM hosts h WHERE %s ORDER BY h.last_scan DESC LIMIT ?`, hostWhere), hostArgs...)
		if err != nil {
			return nil, fmt.Errorf("export query failed: %w", err)
		}
		defer rows.Close()

		var hosts []map[string]any
		for rows.Next() {
			var ip string
			var countryCode, city, asOrg, cloudProvider, cloudType sql.NullString
			var asn, openPorts sql.NullInt64
			if rows.Scan(&ip, &countryCode, &city, &asn, &asOrg, &cloudProvider, &cloudType, &openPorts) != nil {
				continue
			}
			entry := map[string]any{"ip": ip}
			setNullStr(entry, "country", countryCode)
			setNullStr(entry, "city", city)
			setNullInt(entry, "asn", asn)
			setNullStr(entry, "org", asOrg)
			setNullStr(entry, "cloud", cloudProvider)
			setNullStr(entry, "cloud_type", cloudType)
			setNullInt(entry, "open_ports", openPorts)
			hosts = append(hosts, entry)
		}
		return mcpJSON(hosts)

	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown export type: %s", exportType)), nil
	}
}

// ---------------------------------------------------------------------------
// meow_dns — DNS resolution
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleDNS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError("query parameter required"), nil
	}
	query = strings.TrimSpace(query)

	result := map[string]any{"query": query}

	// Reverse lookup if it's an IP
	if ip := net.ParseIP(query); ip != nil {
		names, err := net.LookupAddr(query)
		if err == nil && len(names) > 0 {
			ptrs := make([]string, 0, len(names))
			for _, n := range names {
				ptrs = append(ptrs, strings.TrimSuffix(n, "."))
			}
			result["ptr"] = ptrs
		}

		// Also check if this IP is in our database
		var hostCount int
		h.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM hosts WHERE ip = ?", query).Scan(&hostCount)
		if hostCount > 0 {
			result["in_database"] = true
		}

		return mcpJSON(result)
	}

	// Forward lookup
	ips, err := net.LookupHost(query)
	if err == nil {
		var ipv4, ipv6 []string
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				ipv6 = append(ipv6, ip)
			} else {
				ipv4 = append(ipv4, ip)
			}
		}
		if ipv4 != nil {
			result["a"] = ipv4
		}
		if ipv6 != nil {
			result["aaaa"] = ipv6
		}

		// Check which resolved IPs are in our database
		var knownIPs []string
		for _, ip := range ipv4 {
			var c int
			if h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM hosts WHERE ip = ?", ip).Scan(&c) == nil && c > 0 {
				knownIPs = append(knownIPs, ip)
			}
		}
		if len(knownIPs) > 0 {
			result["in_database"] = knownIPs
		}
	}

	cname, err := net.LookupCNAME(query)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != query {
		result["cname"] = strings.TrimSuffix(cname, ".")
	}

	mxs, err := net.LookupMX(query)
	if err == nil && len(mxs) > 0 {
		mxList := make([]map[string]any, 0, len(mxs))
		for _, mx := range mxs {
			mxList = append(mxList, map[string]any{
				"host": strings.TrimSuffix(mx.Host, "."),
				"pref": mx.Pref,
			})
		}
		result["mx"] = mxList
	}

	nss, err := net.LookupNS(query)
	if err == nil && len(nss) > 0 {
		nsList := make([]string, 0, len(nss))
		for _, ns := range nss {
			nsList = append(nsList, strings.TrimSuffix(ns.Host, "."))
		}
		result["ns"] = nsList
	}

	txts, err := net.LookupTXT(query)
	if err == nil && len(txts) > 0 {
		result["txt"] = txts
	}

	return mcpJSON(result)
}

// ---------------------------------------------------------------------------
// meow_status — System status
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleStatus(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := map[string]any{}

	// Table counts
	var hosts, services, certs int64
	h.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM hosts),
		(SELECT COUNT(*) FROM services),
		(SELECT COUNT(*) FROM certificates)`).Scan(&hosts, &services, &certs)
	stats["hosts"] = hosts
	stats["services"] = services
	stats["certificates"] = certs

	// Enrichment breakdown
	var enriched, pending, failed, skipped int
	h.db.QueryRowContext(ctx, `SELECT
		SUM(CASE WHEN enrichment_status = 'enriched' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status = 'pending' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status = 'failed' THEN 1 ELSE 0 END),
		SUM(CASE WHEN enrichment_status NOT IN ('enriched','pending','failed') OR enrichment_status IS NULL THEN 1 ELSE 0 END)
	FROM services`).Scan(&enriched, &pending, &failed, &skipped)
	stats["enrichment"] = map[string]any{
		"enriched": enriched,
		"pending":  pending,
		"failed":   failed,
		"skipped":  skipped,
	}
	if services > 0 {
		stats["enrichment_rate"] = fmt.Sprintf("%.1f%%", float64(enriched)/float64(services)*100)
	}

	// Domain count
	var domainCount int
	h.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT domain) FROM service_enrichments WHERE domain != '' AND status = 'enriched'",
	).Scan(&domainCount)
	stats["domains"] = domainCount

	// HTTP services count
	var httpCount int
	h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_data").Scan(&httpCount)
	stats["http_services"] = httpCount

	// Top services by enrichment status
	rows, err := h.db.QueryContext(ctx, `
		SELECT service,
			COUNT(*) as total,
			SUM(CASE WHEN enrichment_status = 'enriched' THEN 1 ELSE 0 END) as enriched_count
		FROM services
		WHERE service IS NOT NULL
		GROUP BY service
		ORDER BY total DESC
		LIMIT 10`)
	if err == nil {
		var svcStats []map[string]any
		for rows.Next() {
			var svc string
			var total, enrichedCount int
			if rows.Scan(&svc, &total, &enrichedCount) == nil {
				svcStats = append(svcStats, map[string]any{
					"service":  svc,
					"total":    total,
					"enriched": enrichedCount,
				})
			}
		}
		rows.Close()
		stats["service_breakdown"] = svcStats
	}

	return mcpJSON(stats)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *mcpHandler) queryValueCounts(ctx context.Context, query string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, query)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var value string
		var count int
		if rows.Scan(&value, &count) != nil {
			continue
		}
		results = append(results, map[string]any{"name": value, "count": count})
	}
	return results
}

func mcpJSON(data any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

func setNullStr(m map[string]any, key string, ns sql.NullString) {
	if ns.Valid && ns.String != "" {
		m[key] = ns.String
	}
}

func setNullInt(m map[string]any, key string, ni sql.NullInt64) {
	if ni.Valid {
		m[key] = ni.Int64
	}
}

func intOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
