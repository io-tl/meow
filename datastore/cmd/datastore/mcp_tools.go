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

	"meow/datastore/pkg/meowql"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
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
	limit := clampLimit(req.GetInt("limit", 0), 50, 500)
	page := intOrDefault(req.GetInt("page", 0), 1)
	offset := (page - 1) * limit

	fields := req.GetString("fields", "")

	if mode == "services" {
		return h.searchServices(ctx, query, limit, offset, fields)
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

	args := copyArgs(result.Args, limit, offset)
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
		setIfValidInt(host, "asn", asn)
		setNullStr(host, "org", asOrg)
		setNullStr(host, "cloud", cloudProvider)
		setIfValidInt(host, "ports", openPorts)
		setIfValidInt(host, "services", svcCount)
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search rows iteration: %w", err)
	}

	return mcpJSON(map[string]any{
		"total": total,
		"page":  page,
		"count": len(hosts),
		"hosts": hosts,
	})
}

func (h *mcpHandler) searchServices(ctx context.Context, query string, limit, offset int, fields string) (*mcp.CallToolResult, error) {
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

	args := copyArgs(result.Args, limit, offset)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       s.enrichment_status, s.enrichment_data,
		       h.country_code, h.cloud_provider, h.as_org,
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

	svcDefaults := []string{"ip", "port", "service", "product", "version", "country", "cloud", "org", "enrichment_keys"}
	fieldSet := resolveFields(fields, svcDefaults)
	wantEnrichment := hasFieldPrefix(fieldSet, "enrichment.")
	wantKeys := fieldSet["enrichment_keys"]

	var services []map[string]any
	for rows.Next() {
		var ip string
		var port int
		var svcName, product, version, banner, enrichStatus sql.NullString
		var enrichData sql.NullString
		var countryCode, cloudProvider, asOrg sql.NullString
		var httpStatus sql.NullInt64
		var httpTitle, httpServer sql.NullString

		if err := rows.Scan(&ip, &port, &svcName, &product, &version, &banner,
			&enrichStatus, &enrichData, &countryCode, &cloudProvider, &asOrg,
			&httpStatus, &httpTitle, &httpServer); err != nil {
			continue
		}

		svc := map[string]any{"ip": ip, "port": port}
		setNullStr(svc, "service", svcName)
		setNullStr(svc, "product", product)
		setNullStr(svc, "version", version)
		setSanitizedBanner(svc, "banner", banner)
		setNullStr(svc, "enrichment", enrichStatus)
		setNullStr(svc, "country", countryCode)
		setNullStr(svc, "cloud", cloudProvider)
		setNullStr(svc, "org", asOrg)
		setIfValidInt(svc, "http_status", httpStatus)
		setNullStr(svc, "http_title", httpTitle)
		setNullStr(svc, "http_server", httpServer)
		if wantEnrichment {
			parseEnrichmentData(svc, enrichData)
		}
		if wantKeys {
			setEnrichmentKeys(svc, enrichData)
		}
		services = append(services, filterRow(svc, fieldSet))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("services rows iteration: %w", err)
	}

	return mcpJSON(map[string]any{
		"total":    total,
		"count":    len(services),
		"services": services,
	})
}

// ---------------------------------------------------------------------------
// meow_count — Lightweight count query
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleCount(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	if query == "" {
		return mcp.NewToolResultError("query parameter required"), nil
	}
	mode := req.GetString("mode", "hosts")

	var total int
	if mode == "services" {
		result := meowql.CompileServiceCentric(query)
		if result.Err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
		}
		if err := h.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT COUNT(*) FROM services s
			INNER JOIN hosts h ON s.ip = h.ip
			WHERE %s AND s.enrichment_status != 'pending'`, result.Where),
			result.Args...,
		).Scan(&total); err != nil {
			return nil, fmt.Errorf("count query failed: %w", err)
		}
	} else {
		result := meowql.Compile(query)
		if result.Err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v\nAvailable fields: %s",
				result.Err, strings.Join(meowql.FieldNames(), ", "))), nil
		}
		if err := h.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where),
			result.Args...,
		).Scan(&total); err != nil {
			return nil, fmt.Errorf("count query failed: %w", err)
		}
	}

	return mcpJSON(map[string]any{"total": total})
}

// ---------------------------------------------------------------------------
// meow_host — Detailed host information
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleHost(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ip, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError("ip parameter required"), nil
	}
	if net.ParseIP(ip) == nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", ip)), nil
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
	setIfValidInt(host, "asn", asn)
	setNullStr(host, "as_org", asOrg)
	setNullStr(host, "cloud_provider", cloudProvider)
	setNullStr(host, "cloud_region", cloudRegion)
	setIfValidInt(host, "first_seen", firstSeen)
	setIfValidInt(host, "last_scan", lastScan)
	setIfValidInt(host, "open_ports_count", openPorts)
	setIfValidInt(host, "services_count", svcCount)

	// Sections filtering
	sections := parseFieldsParam(req.GetString("sections", ""))
	fields := req.GetString("fields", "")

	if sections == nil || sections["services"] {
		host["services"] = h.queryServices(ctx, ip, fields)
	}
	if sections == nil || sections["certificates"] {
		host["certificates"] = h.queryCertificates(ctx, ip, fields)
	}
	if sections == nil || sections["domains"] {
		host["domains"] = h.queryDomains(ctx, ip)
	}

	return mcpJSON(host)
}

func (h *mcpHandler) queryServices(ctx context.Context, ip string, fields string) []map[string]any {
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

	svcDefaults := []string{
		"port", "service", "product", "version",
		"enrichment.anonymous_login", "enrichment.auth_required", "enrichment.signing_required",
		"enrichment.default_credentials", "enrichment.tls", "enrichment.protocol", "enrichment.version",
	}
	fieldSet := resolveFields(fields, svcDefaults)
	wantEnrichment := hasFieldPrefix(fieldSet, "enrichment.")

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
		setSanitizedBanner(svc, "banner", banner)
		setNullStr(svc, "enrichment", enrichStatus)
		setIfValidInt(svc, "http_status", httpStatus)
		setNullStr(svc, "http_title", httpTitle)
		setNullStr(svc, "http_server", httpServer)
		setNullStr(svc, "cms", httpCMS)
		setNullStr(svc, "framework", httpFramework)

		// Parse enrichment_data JSON for key fields
		if wantEnrichment && enrichData.Valid && enrichData.String != "" && enrichData.String != "{}" {
			var ed map[string]any
			if json.Unmarshal([]byte(enrichData.String), &ed) == nil {
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

		services = append(services, filterRow(svc, fieldSet))
	}
	// rows.Err() intentionally not returned — sub-query helper, partial results acceptable
	return services
}

func (h *mcpHandler) queryCertificates(ctx context.Context, ip string, fields string) []map[string]any {
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

	certDefaults := []string{"port", "fingerprint", "subject_cn", "issuer_cn", "self_signed", "expired"}
	fieldSet := resolveFields(fields, certDefaults)

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
		setIfValidInt(cert, "bits", bits)
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
		certs = append(certs, filterRow(cert, fieldSet))
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
		setIfValidInt(d, "port", port)
		domains = append(domains, d)
	}
	return domains
}

// ---------------------------------------------------------------------------
// meow_stats — Overview statistics
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleStats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := map[string]any{}

	// Section filtering: only run queries for requested sections
	statsDefaults := []string{"total_hosts", "total_services", "total_certificates", "enrichment", "top_services", "top_countries"}
	fieldSet := resolveFields(req.GetString("fields", ""), statsDefaults)

	// Total counts (always cheap, run if any total_* requested)
	if fieldSet["total_hosts"] || fieldSet["total_services"] || fieldSet["total_certificates"] {
		totalHosts, totalServices, totalCerts, _ := h.db.getTableCounts()
		if fieldSet["total_hosts"] {
			stats["total_hosts"] = totalHosts
		}
		if fieldSet["total_services"] {
			stats["total_services"] = totalServices
		}
		if fieldSet["total_certificates"] {
			stats["total_certificates"] = totalCerts
		}
	}

	// Enrichment status
	if fieldSet["enrichment"] {
		enriched, pending, failed, skipped, _ := h.db.getEnrichmentStatusCounts()
		stats["enrichment"] = map[string]int{
			"enriched": enriched, "pending": pending, "failed": failed, "skipped": skipped,
		}
	}

	// Top services
	if fieldSet["top_services"] {
		stats["top_services"] = h.queryValueCounts(ctx, `
			SELECT service, COUNT(*) FROM services
			WHERE service IS NOT NULL GROUP BY service ORDER BY COUNT(*) DESC LIMIT 15`)
	}

	// Top countries
	if fieldSet["top_countries"] {
		stats["top_countries"] = h.queryValueCounts(ctx, `
			SELECT country_code, COUNT(*) FROM hosts
			WHERE country_code IS NOT NULL GROUP BY country_code ORDER BY COUNT(*) DESC LIMIT 10`)
	}

	// Cloud providers (not in defaults — request with fields=cloud_providers)
	if fieldSet["cloud_providers"] {
		stats["cloud_providers"] = h.queryValueCounts(ctx, `
			SELECT cloud_provider, COUNT(*) FROM hosts
			WHERE cloud_provider IS NOT NULL GROUP BY cloud_provider ORDER BY COUNT(*) DESC`)
	}

	// Top products (not in defaults — request with fields=top_products)
	if fieldSet["top_products"] {
		stats["top_products"] = h.queryValueCounts(ctx, `
			SELECT product, COUNT(*) FROM services
			WHERE product IS NOT NULL AND product != '' GROUP BY product ORDER BY COUNT(*) DESC LIMIT 15`)
	}

	// Top technologies (not in defaults — request with fields=top_technologies)
	if fieldSet["top_technologies"] {
		stats["top_technologies"] = h.queryValueCounts(ctx, `
			SELECT json_extract(value, '$.name'), COUNT(*) FROM http_data, json_each(technologies)
			WHERE technologies IS NOT NULL AND technologies != ''
			GROUP BY json_extract(value, '$.name') ORDER BY COUNT(*) DESC LIMIT 10`)
	}

	return mcpJSON(stats)
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
	limit := clampLimit(req.GetInt("limit", 0), 100, 1000)
	fields := req.GetString("fields", "")

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

	pivotDefaults := []string{"ip", "port", "service", "product", "country_code"}
	fieldSet := resolveFields(fields, pivotDefaults)

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
		results = append(results, filterRow(row, fieldSet))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pivot rows iteration: %w", err)
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
	limit := clampLimit(req.GetInt("limit", 0), 50, 500)
	fields := req.GetString("fields", "")

	whereClause := "WHERE 1=1"
	var args []any

	if query != "" {
		queryLower := "%" + escapeLike(strings.ToLower(query)) + "%"
		whereClause += ` AND (
			LOWER(c.subject_cn) LIKE ? ESCAPE '\' OR LOWER(c.issuer_cn) LIKE ? ESCAPE '\' OR
			LOWER(c.names) LIKE ? ESCAPE '\' OR c.fingerprint_sha256 LIKE ? ESCAPE '\' OR
			LOWER(c.subject_org) LIKE ? ESCAPE '\' OR LOWER(c.issuer_org) LIKE ? ESCAPE '\' OR
			c.serial_number LIKE ? ESCAPE '\')`
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

	certDefaults := []string{"fingerprint", "subject_cn", "issuer_cn", "status", "self_signed", "host_count", "not_after"}
	fieldSet := resolveFields(fields, certDefaults)

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
		setIfValidInt(cert, "bits", bits)
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

		certs = append(certs, filterRow(cert, fieldSet))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("certs rows iteration: %w", err)
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
	limit := clampLimit(req.GetInt("limit", 0), 50, 500)
	fields := req.GetString("fields", "")

	// If a specific domain is given, return its full service breakdown
	if domain != "" {
		return h.domainServices(ctx, domain, limit, fields)
	}

	// Otherwise, list domains with stats
	query := req.GetString("query", "")
	protocol := req.GetString("protocol", "")

	whereClause := "WHERE se.domain != '' AND se.status = 'enriched'"
	var args []any

	if query != "" {
		whereClause += " AND LOWER(se.domain) LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLike(strings.ToLower(query))+"%")
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

	domDefaults := []string{"domain", "services_count", "protocols"}
	fieldSet := resolveFields(fields, domDefaults)

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
		setIfValidInt(entry, "sample_status_code", sampleStatus)
		setIfValidInt(entry, "last_seen", lastSeen)
		domains = append(domains, filterRow(entry, fieldSet))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domains rows iteration: %w", err)
	}

	return mcpJSON(map[string]any{
		"total":   totalDomains,
		"count":   len(domains),
		"domains": domains,
	})
}

func (h *mcpHandler) domainServices(ctx context.Context, domain string, limit int, fields string) (*mcp.CallToolResult, error) {
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

	detailDefaults := []string{"ip", "port", "protocol", "status_code", "title", "country"}
	fieldSet := resolveFields(fields, detailDefaults)

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
		setSanitizedBanner(svc, "banner", banner)
		setIfValidInt(svc, "status_code", statusCode)
		setNullStr(svc, "title", title)
		setNullStr(svc, "server", server)
		setNullStr(svc, "redirect_url", redirectURL)
		setIfValidInt(svc, "content_length", contentLength)
		setNullStr(svc, "country", countryCode)
		setNullStr(svc, "org", asOrg)
		setNullStr(svc, "cloud", cloudProvider)
		services = append(services, filterRow(svc, fieldSet))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domain services rows iteration: %w", err)
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
	limit := clampLimit(req.GetInt("limit", 0), 1000, 10000)

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
			setIfValidInt(entry, "asn", asn)
			setNullStr(entry, "org", asOrg)
			setNullStr(entry, "cloud", cloudProvider)
			setNullStr(entry, "cloud_type", cloudType)
			setIfValidInt(entry, "open_ports", openPorts)
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

	result := resolveDNS(query)

	// Enrich with database cross-reference
	if ip := net.ParseIP(query); ip != nil {
		// Reverse lookup: check if this IP is in our database
		var hostCount int
		h.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM hosts WHERE ip = ?", query).Scan(&hostCount)
		if hostCount > 0 {
			result["in_database"] = true
		}
	} else if ipv4, ok := result["a"].([]string); ok {
		// Forward lookup: check which resolved IPs are in our database
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
// meow_scan — Submit a scan request via NATS
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target parameter required"), nil
	}

	if h.scanTracker == nil || !h.scanTracker.HasActiveScanners() {
		return mcp.NewToolResultError("no active scanners available — ensure at least one synscan instance is running in daemon mode"), nil
	}

	scanReq := ScanRequest{
		RequestID: uuid.New().String(),
		Target:    target,
		Ports:     req.GetString("ports", ""),
		RateLimit: req.GetInt("rate", 0),
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(scanReq)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}

	if err := h.nc.Publish(TopicScanRequest, data); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to publish scan request: %v", err)), nil
	}

	return mcpJSON(map[string]any{
		"request_id": scanReq.RequestID,
		"message":    "scan request submitted",
		"target":     target,
		"ports":      scanReq.Ports,
	})
}

// ---------------------------------------------------------------------------
// meow_scanners — List active scanner instances
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleScanners(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if h.scanTracker == nil {
		return mcpJSON(map[string]any{"count": 0, "scanners": []any{}})
	}

	scanners := h.scanTracker.GetActiveScanners()
	result := make([]map[string]any, 0, len(scanners))
	for _, s := range scanners {
		node := map[string]any{
			"node_id":  s.NodeID,
			"hostname": s.Hostname,
			"status":   s.Status,
		}
		if s.ScanID != "" {
			node["scan_id"] = s.ScanID
		}
		if s.Transport != "" {
			node["transport"] = s.Transport
		}
		if s.PacketsTotal > 0 {
			node["packets_sent"] = s.PacketsSent
			node["packets_total"] = s.PacketsTotal
		}
		result = append(result, node)
	}
	return mcpJSON(map[string]any{
		"count":    len(result),
		"scanners": result,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *mcpHandler) queryValueCounts(ctx context.Context, query string) []map[string]any {
	return h.db.queryNameCountRows(ctx, query, "name")
}

func mcpJSON(data any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

// setNullStr sets key in the map if the NullString is valid and non-empty.
// Unlike setIfValid, this also filters out empty strings.
func setNullStr(m map[string]any, key string, ns sql.NullString) {
	if ns.Valid && ns.String != "" {
		m[key] = ns.String
	}
}

// setSanitizedBanner sets the banner field after stripping non-printable characters
// and truncating to a reasonable length. Binary protocol banners (SMB, RPC, etc.)
// become unreadable \u0000 sequences in JSON — this keeps the output clean.
func setSanitizedBanner(m map[string]any, key string, ns sql.NullString) {
	if !ns.Valid || ns.String == "" {
		return
	}
	s := ns.String
	// Strip non-printable characters (keep tab, newline, carriage return)
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f || c == '\t' || c == '\n' || c == '\r' {
			clean = append(clean, c)
		}
	}
	result := strings.TrimSpace(string(clean))
	if result == "" {
		return
	}
	const maxBanner = 256
	if len(result) > maxBanner {
		result = result[:maxBanner] + "..."
	}
	m[key] = result
}

// parseFieldsParam parses a comma-separated fields string into a set.
// Returns nil if the input is empty (meaning "use defaults").
func parseFieldsParam(fields string) map[string]bool {
	if fields == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, f := range strings.Split(fields, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			set[f] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// resolveFields returns the user-provided field set if non-empty, otherwise the defaults.
func resolveFields(userFields string, defaults []string) map[string]bool {
	if userFields != "" {
		return parseFieldsParam(userFields)
	}
	set := make(map[string]bool, len(defaults))
	for _, f := range defaults {
		set[f] = true
	}
	return set
}

// filterRow returns a new map containing only keys present in the allowed set.
// If allowed is nil, returns the original map unchanged.
func filterRow(m map[string]any, allowed map[string]bool) map[string]any {
	if allowed == nil {
		return m
	}
	filtered := make(map[string]any, len(allowed))
	for k, v := range m {
		if allowed[k] {
			filtered[k] = v
		}
	}
	return filtered
}

// hasFieldPrefix checks if any key in the set starts with the given prefix.
func hasFieldPrefix(fields map[string]bool, prefix string) bool {
	for k := range fields {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// setEnrichmentKeys extracts only the key names from the enrichment_data JSON
// and sets them as an "enrichment_keys" array. This lets the model discover
// available fields without paying the token cost of all values.
func setEnrichmentKeys(m map[string]any, ns sql.NullString) {
	if !ns.Valid || ns.String == "" || ns.String == "{}" {
		return
	}
	var ed map[string]any
	if json.Unmarshal([]byte(ns.String), &ed) != nil {
		return
	}
	keys := make([]string, 0, len(ed))
	for k := range ed {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		m["enrichment_keys"] = keys
	}
}

// parseEnrichmentData extracts enrichment_data JSON fields into the service map
// as top-level "enrichment.<key>" entries, so Claude can see exports, shares, etc.
func parseEnrichmentData(m map[string]any, ns sql.NullString) {
	if !ns.Valid || ns.String == "" || ns.String == "{}" {
		return
	}
	var ed map[string]any
	if json.Unmarshal([]byte(ns.String), &ed) != nil {
		return
	}
	for k, v := range ed {
		m["enrichment."+k] = v
	}
}

func intOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// clampLimit enforces a maximum on user-provided limits to prevent resource exhaustion.
func clampLimit(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// escapeLike escapes SQL LIKE wildcards (%, _) in user input to prevent
// unintended pattern matching.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// copyArgs returns a new slice with extra values appended, avoiding mutation
// of the original slice's underlying array.
func copyArgs(src []any, extra ...any) []any {
	dst := make([]any, len(src), len(src)+len(extra))
	copy(dst, src)
	return append(dst, extra...)
}
