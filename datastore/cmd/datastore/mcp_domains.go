package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

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

	return mcpEnvelope("meow_domains", domains, len(domains) >= limit)
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

	return mcpEnvelope("meow_domains", services, len(services) >= limit)
}
