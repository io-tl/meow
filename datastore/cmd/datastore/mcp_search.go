package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"meow/datastore/pkg/meowql"

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
	return h.searchHosts(ctx, query, limit, offset)
}

func (h *mcpHandler) searchHosts(ctx context.Context, query string, limit, offset int) (*mcp.CallToolResult, error) {
	result := meowql.Compile(query)
	if result.Err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v\nAvailable fields: %s",
			result.Err, strings.Join(meowql.FieldNames(), ", "))), nil
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

	return mcpEnvelope("meow_search", hosts, len(hosts) >= limit)
}

func (h *mcpHandler) searchServices(ctx context.Context, query string, limit, offset int, fields string) (*mcp.CallToolResult, error) {
	expr, _ := meowql.Parse(query)
	matchedFields := meowql.ExtractFields(expr)
	result := meowql.CompileServiceCentric(query)
	if result.Err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
	}
	statusFilter := serviceSearchStatusFilter(matchedFields)

	args := copyArgs(result.Args, limit, offset)
	rows, err := h.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       s.enrichment_status, s.enrichment_data,
		       h.country_code, h.cloud_provider, h.as_org,
		       hd.status_code, hd.title, hd.server
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		LEFT JOIN http_data hd ON hd.ip = s.ip AND hd.port = s.port
		WHERE %s AND %s
		ORDER BY s.detected_at DESC LIMIT ? OFFSET ?`, result.Where, statusFilter), args...)
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

	return mcpEnvelope("meow_search", services, len(services) >= limit)
}
