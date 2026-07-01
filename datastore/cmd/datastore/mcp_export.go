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

		var lines []map[string]any
		for rows.Next() {
			var ip string
			var port int
			if rows.Scan(&ip, &port) == nil {
				lines = append(lines, map[string]any{"value": fmt.Sprintf("%s:%d", ip, port)})
			}
		}
		return mcpEnvelope("meow_export", lines, len(lines) >= limit)

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
		return mcpEnvelope("meow_export", services, len(services) >= limit)

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
			setNullStr(entry, "country_code", countryCode)
			setNullStr(entry, "city", city)
			setIfValidInt(entry, "asn", asn)
			setNullStr(entry, "as_org", asOrg)
			setNullStr(entry, "cloud_provider", cloudProvider)
			setNullStr(entry, "cloud_type", cloudType)
			setIfValidInt(entry, "open_ports_count", openPorts)
			hosts = append(hosts, entry)
		}
		return mcpEnvelope("meow_export", hosts, len(hosts) >= limit)

	case "domains":
		// Domains are host-centric: compile the query against the hosts table.
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
			SELECT hd.domain,
			       GROUP_CONCAT(DISTINCT hd.ip) AS ips,
			       GROUP_CONCAT(DISTINCT hd.source) AS sources,
			       COUNT(DISTINCT hd.ip) AS ip_count
			FROM host_domains hd INNER JOIN hosts h ON h.ip = hd.ip
			WHERE %s
			GROUP BY hd.domain
			ORDER BY ip_count DESC, hd.domain ASC LIMIT ?`, hostWhere), hostArgs...)
		if err != nil {
			return nil, fmt.Errorf("export query failed: %w", err)
		}
		defer rows.Close()

		var domains []map[string]any
		for rows.Next() {
			var domain string
			var ips, sources sql.NullString
			var ipCount int
			if rows.Scan(&domain, &ips, &sources, &ipCount) != nil {
				continue
			}
			entry := map[string]any{"domain": domain, "ip_count": ipCount}
			if ips.Valid && ips.String != "" {
				entry["ips"] = strings.Split(ips.String, ",")
			}
			setNullStr(entry, "source", sources)
			domains = append(domains, entry)
		}
		return mcpEnvelope("meow_export", domains, len(domains) >= limit)

	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown export type: %s", exportType)), nil
	}
}
