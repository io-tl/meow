package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

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

	return mcpEnvelope("meow_pivot", results, len(results) >= limit)
}

func (h *mcpHandler) queryValueCounts(ctx context.Context, query string) []map[string]any {
	return h.db.queryNameCountRows(ctx, query, "name")
}
