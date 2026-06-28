package main

import (
	"context"
	"net"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

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
		var hostCount int
		h.db.QueryRowContextLogged(ctx,
			"SELECT COUNT(*) FROM hosts WHERE ip = ?", query).Scan(&hostCount)
		if hostCount > 0 {
			result["in_database"] = true
		}
	} else if ipv4, ok := result["a"].([]string); ok && len(ipv4) > 0 {
		placeholders := make([]string, len(ipv4))
		args := make([]any, len(ipv4))
		for i, ip := range ipv4 {
			placeholders[i] = "?"
			args[i] = ip
		}
		rows, err := h.db.QueryContext(ctx,
			"SELECT ip FROM hosts WHERE ip IN ("+strings.Join(placeholders, ",")+")", args...)
		if err == nil {
			var knownIPs []string
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					knownIPs = append(knownIPs, ip)
				}
			}
			rows.Close()
			if len(knownIPs) > 0 {
				result["in_database"] = knownIPs
			}
		}
	}

	return mcpEnvelope("meow_dns", []map[string]any{result}, false)
}
