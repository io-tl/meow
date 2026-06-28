package main

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// meow_status — System status
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleStatus(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := map[string]any{}

	// Table counts
	var hosts, services, certs int64
	h.db.QueryRowContextLogged(ctx, `SELECT
		(SELECT COUNT(*) FROM hosts),
		(SELECT COUNT(*) FROM services),
		(SELECT COUNT(*) FROM certificates)`).Scan(&hosts, &services, &certs)
	stats["hosts"] = hosts
	stats["services"] = services
	stats["certificates"] = certs

	// Enrichment breakdown
	var enriched, pending, failed, skipped int
	h.db.QueryRowContextLogged(ctx, `SELECT
		(SELECT COUNT(*) FROM services WHERE enrichment_status = 'enriched'),
		(SELECT COUNT(*) FROM services WHERE enrichment_status = 'pending'),
		(SELECT COUNT(*) FROM services WHERE enrichment_status = 'failed'),
		(SELECT COUNT(*) FROM services WHERE enrichment_status = 'skipped')
	FROM services
	LIMIT 1`).Scan(&enriched, &pending, &failed, &skipped)
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
	h.db.QueryRowContextLogged(ctx,
		"SELECT COUNT(DISTINCT domain) FROM service_enrichments WHERE domain != '' AND status = 'enriched'",
	).Scan(&domainCount)
	stats["domains"] = domainCount

	// HTTP services count
	var httpCount int
	h.db.QueryRowContextLogged(ctx, "SELECT COUNT(*) FROM http_data").Scan(&httpCount)
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

	// Active scanners (merged from former meow_scanners tool)
	if h.scanTracker != nil {
		scanners := h.scanTracker.GetActiveScanners()
		scannerList := make([]map[string]any, 0, len(scanners))
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
			scannerList = append(scannerList, node)
		}
		stats["scanners"] = map[string]any{
			"count": len(scannerList),
			"nodes": scannerList,
		}
	}

	return mcpEnvelope("meow_status", []map[string]any{stats}, false)
}
