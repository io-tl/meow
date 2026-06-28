package main

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"meow/datastore/pkg/meowql"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// meow_count — Lightweight count-only query
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleCount(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError("query parameter required"), nil
	}
	return h.countQuery(ctx, query, req.GetString("mode", "hosts"))
}

func (h *mcpHandler) countQuery(ctx context.Context, query, mode string) (*mcp.CallToolResult, error) {
	var total int
	if mode == "services" {
		expr, _ := meowql.Parse(query)
		matchedFields := meowql.ExtractFields(expr)
		result := meowql.CompileServiceCentric(query)
		if result.Err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
		}
		statusFilter := serviceSearchStatusFilter(matchedFields)
		if err := h.db.QueryRowContextLogged(ctx, fmt.Sprintf(`
			SELECT COUNT(*) FROM services s
			INNER JOIN hosts h ON s.ip = h.ip
			WHERE %s AND %s`, result.Where, statusFilter),
			result.Args...,
		).Scan(&total); err != nil {
			return nil, fmt.Errorf("count query failed: %w", err)
		}
	} else {
		result := meowql.Compile(query)
		if result.Err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("MeowQL error: %v", result.Err)), nil
		}
		if err := h.db.QueryRowContextLogged(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where),
			result.Args...,
		).Scan(&total); err != nil {
			return nil, fmt.Errorf("count query failed: %w", err)
		}
	}
	return mcpEnvelope("meow_count", []map[string]any{{"total": total}}, false)
}

// ---------------------------------------------------------------------------
// meow_schema — Enrichment schema discovery
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleSchema(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	search := req.GetString("search", "")

	// "protocol" is the preferred param; "service" is kept for backward compat.
	// Both are family-aware here: the value is resolved to its canonical family
	// and the schema spans every member of that family.
	target := req.GetString("protocol", "")
	if target == "" {
		target = req.GetString("service", "")
	}

	// No target (or the legacy "*" wildcard) → list the protocol families present.
	if target == "" || target == "*" {
		return h.enrichmentFamilies(ctx, search)
	}

	canonical := meowql.FamilyOf(target)
	members := meowql.ProtocolFamily(canonical)
	return h.enrichmentSchemaFamily(ctx, members, search)
}

// enrichmentSchemaFamily returns the union of enrichment JSON keys (key, type,
// count, sample) seen across every member service of a protocol family,
// optionally filtered by a substring search on key names. This is "all the
// enrichment fields possible for <protocol>".
func (h *mcpHandler) enrichmentSchemaFamily(ctx context.Context, members []string, search string) (*mcp.CallToolResult, error) {
	placeholders := make([]string, len(members))
	args := make([]any, 0, len(members)+1)
	for i, m := range members {
		placeholders[i] = "?"
		args = append(args, m)
	}

	q := `SELECT je.key,
	             COUNT(*) as cnt,
	             typeof(je.value) as typ,
	             CASE typeof(je.value)
	               WHEN 'text'    THEN substr(je.value, 1, 60)
	               WHEN 'integer' THEN CAST(je.value AS TEXT)
	               WHEN 'real'    THEN CAST(je.value AS TEXT)
	               WHEN 'null'    THEN 'null'
	               ELSE typeof(je.value)
	             END as sample
	      FROM services s, json_each(s.enrichment_data) je
	      WHERE s.service IN (` + strings.Join(placeholders, ", ") + `) AND s.enrichment_status = 'enriched'
	            AND s.enrichment_data IS NOT NULL AND s.enrichment_data != '{}'`

	if search != "" {
		q += " AND LOWER(je.key) LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	q += " GROUP BY je.key ORDER BY cnt DESC"

	rows, err := h.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("enrichment schema query failed: %w", err)
	}
	defer rows.Close()

	var keys []map[string]any
	for rows.Next() {
		var key, typ, sample string
		var cnt int
		if rows.Scan(&key, &cnt, &typ, &sample) != nil {
			continue
		}
		entry := map[string]any{
			"key":    key,
			"count":  cnt,
			"type":   typ,
			"sample": sample,
		}
		keys = append(keys, entry)
	}

	return mcpEnvelope("meow_schema", keys, false)
}

// enrichmentFamilies lists the protocol families present in the database: for
// each canonical protocol it reports the member service names actually seen and
// the total enriched service count. Service names are grouped into families via
// meowql.FamilyOf (unknown services form their own single-member family).
func (h *mcpHandler) enrichmentFamilies(ctx context.Context, search string) (*mcp.CallToolResult, error) {
	q := `SELECT s.service, COUNT(DISTINCT s.ip || ':' || CAST(s.port AS TEXT)) as cnt
	      FROM services s, json_each(s.enrichment_data) je
	      WHERE s.enrichment_status = 'enriched'
	            AND s.enrichment_data IS NOT NULL AND s.enrichment_data != '{}'`
	var args []any

	if search != "" {
		q += " AND LOWER(je.key) LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	q += " GROUP BY s.service"

	rows, err := h.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("enrichment families query failed: %w", err)
	}
	defer rows.Close()

	type familyAgg struct {
		members []string
		seen    map[string]bool
		count   int
	}
	agg := map[string]*familyAgg{}
	for rows.Next() {
		var svc sql.NullString
		var cnt int
		if rows.Scan(&svc, &cnt) != nil {
			continue
		}
		if !svc.Valid || svc.String == "" {
			continue
		}
		canonical := meowql.FamilyOf(svc.String)
		f := agg[canonical]
		if f == nil {
			f = &familyAgg{seen: map[string]bool{}}
			agg[canonical] = f
		}
		if !f.seen[svc.String] {
			f.seen[svc.String] = true
			f.members = append(f.members, svc.String)
		}
		f.count += cnt
	}

	families := make([]map[string]any, 0, len(agg))
	for canonical, f := range agg {
		sort.Strings(f.members)
		families = append(families, map[string]any{
			"protocol": canonical,
			"members":  f.members,
			"count":    f.count,
		})
	}
	// Most-populated families first, with a stable canonical tie-break.
	sort.Slice(families, func(i, j int) bool {
		ci, cj := families[i]["count"].(int), families[j]["count"].(int)
		if ci != cj {
			return ci > cj
		}
		return families[i]["protocol"].(string) < families[j]["protocol"].(string)
	})

	return mcpEnvelope("meow_schema", families, false)
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

	return mcpEnvelope("meow_stats", []map[string]any{stats}, false)
}
