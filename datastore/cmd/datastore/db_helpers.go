package main

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// setIfValid sets key in the map if the NullString is valid.
func setIfValid(m map[string]any, key string, ns sql.NullString) {
	if ns.Valid {
		m[key] = ns.String
	}
}

// setIfValidInt sets key in the map if the NullInt64 is valid.
func setIfValidInt(m map[string]any, key string, ni sql.NullInt64) {
	if ni.Valid {
		m[key] = ni.Int64
	}
}

// queryNameCountRows executes a query returning (string, int) rows and returns
// a slice of {valueKey: value, "count": count} maps. Shared by REST and MCP handlers.
func (db *DB) queryNameCountRows(ctx context.Context, query string, valueKey string) []map[string]any {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		log.Warn().Err(err).Str("query_key", valueKey).Msg("Failed to query value counts")
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
		results = append(results, map[string]any{valueKey: value, "count": count})
	}
	return results
}

// getTableCounts returns total counts for hosts, services, and certificates in a single query.
func (db *DB) getTableCounts() (hosts, services, certs int64, err error) {
	err = db.QueryRowLogged(`
		SELECT
			(SELECT COUNT(*) FROM hosts),
			(SELECT COUNT(*) FROM services),
			(SELECT COUNT(*) FROM certificates)
	`).Scan(&hosts, &services, &certs)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get table counts")
	}
	return
}

// getEnrichmentStatusCounts returns enrichment status counts from the services table.
// Uses scalar COUNT subqueries so the result always has one row, even when
// services is empty.
func (db *DB) getEnrichmentStatusCounts() (enriched, pending, failed, skipped int, err error) {
	err = db.QueryRowLogged(`
		SELECT
			(SELECT COUNT(*) FROM services WHERE enrichment_status = 'enriched'),
			(SELECT COUNT(*) FROM services WHERE enrichment_status = 'pending'),
			(SELECT COUNT(*) FROM services WHERE enrichment_status = 'failed'),
			(SELECT COUNT(*) FROM services WHERE enrichment_status = 'skipped')
	`).Scan(&enriched, &pending, &failed, &skipped)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get enrichment status counts")
	}
	return
}

// resolveDNS performs forward or reverse DNS lookups and returns the results as a map.
// For IPs: returns PTR records. For domains: returns A, AAAA, CNAME, MX, NS, TXT records.
func resolveDNS(query string) map[string]any {
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
		return result
	}

	// Forward lookup: A/AAAA
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
	}

	// CNAME
	cname, err := net.LookupCNAME(query)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != query {
		result["cname"] = strings.TrimSuffix(cname, ".")
	}

	// MX
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

	// NS
	nss, err := net.LookupNS(query)
	if err == nil && len(nss) > 0 {
		nsList := make([]string, 0, len(nss))
		for _, ns := range nss {
			nsList = append(nsList, strings.TrimSuffix(ns.Host, "."))
		}
		result["ns"] = nsList
	}

	// TXT
	txts, err := net.LookupTXT(query)
	if err == nil && len(txts) > 0 {
		result["txt"] = txts
	}

	return result
}

// parsePagination parses limit and page query parameters with validation.
// The requested limit is honored as-is (no hard cap); only invalid or
// non-positive values fall back to defaultLimit. A caller that wants 10_000_000
// rows gets them.
func parsePagination(c *gin.Context, defaultLimit int) (limit, offset, page int) {
	limitStr := c.DefaultQuery("limit", strconv.Itoa(defaultLimit))
	pageStr := c.DefaultQuery("page", "1")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	page, err = strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		page = 1
	}
	offset = (page - 1) * limit
	return
}
