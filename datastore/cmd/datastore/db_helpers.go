package main

import (
	"database/sql"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// setIfValid sets key in gin.H if the NullString is valid
func setIfValid(m gin.H, key string, ns sql.NullString) {
	if ns.Valid {
		m[key] = ns.String
	}
}

// setIfValidInt sets key in gin.H if the NullInt64 is valid
func setIfValidInt(m gin.H, key string, ni sql.NullInt64) {
	if ni.Valid {
		m[key] = ni.Int64
	}
}

// getTableCounts returns total counts for hosts, services, and certificates in a single query.
func (db *DB) getTableCounts() (hosts, services, certs int64, err error) {
	err = db.QueryRow(`
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
// Uses SUM(CASE) to return all counts in a single row instead of GROUP BY.
func (db *DB) getEnrichmentStatusCounts() (enriched, pending, failed, skipped int, err error) {
	err = db.QueryRow(`
		SELECT
			SUM(CASE WHEN enrichment_status = 'enriched' THEN 1 ELSE 0 END),
			SUM(CASE WHEN enrichment_status = 'pending' THEN 1 ELSE 0 END),
			SUM(CASE WHEN enrichment_status = 'failed' THEN 1 ELSE 0 END),
			SUM(CASE WHEN enrichment_status NOT IN ('enriched','pending','failed') OR enrichment_status IS NULL THEN 1 ELSE 0 END)
		FROM services
	`).Scan(&enriched, &pending, &failed, &skipped)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get enrichment status counts")
	}
	return
}

// parsePagination parses limit and page query parameters with validation
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

