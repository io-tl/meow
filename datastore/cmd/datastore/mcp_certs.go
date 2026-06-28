package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

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

	return mcpEnvelope("meow_certs", certs, len(certs) >= limit)
}
