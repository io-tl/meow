package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mcpJSON(data any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

// mcpEnvelope wraps a successful tool result in the unified output envelope:
//
//	{ "tool": <name>, "count": <len(results)>, "truncated": <bool>, "results": [ ... ] }
//
// results is always a JSON array. List-returning tools pass their rows directly
// (truncated = true when the list was clamped to its limit). Object-returning
// tools pass a single-element slice ([obj]) with truncated = false.
func mcpEnvelope(tool string, results []map[string]any, truncated bool) (*mcp.CallToolResult, error) {
	if results == nil {
		results = []map[string]any{}
	}
	return mcpJSON(map[string]any{"tool": tool, "count": len(results), "truncated": truncated, "results": results})
}

// setNullStr sets key in the map if the NullString is valid and non-empty.
// Unlike setIfValid, this also filters out empty strings.
func setNullStr(m map[string]any, key string, ns sql.NullString) {
	if ns.Valid && ns.String != "" {
		m[key] = ns.String
	}
}

// setSanitizedBanner sets the banner field after stripping non-printable characters
// and truncating to a reasonable length. Binary protocol banners (SMB, RPC, etc.)
// become unreadable \u0000 sequences in JSON — this keeps the output clean.
func setSanitizedBanner(m map[string]any, key string, ns sql.NullString) {
	if !ns.Valid || ns.String == "" {
		return
	}
	s := ns.String
	// Strip non-printable characters (keep tab, newline, carriage return)
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f || c == '\t' || c == '\n' || c == '\r' {
			clean = append(clean, c)
		}
	}
	result := strings.TrimSpace(string(clean))
	if result == "" {
		return
	}
	const maxBanner = 256
	if len(result) > maxBanner {
		result = result[:maxBanner] + "..."
	}
	m[key] = result
}

// parseFieldsParam parses a comma-separated fields string into a set.
// Returns nil if the input is empty (meaning "use defaults").
func parseFieldsParam(fields string) map[string]bool {
	if fields == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, f := range strings.Split(fields, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			set[f] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// resolveFields returns the user-provided field set if non-empty, otherwise the defaults.
func resolveFields(userFields string, defaults []string) map[string]bool {
	if userFields != "" {
		return parseFieldsParam(userFields)
	}
	set := make(map[string]bool, len(defaults))
	for _, f := range defaults {
		set[f] = true
	}
	return set
}

// filterRow returns a new map containing only keys present in the allowed set.
// If allowed is nil, returns the original map unchanged.
func filterRow(m map[string]any, allowed map[string]bool) map[string]any {
	if allowed == nil {
		return m
	}
	filtered := make(map[string]any, len(allowed))
	for k, v := range m {
		if allowed[k] {
			filtered[k] = v
		}
	}
	return filtered
}

// hasFieldPrefix checks if any key in the set starts with the given prefix.
func hasFieldPrefix(fields map[string]bool, prefix string) bool {
	for k := range fields {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// setEnrichmentKeys extracts only the key names from the enrichment_data JSON
// and sets them as an "enrichment_keys" array. This lets the model discover
// available fields without paying the token cost of all values.
func setEnrichmentKeys(m map[string]any, ns sql.NullString) {
	if !ns.Valid || ns.String == "" || ns.String == "{}" {
		return
	}
	var ed map[string]any
	if json.Unmarshal([]byte(ns.String), &ed) != nil {
		return
	}
	keys := make([]string, 0, len(ed))
	for k := range ed {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		m["enrichment_keys"] = keys
	}
}

// parseEnrichmentData extracts enrichment_data JSON fields into the service map
// as top-level "enrichment.<key>" entries, so Claude can see exports, shares, etc.
func parseEnrichmentData(m map[string]any, ns sql.NullString) {
	if !ns.Valid || ns.String == "" || ns.String == "{}" {
		return
	}
	var ed map[string]any
	if json.Unmarshal([]byte(ns.String), &ed) != nil {
		return
	}
	for k, v := range ed {
		m["enrichment."+k] = v
	}
}

func intOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// clampLimit enforces a maximum on user-provided limits to prevent resource exhaustion.
func clampLimit(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// escapeLike escapes SQL LIKE wildcards (%, _) in user input to prevent
// unintended pattern matching.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// copyArgs returns a new slice with extra values appended, avoiding mutation
// of the original slice's underlying array.
func copyArgs(src []any, extra ...any) []any {
	dst := make([]any, len(src), len(src)+len(extra))
	copy(dst, src)
	return append(dst, extra...)
}
