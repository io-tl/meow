package meowql

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// QueryResult holds the compiled SQL output from a MeowQL query.
type QueryResult struct {
	// Where is the SQL WHERE clause (without the "WHERE" keyword).
	// Empty string if no conditions (matches all).
	Where string

	// Args contains the parameterized values for the WHERE clause.
	Args []any

	// Err contains any compilation error.
	Err error
}

// Compile parses and compiles a MeowQL query string into a SQL WHERE clause.
// The result is designed for host-centric queries:
//
//	SELECT h.* FROM hosts h WHERE <result.Where> ORDER BY ...
//
// Related table conditions use EXISTS subqueries to avoid row duplication.
func Compile(input string) QueryResult {
	expr, err := Parse(input)
	if err != nil {
		return QueryResult{Err: err}
	}
	if expr == nil {
		return QueryResult{Where: "1=1"}
	}

	c := &compiler{}
	where := c.compileExpr(expr)
	if c.err != nil {
		return QueryResult{Err: c.err}
	}

	return QueryResult{
		Where: where,
		Args:  c.args,
	}
}

// CompileServiceCentric parses and compiles a MeowQL query for service-centric queries:
//
//	SELECT s.* FROM services s INNER JOIN hosts h ON s.ip = h.ip WHERE <result.Where> ORDER BY ...
//
// Service-table conditions apply directly on the services table (aliased as "s")
// instead of being wrapped in EXISTS subqueries. Other table conditions use
// EXISTS subqueries joined via s.ip/s.port.
func CompileServiceCentric(input string) QueryResult {
	expr, err := Parse(input)
	if err != nil {
		return QueryResult{Err: err}
	}
	if expr == nil {
		return QueryResult{Where: "1=1"}
	}

	c := &compiler{serviceCentric: true}
	where := c.compileExpr(expr)
	if c.err != nil {
		return QueryResult{Err: c.err}
	}

	return QueryResult{
		Where: where,
		Args:  c.args,
	}
}

type compiler struct {
	args           []any
	err            error
	serviceCentric bool
}

func (c *compiler) addArg(v any) string {
	c.args = append(c.args, v)
	return "?"
}

func (c *compiler) compileExpr(expr Expression) string {
	if c.err != nil {
		return ""
	}

	switch e := expr.(type) {
	case *AndExpr:
		left := c.compileExpr(e.Left)
		right := c.compileExpr(e.Right)
		return "(" + left + " AND " + right + ")"

	case *OrExpr:
		left := c.compileExpr(e.Left)
		right := c.compileExpr(e.Right)
		return "(" + left + " OR " + right + ")"

	case *NotExpr:
		inner := c.compileExpr(e.Expr)
		return "NOT (" + inner + ")"

	case *Condition:
		return c.compileCondition(e)

	default:
		c.err = fmt.Errorf("unknown expression type: %T", expr)
		return ""
	}
}

func (c *compiler) compileCondition(cond *Condition) string {
	field, ok := LookupField(cond.Field)
	if !ok {
		c.err = fmt.Errorf("unknown field %q", cond.Field)
		return ""
	}

	// Set expression: field:{val1, val2, ...}
	if len(cond.Values) > 0 {
		return c.compileSetCondition(cond, field)
	}

	// Exists check: field:*
	if cond.Value == "*" && cond.Operator == TokenColon {
		return c.compileExistsCheck(cond, field)
	}

	// Build the column comparison SQL
	colSQL := c.compileComparison(cond, field)
	if c.err != nil {
		return ""
	}

	// Wrap in EXISTS subquery if the field is not on the hosts table
	return c.wrapWithTable(field, colSQL)
}

// compileComparison generates the column comparison expression.
func (c *compiler) compileComparison(cond *Condition, field FieldInfo) string {
	col := c.columnRef(field)

	// JSON fields get special handling via json_extract / json_each
	if field.DataType == TypeJSON {
		return c.compileJSONComparison(cond, field, col)
	}

	switch cond.Operator {
	case TokenColon:
		// Special handling for IP fields with CIDR
		if field.DataType == TypeIP {
			return c.compileIPMatch(cond.Value, col)
		}
		// Integer fields: exact match (port:443 must NOT match 8443)
		if field.DataType == TypeInteger {
			if n, err := strconv.ParseInt(cond.Value, 10, 64); err == nil {
				return col + " = " + c.addArg(n)
			}
		}
		// Float fields: exact match
		if field.DataType == TypeFloat {
			if f, err := strconv.ParseFloat(cond.Value, 64); err == nil {
				return col + " = " + c.addArg(f)
			}
		}
		// Boolean fields: exact match
		if field.DataType == TypeBoolean {
			return c.compileBooleanMatch(cond.Value, col)
		}
		// String fields: contains (case-insensitive LIKE)
		pattern := "%" + escapeLike(cond.Value) + "%"
		return col + " LIKE " + c.addArg(pattern) + " ESCAPE '\\'"

	case TokenEqual:
		// Exact match
		if field.DataType == TypeIP {
			return c.compileIPMatch(cond.Value, col)
		}
		if field.DataType == TypeInteger {
			if n, err := strconv.ParseInt(cond.Value, 10, 64); err == nil {
				return col + " = " + c.addArg(n)
			}
		}
		if field.DataType == TypeFloat {
			if f, err := strconv.ParseFloat(cond.Value, 64); err == nil {
				return col + " = " + c.addArg(f)
			}
		}
		if field.DataType == TypeBoolean {
			return c.compileBooleanMatch(cond.Value, col)
		}
		if field.CaseInsens {
			return "LOWER(" + col + ") = LOWER(" + c.addArg(cond.Value) + ")"
		}
		return col + " = " + c.addArg(cond.Value)

	case TokenNotEqual:
		if field.DataType == TypeInteger {
			if n, err := strconv.ParseInt(cond.Value, 10, 64); err == nil {
				return "(" + col + " IS NULL OR " + col + " != " + c.addArg(n) + ")"
			}
		}
		if field.CaseInsens {
			return "(" + col + " IS NULL OR LOWER(" + col + ") != LOWER(" + c.addArg(cond.Value) + "))"
		}
		return "(" + col + " IS NULL OR " + col + " != " + c.addArg(cond.Value) + ")"

	case TokenRegexOp:
		// SQLite doesn't have native regex, we approximate with LIKE + GLOB
		// For basic patterns, we convert. For complex regex, we use GLOB.
		pattern := regexToGlob(cond.Value)
		if pattern != "" {
			return col + " GLOB " + c.addArg(pattern)
		}
		// Fallback: treat as contains
		return col + " LIKE " + c.addArg("%"+escapeLike(cond.Value)+"%") + " ESCAPE '\\'"

	case TokenWildcard:
		// Wildcard matching: * = any chars, ? = single char → SQLite GLOB
		return col + " GLOB " + c.addArg(cond.Value)

	case TokenGT:
		return c.compileNumericOp(cond.Value, field, col, ">")
	case TokenLT:
		return c.compileNumericOp(cond.Value, field, col, "<")
	case TokenGTE:
		return c.compileNumericOp(cond.Value, field, col, ">=")
	case TokenLTE:
		return c.compileNumericOp(cond.Value, field, col, "<=")

	default:
		c.err = fmt.Errorf("unsupported operator %s for field %q", cond.Operator, cond.Field)
		return ""
	}
}

// compileJSONComparison handles all operators for JSON path fields.
// Uses json_extract() for scalar access and json_each() for array element search.
//
// Strategy:
//   - ":" (contains) → CAST(json_extract(...) AS TEXT) LIKE '%value%'
//     Works universally for scalars, arrays, nested objects (searches in stringified form).
//   - "=" (exact) → json_extract() = ? OR EXISTS(json_each ... WHERE value = ?)
//     Handles both scalar equality and array element membership.
//   - "!=" → NOT(json_extract() = ?)
//   - ">", "<", ">=", "<=" → numeric comparison on json_extract()
//   - "*=" (wildcard) → CAST(json_extract() AS TEXT) GLOB ?
func (c *compiler) compileJSONComparison(cond *Condition, field FieldInfo, col string) string {
	alias := c.resolveAlias(field.Table)
	qualifiedCol := alias + "." + field.Column

	// Guard against NULL or empty JSON columns to prevent "malformed JSON" errors
	// from json_extract() being called on non-JSON data.
	guard := qualifiedCol + " IS NOT NULL AND " + qualifiedCol + " != ''"

	switch cond.Operator {
	case TokenColon:
		// Contains search: works on scalars ("version" LIKE '%5.7%') and
		// arrays (["PASV","AUTH TLS"] LIKE '%AUTH TLS%')
		val := strings.ToLower(cond.Value)
		switch val {
		case "true", "yes":
			return "(" + guard + " AND " + col + " = 1)"
		case "false", "no":
			return "(" + guard + " AND " + col + " = 0)"
		default:
			pattern := "%" + escapeLike(cond.Value) + "%"
			return "(" + guard + " AND CAST(" + col + " AS TEXT) LIKE " + c.addArg(pattern) + " ESCAPE '\\')"
		}

	case TokenEqual:
		// Exact match: handle scalars directly, arrays via json_each
		val := strings.ToLower(cond.Value)
		switch val {
		case "true", "yes":
			return "(" + guard + " AND " + col + " = 1)"
		case "false", "no":
			return "(" + guard + " AND " + col + " = 0)"
		default:
			// Try numeric
			if n, err := strconv.ParseInt(cond.Value, 10, 64); err == nil {
				return "(" + guard + " AND (" + col + " = " + c.addArg(n) +
					" OR EXISTS (SELECT 1 FROM json_each(" + qualifiedCol + ", " + safeJSONPathLiteral(field.JSONPath) + ") WHERE value = " + c.addArg(n) + ")))"
			}
			if f, err := strconv.ParseFloat(cond.Value, 64); err == nil {
				return "(" + guard + " AND (" + col + " = " + c.addArg(f) +
					" OR EXISTS (SELECT 1 FROM json_each(" + qualifiedCol + ", " + safeJSONPathLiteral(field.JSONPath) + ") WHERE value = " + c.addArg(f) + ")))"
			}
			// String: scalar OR array element
			return "(" + guard + " AND (" + col + " = " + c.addArg(cond.Value) +
				" OR EXISTS (SELECT 1 FROM json_each(" + qualifiedCol + ", " + safeJSONPathLiteral(field.JSONPath) + ") WHERE value = " + c.addArg(cond.Value) + ")))"
		}

	case TokenNotEqual:
		// NOT scalar match: if source column is NULL/empty, field doesn't exist → not equal
		return "(" + qualifiedCol + " IS NULL OR " + qualifiedCol + " = '' OR " + col + " != " + c.addArg(cond.Value) + ")"

	case TokenGT, TokenLT, TokenGTE, TokenLTE:
		opStr := map[TokenType]string{
			TokenGT: ">", TokenLT: "<", TokenGTE: ">=", TokenLTE: "<=",
		}[cond.Operator]
		if n, err := strconv.ParseInt(cond.Value, 10, 64); err == nil {
			return "(" + guard + " AND CAST(" + col + " AS INTEGER) " + opStr + " " + c.addArg(n) + ")"
		}
		if f, err := strconv.ParseFloat(cond.Value, 64); err == nil {
			return "(" + guard + " AND CAST(" + col + " AS REAL) " + opStr + " " + c.addArg(f) + ")"
		}
		return "(" + guard + " AND " + col + " " + opStr + " " + c.addArg(cond.Value) + ")"

	case TokenWildcard:
		return "(" + guard + " AND CAST(" + col + " AS TEXT) GLOB " + c.addArg(cond.Value) + ")"

	case TokenRegexOp:
		// Approximate regex on JSON field via GLOB
		pattern := regexToGlob(cond.Value)
		if pattern != "" {
			return "(" + guard + " AND CAST(" + col + " AS TEXT) GLOB " + c.addArg(pattern) + ")"
		}
		return "(" + guard + " AND CAST(" + col + " AS TEXT) LIKE " + c.addArg("%"+escapeLike(cond.Value)+"%") + " ESCAPE '\\')"

	default:
		c.err = fmt.Errorf("unsupported operator %s for JSON field %q", cond.Operator, cond.Field)
		return ""
	}
}

func (c *compiler) compileNumericOp(value string, field FieldInfo, col, op string) string {
	switch field.DataType {
	case TypeInteger:
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return col + " " + op + " " + c.addArg(n)
		}
		c.err = fmt.Errorf("expected integer value for field, got %q", value)
		return ""
	case TypeFloat:
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return col + " " + op + " " + c.addArg(f)
		}
		c.err = fmt.Errorf("expected numeric value for field, got %q", value)
		return ""
	default:
		return col + " " + op + " " + c.addArg(value)
	}
}

func (c *compiler) compileIPMatch(value, col string) string {
	// Check if it's CIDR notation
	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			c.err = fmt.Errorf("invalid CIDR %q: %v", value, err)
			return ""
		}
		return c.compileCIDRMatch(ipNet, col)
	}
	// Exact IP match
	return col + " = " + c.addArg(value)
}

// compileCIDRMatch generates SQL for CIDR matching using LIKE patterns.
// For octet-aligned masks (/8, /16, /24), uses efficient LIKE prefix.
// For others, generates range check with computed boundaries.
func (c *compiler) compileCIDRMatch(ipNet *net.IPNet, col string) string {
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		// IPv6 not supported yet, fall back to prefix
		return col + " LIKE " + c.addArg(ipNet.IP.String()+"%")
	}

	ip := ipNet.IP.To4()
	if ip == nil {
		return col + " = " + c.addArg(ipNet.String())
	}

	// Octet-aligned: use LIKE for best performance
	switch ones {
	case 8:
		return col + " LIKE " + c.addArg(fmt.Sprintf("%d.%%", ip[0]))
	case 16:
		return col + " LIKE " + c.addArg(fmt.Sprintf("%d.%d.%%", ip[0], ip[1]))
	case 24:
		return col + " LIKE " + c.addArg(fmt.Sprintf("%d.%d.%d.%%", ip[0], ip[1], ip[2]))
	case 32:
		return col + " = " + c.addArg(ip.String())
	}

	// Non-octet-aligned: use ip_int BETWEEN for precise CIDR matching.
	// This requires the ip_int column to be populated (see ensureHost).
	start := ipToUint32(ipNet.IP)
	mask := ipToUint32(net.IP(ipNet.Mask))
	end := start | ^mask

	return "h.ip_int BETWEEN " + c.addArg(int64(start)) + " AND " + c.addArg(int64(end))
}

func (c *compiler) compileBooleanMatch(value, col string) string {
	switch strings.ToLower(value) {
	case "true", "1", "yes":
		return col + " = 1"
	case "false", "0", "no":
		return col + " = 0"
	default:
		return col + " = " + c.addArg(value)
	}
}

func (c *compiler) compileExistsCheck(_ *Condition, field FieldInfo) string {
	col := c.columnRef(field)

	// JSON fields need a guard on the raw column before calling json_extract,
	// otherwise json_extract('', path) raises "malformed JSON" and kills the query.
	if field.DataType == TypeJSON {
		alias := c.resolveAlias(field.Table)
		qualifiedCol := alias + "." + field.Column
		guard := qualifiedCol + " IS NOT NULL AND " + qualifiedCol + " != ''"
		// json_type returns the type string ("array","object","text","integer","real")
		// or SQL NULL if the path doesn't exist. For JSON null it returns "null" (a string),
		// so we must also exclude that.
		jt := "json_type(" + qualifiedCol + ", " + safeJSONPathLiteral(field.JSONPath) + ")"
		notNull := jt + " IS NOT NULL AND " + jt + " != 'null'"
		return c.wrapWithTable(field, "("+guard+" AND "+notNull+")")
	}

	notNull := col + " IS NOT NULL AND " + col + " != ''"
	return c.wrapWithTable(field, notNull)
}

func (c *compiler) compileSetCondition(cond *Condition, field FieldInfo) string {
	col := c.columnRef(field)

	placeholders := make([]string, len(cond.Values))
	for i, v := range cond.Values {
		if field.DataType == TypeInteger {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				placeholders[i] = c.addArg(n)
				continue
			}
		}
		placeholders[i] = c.addArg(v)
	}

	inClause := col + " IN (" + strings.Join(placeholders, ", ") + ")"
	return c.wrapWithTable(field, inClause)
}

// tableAlias returns the SQL alias for a table.
func tableAlias(table string) string {
	switch table {
	case TableHosts:
		return "h"
	case TableServices:
		return "_s"
	case TableHTTPData:
		return "_hd"
	case TableCertificates:
		return "_c"
	case TableServiceCerts:
		return "_sc"
	case TableHostDomains:
		return "_hdom"
	case TableServiceEnrichments:
		return "_se"
	default:
		return ""
	}
}

// resolveAlias returns the SQL alias for a table, accounting for service-centric mode.
// In service-centric mode, services use "s" (the main table) instead of "_s" (subquery alias).
func (c *compiler) resolveAlias(table string) string {
	if c.serviceCentric && table == TableServices {
		return "s"
	}
	return tableAlias(table)
}

// columnRef returns the SQL column reference with appropriate table alias.
// For JSON fields, returns json_extract(column, path) expression.
func (c *compiler) columnRef(field FieldInfo) string {
	alias := c.resolveAlias(field.Table)
	if alias == "" {
		return field.Column
	}

	qualifiedCol := alias + "." + field.Column

	// JSON path: use json_extract()
	if field.JSONPath != "" {
		return "json_extract(" + qualifiedCol + ", " + safeJSONPathLiteral(field.JSONPath) + ")"
	}

	return qualifiedCol
}

// wrapWithTable wraps a condition SQL in an EXISTS subquery if needed.
func (c *compiler) wrapWithTable(field FieldInfo, conditionSQL string) string {
	if c.serviceCentric {
		return c.wrapWithTableServiceCentric(field, conditionSQL)
	}

	switch field.Table {
	case TableHosts:
		// Direct condition on the hosts table
		return conditionSQL

	case TableServices:
		return "EXISTS (SELECT 1 FROM services _s WHERE _s.ip = h.ip AND " + conditionSQL + ")"

	case TableHTTPData:
		return "EXISTS (SELECT 1 FROM services _s " +
			"INNER JOIN http_data _hd ON _s.ip = _hd.ip AND _s.port = _hd.port " +
			"WHERE _s.ip = h.ip AND " + conditionSQL + ")"

	case TableCertificates:
		return "EXISTS (SELECT 1 FROM service_certificates _sc " +
			"INNER JOIN certificates _c ON _sc.cert_fingerprint = _c.fingerprint_sha256 " +
			"WHERE _sc.ip = h.ip AND " + conditionSQL + ")"

	case TableServiceCerts:
		return "EXISTS (SELECT 1 FROM service_certificates _sc WHERE _sc.ip = h.ip AND " + conditionSQL + ")"

	case TableHostDomains:
		return "EXISTS (SELECT 1 FROM host_domains _hdom WHERE _hdom.ip = h.ip AND " + conditionSQL + ")"

	case TableServiceEnrichments:
		return "EXISTS (SELECT 1 FROM service_enrichments _se WHERE _se.ip = h.ip AND " + conditionSQL + ")"

	default:
		c.err = fmt.Errorf("unknown table %q for field", field.Table)
		return ""
	}
}

// wrapWithTableServiceCentric generates SQL for service-centric queries.
// Service conditions apply directly on the main "s" table.
// Other table conditions use EXISTS subqueries joined via s.ip/s.port.
func (c *compiler) wrapWithTableServiceCentric(field FieldInfo, conditionSQL string) string {
	switch field.Table {
	case TableHosts:
		// Direct condition on hosts (joined as h)
		return conditionSQL

	case TableServices:
		// Direct condition on the main services table (aliased as s)
		// conditionSQL already uses "s." via resolveAlias
		return conditionSQL

	case TableHTTPData:
		return "EXISTS (SELECT 1 FROM http_data _hd " +
			"WHERE _hd.ip = s.ip AND _hd.port = s.port AND " + conditionSQL + ")"

	case TableCertificates:
		return "EXISTS (SELECT 1 FROM service_certificates _sc " +
			"INNER JOIN certificates _c ON _sc.cert_fingerprint = _c.fingerprint_sha256 " +
			"WHERE _sc.ip = s.ip AND _sc.port = s.port AND " + conditionSQL + ")"

	case TableServiceCerts:
		return "EXISTS (SELECT 1 FROM service_certificates _sc " +
			"WHERE _sc.ip = s.ip AND _sc.port = s.port AND " + conditionSQL + ")"

	case TableHostDomains:
		return "EXISTS (SELECT 1 FROM host_domains _hdom WHERE _hdom.ip = s.ip AND " + conditionSQL + ")"

	case TableServiceEnrichments:
		return "EXISTS (SELECT 1 FROM service_enrichments _se " +
			"WHERE _se.ip = s.ip AND _se.port = s.port AND " + conditionSQL + ")"

	default:
		c.err = fmt.Errorf("unknown table %q for field", field.Table)
		return ""
	}
}

// Helper functions

// safeJSONPathLiteral returns a SQL string literal for a JSON path,
// escaping single quotes as defense-in-depth against injection.
func safeJSONPathLiteral(jsonPath string) string {
	return "'" + strings.ReplaceAll(jsonPath, "'", "''") + "'"
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// regexToGlob converts simple regex patterns to SQLite GLOB patterns.
// Returns empty string if the regex is too complex.
func regexToGlob(pattern string) string {
	// Handle common simple patterns
	var result strings.Builder
	i := 0
	for i < len(pattern) {
		ch := pattern[i]
		switch ch {
		case '^':
			// Anchor start - GLOB implicitly anchors
			i++
		case '$':
			// Anchor end - GLOB implicitly anchors
			i++
		case '.':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				result.WriteString("*")
				i += 2
			} else if i+1 < len(pattern) && pattern[i+1] == '+' {
				result.WriteString("?*")
				i += 2
			} else {
				result.WriteString("?")
				i++
			}
		case '*', '+', '?', '(', ')', '[', ']', '{', '}', '|':
			// Complex regex - can't convert
			return ""
		case '\\':
			if i+1 < len(pattern) {
				result.WriteByte(pattern[i+1])
				i += 2
			} else {
				return ""
			}
		default:
			result.WriteByte(ch)
			i++
		}
	}
	return result.String()
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
