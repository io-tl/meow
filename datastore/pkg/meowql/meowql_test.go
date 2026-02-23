package meowql

import (
	"strings"
	"testing"
)

// === Lexer Tests ===

func TestLexSimple(t *testing.T) {
	tests := []struct {
		input    string
		expected []TokenType
	}{
		{"port:443", []TokenType{TokenIdent, TokenColon, TokenNumber, TokenEOF}},
		{`country:"US"`, []TokenType{TokenIdent, TokenColon, TokenString, TokenEOF}},
		{"port:443 and country:US", []TokenType{TokenIdent, TokenColon, TokenNumber, TokenAnd, TokenIdent, TokenColon, TokenIdent, TokenEOF}},
		{"not port:22", []TokenType{TokenNot, TokenIdent, TokenColon, TokenNumber, TokenEOF}},
		{"port:{80, 443}", []TokenType{TokenIdent, TokenColon, TokenLBrace, TokenNumber, TokenComma, TokenNumber, TokenRBrace, TokenEOF}},
		{"ip:192.168.1.0/24", []TokenType{TokenIdent, TokenColon, TokenCIDR, TokenEOF}},
		{`banner*="OpenSSH*"`, []TokenType{TokenIdent, TokenWildcard, TokenString, TokenEOF}},
		{"port>=8000", []TokenType{TokenIdent, TokenGTE, TokenNumber, TokenEOF}},
		{`service!="http"`, []TokenType{TokenIdent, TokenNotEqual, TokenString, TokenEOF}},
		{`banner=~"^SSH"`, []TokenType{TokenIdent, TokenRegexOp, TokenString, TokenEOF}},
		{"port:*", []TokenType{TokenIdent, TokenColon, TokenStar, TokenEOF}},
	}

	for _, tt := range tests {
		tokens, err := Lex(tt.input)
		if err != nil {
			t.Errorf("Lex(%q) error: %v", tt.input, err)
			continue
		}

		if len(tokens) != len(tt.expected) {
			t.Errorf("Lex(%q): got %d tokens, want %d\n  tokens: %v", tt.input, len(tokens), len(tt.expected), tokens)
			continue
		}

		for i, tok := range tokens {
			if tok.Type != tt.expected[i] {
				t.Errorf("Lex(%q) token[%d]: got %s, want %s", tt.input, i, tok.Type, tt.expected[i])
			}
		}
	}
}

func TestLexStringEscapes(t *testing.T) {
	tokens, err := Lex(`title:"hello \"world\""`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ident, colon, string, eof
	if tokens[2].Value != `hello "world"` {
		t.Errorf("got %q, want %q", tokens[2].Value, `hello "world"`)
	}
}

func TestLexImplicitAnd(t *testing.T) {
	tokens, err := Lex("port:443 country:US service:http")
	if err != nil {
		t.Fatal(err)
	}
	// port:443 country:US service:http → 10 tokens (3 conditions × 3 tokens + EOF)
	// No AND tokens - implicit
	for _, tok := range tokens {
		if tok.Type == TokenAnd {
			t.Error("should not have explicit AND token for implicit AND")
		}
	}
}

func TestLexErrors(t *testing.T) {
	tests := []string{
		`"unterminated string`,
		`'also unterminated`,
	}
	for _, input := range tests {
		_, err := Lex(input)
		if err == nil {
			t.Errorf("Lex(%q) expected error, got nil", input)
		}
	}
}

// === Parser Tests ===

func TestParseSimpleCondition(t *testing.T) {
	expr, err := Parse("port:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond, ok := expr.(*Condition)
	if !ok {
		t.Fatalf("expected *Condition, got %T", expr)
	}
	if cond.Field != "port" || cond.Operator != TokenColon || cond.Value != "443" {
		t.Errorf("got field=%q op=%s val=%q", cond.Field, cond.Operator, cond.Value)
	}
}

func TestParseExplicitAnd(t *testing.T) {
	expr, err := Parse("port:443 and country:US")
	if err != nil {
		t.Fatal(err)
	}
	and, ok := expr.(*AndExpr)
	if !ok {
		t.Fatalf("expected *AndExpr, got %T", expr)
	}
	left := and.Left.(*Condition)
	right := and.Right.(*Condition)
	if left.Field != "port" || right.Field != "country" {
		t.Errorf("got left=%q right=%q", left.Field, right.Field)
	}
}

func TestParseImplicitAnd(t *testing.T) {
	expr, err := Parse("port:443 country:US")
	if err != nil {
		t.Fatal(err)
	}
	and, ok := expr.(*AndExpr)
	if !ok {
		t.Fatalf("expected *AndExpr (implicit), got %T", expr)
	}
	left := and.Left.(*Condition)
	right := and.Right.(*Condition)
	if left.Field != "port" || right.Field != "country" {
		t.Errorf("got left=%q right=%q", left.Field, right.Field)
	}
}

func TestParseOr(t *testing.T) {
	expr, err := Parse("port:80 or port:443")
	if err != nil {
		t.Fatal(err)
	}
	or, ok := expr.(*OrExpr)
	if !ok {
		t.Fatalf("expected *OrExpr, got %T", expr)
	}
	_ = or.Left.(*Condition)
	_ = or.Right.(*Condition)
}

func TestParseNot(t *testing.T) {
	expr, err := Parse("not cloud:aws")
	if err != nil {
		t.Fatal(err)
	}
	notExpr, ok := expr.(*NotExpr)
	if !ok {
		t.Fatalf("expected *NotExpr, got %T", expr)
	}
	_ = notExpr.Expr.(*Condition)
}

func TestParseParens(t *testing.T) {
	expr, err := Parse("(port:80 or port:443) and country:US")
	if err != nil {
		t.Fatal(err)
	}
	and, ok := expr.(*AndExpr)
	if !ok {
		t.Fatalf("expected *AndExpr, got %T", expr)
	}
	_, ok = and.Left.(*OrExpr)
	if !ok {
		t.Fatalf("expected *OrExpr inside parens, got %T", and.Left)
	}
}

func TestParseSet(t *testing.T) {
	expr, err := Parse("port:{80, 443, 8080}")
	if err != nil {
		t.Fatal(err)
	}
	cond, ok := expr.(*Condition)
	if !ok {
		t.Fatalf("expected *Condition, got %T", expr)
	}
	if len(cond.Values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(cond.Values))
	}
	if cond.Values[0] != "80" || cond.Values[1] != "443" || cond.Values[2] != "8080" {
		t.Errorf("unexpected values: %v", cond.Values)
	}
}

func TestParseExistsCheck(t *testing.T) {
	expr, err := Parse("banner:*")
	if err != nil {
		t.Fatal(err)
	}
	cond, ok := expr.(*Condition)
	if !ok {
		t.Fatalf("expected *Condition, got %T", expr)
	}
	if cond.Value != "*" {
		t.Errorf("expected exists value '*', got %q", cond.Value)
	}
}

func TestParsePrecedence(t *testing.T) {
	// AND binds tighter than OR: a or b and c → a or (b and c)
	expr, err := Parse("port:80 or port:443 and country:US")
	if err != nil {
		t.Fatal(err)
	}
	or, ok := expr.(*OrExpr)
	if !ok {
		t.Fatalf("expected *OrExpr at top, got %T", expr)
	}
	_, ok = or.Right.(*AndExpr)
	if !ok {
		t.Fatalf("expected *AndExpr on right of OR, got %T", or.Right)
	}
}

func TestParseComplex(t *testing.T) {
	input := `(country:"US" or country:"DE") and not cloud:"aws" and port:{80, 443}`
	_, err := Parse(input)
	if err != nil {
		t.Fatalf("failed to parse complex query: %v", err)
	}
}

func TestParseEmpty(t *testing.T) {
	expr, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if expr != nil {
		t.Errorf("expected nil for empty input, got %T", expr)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []string{
		"port:",             // missing value
		":443",              // missing field
		"port:443 and",      // trailing operator
		"port:443 or",       // trailing operator
		"((port:443)",       // unbalanced parens
		"port:{}",           // empty set
	}
	for _, input := range tests {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) expected error, got nil", input)
		}
	}
}

// === Compiler Tests ===

func TestCompileSimpleHostField(t *testing.T) {
	r := Compile("country:US")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "h.country_code") {
		t.Errorf("expected h.country_code in WHERE, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "LIKE") {
		t.Errorf("expected LIKE for : operator, got: %s", r.Where)
	}
	if len(r.Args) != 1 {
		t.Errorf("expected 1 arg, got %d", len(r.Args))
	}
}

func TestCompileExactMatch(t *testing.T) {
	r := Compile(`country="US"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "LOWER") {
		t.Errorf("expected case-insensitive comparison, got: %s", r.Where)
	}
}

func TestCompileServiceField(t *testing.T) {
	r := Compile("port:443")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "EXISTS") {
		t.Errorf("expected EXISTS subquery for services table, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "_s.port") {
		t.Errorf("expected _s.port in subquery, got: %s", r.Where)
	}
}

func TestCompileHTTPField(t *testing.T) {
	r := Compile(`http.title:"login"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "EXISTS") {
		t.Errorf("expected EXISTS subquery, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "http_data") {
		t.Errorf("expected http_data join, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "_hd.title") {
		t.Errorf("expected _hd.title, got: %s", r.Where)
	}
}

func TestCompileCertField(t *testing.T) {
	r := Compile(`tls.cert.cn:"example.com"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "service_certificates") {
		t.Errorf("expected service_certificates join, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "certificates _c") {
		t.Errorf("expected certificates alias, got: %s", r.Where)
	}
}

func TestCompileAnd(t *testing.T) {
	r := Compile("port:443 and country:US")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "AND") {
		t.Errorf("expected AND, got: %s", r.Where)
	}
	if len(r.Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(r.Args))
	}
}

func TestCompileOr(t *testing.T) {
	r := Compile("port:80 or port:443")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "OR") {
		t.Errorf("expected OR, got: %s", r.Where)
	}
}

func TestCompileNot(t *testing.T) {
	r := Compile("not cloud:aws")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "NOT") {
		t.Errorf("expected NOT, got: %s", r.Where)
	}
}

func TestCompileSet(t *testing.T) {
	r := Compile("port:{80, 443, 8080}")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "IN") {
		t.Errorf("expected IN clause, got: %s", r.Where)
	}
	if len(r.Args) != 3 {
		t.Errorf("expected 3 args for set, got %d", len(r.Args))
	}
}

func TestCompileCIDR(t *testing.T) {
	tests := []struct {
		input   string
		contains string
	}{
		{"ip:192.168.1.0/24", "192.168.1.%"},
		{"ip:10.0.0.0/8", "10.%"},
		{"ip:172.16.0.0/16", "172.16.%"},
	}

	for _, tt := range tests {
		r := Compile(tt.input)
		if r.Err != nil {
			t.Errorf("Compile(%q) error: %v", tt.input, r.Err)
			continue
		}
		found := false
		for _, arg := range r.Args {
			if s, ok := arg.(string); ok && s == tt.contains {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Compile(%q): expected arg %q in %v", tt.input, tt.contains, r.Args)
		}
	}
}

func TestCompileNotEqual(t *testing.T) {
	r := Compile(`service!="ssh"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "IS NULL OR") {
		t.Errorf("expected NULL-safe != pattern, got: %s", r.Where)
	}
}

func TestCompileNumericComparison(t *testing.T) {
	r := Compile("port>=8000")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, ">=") {
		t.Errorf("expected >= operator, got: %s", r.Where)
	}
}

func TestCompileWildcard(t *testing.T) {
	r := Compile(`banner*="OpenSSH_8.*"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "GLOB") {
		t.Errorf("expected GLOB for wildcard, got: %s", r.Where)
	}
}

func TestCompileExistsCheck(t *testing.T) {
	r := Compile("banner:*")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "IS NOT NULL") {
		t.Errorf("expected IS NOT NULL for exists check, got: %s", r.Where)
	}
}

func TestCompileEmpty(t *testing.T) {
	r := Compile("")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if r.Where != "1=1" {
		t.Errorf("expected '1=1' for empty query, got: %s", r.Where)
	}
}

func TestCompileUnknownField(t *testing.T) {
	r := Compile("nonexistent:value")
	if r.Err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestCompileComplex(t *testing.T) {
	input := `(country:"US" or country:"DE") and not cloud:"aws" and port:{80, 443}`
	r := Compile(input)
	if r.Err != nil {
		t.Fatalf("Compile(%q) error: %v", input, r.Err)
	}
	if !strings.Contains(r.Where, "AND") && !strings.Contains(r.Where, "OR") {
		t.Errorf("expected boolean operators in output, got: %s", r.Where)
	}
	// Should have: US, DE, aws, 80, 443 = 5 args
	if len(r.Args) != 5 {
		t.Errorf("expected 5 args, got %d: %v", len(r.Args), r.Args)
	}
}

func TestCompileDomainField(t *testing.T) {
	r := Compile(`domain:"example.com"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "host_domains") {
		t.Errorf("expected host_domains table, got: %s", r.Where)
	}
}

func TestCompileEnrichmentStatus(t *testing.T) {
	r := Compile(`enrichment="pending"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "enrichment_status") {
		t.Errorf("expected enrichment_status column, got: %s", r.Where)
	}
}

// === JSON Path Tests ===

func TestCompileEnrichmentJSON(t *testing.T) {
	r := Compile(`enrichment.anonymous_login:true`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "json_extract") {
		t.Errorf("expected json_extract for enrichment field, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "$.anonymous_login") {
		t.Errorf("expected JSON path $.anonymous_login, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "= 1") {
		t.Errorf("expected boolean true → = 1, got: %s", r.Where)
	}
}

func TestCompileEnrichmentNestedPath(t *testing.T) {
	r := Compile(`enrichment.tls.version:"TLS 1.3"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "$.tls.version") {
		t.Errorf("expected nested JSON path $.tls.version, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "enrichment_data") {
		t.Errorf("expected enrichment_data column, got: %s", r.Where)
	}
}

func TestCompileEnrichmentContains(t *testing.T) {
	// `:` on JSON should use CAST + LIKE for universal search (scalars and arrays)
	r := Compile(`enrichment.features:"AUTH TLS"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "CAST") && !strings.Contains(r.Where, "LIKE") {
		t.Errorf("expected CAST+LIKE for JSON contains, got: %s", r.Where)
	}
}

func TestCompileEnrichmentExactArray(t *testing.T) {
	// `=` on JSON should handle both scalar and array via json_each
	r := Compile(`enrichment.auth_methods="PLAIN"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "json_each") {
		t.Errorf("expected json_each for array membership, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "json_extract") {
		t.Errorf("expected json_extract, got: %s", r.Where)
	}
}

func TestCompileEnrichmentNumericComparison(t *testing.T) {
	r := Compile(`enrichment.status_code>=400`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "CAST") {
		t.Errorf("expected CAST for numeric JSON comparison, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, ">=") {
		t.Errorf("expected >= operator, got: %s", r.Where)
	}
}

func TestCompileFingerprintJSON(t *testing.T) {
	r := Compile(`fingerprint.jarm:"2ad2ad"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "fingerprint_data") {
		t.Errorf("expected fingerprint_data column, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "$.jarm") {
		t.Errorf("expected $.jarm path, got: %s", r.Where)
	}
}

func TestCompileHTTPHeadersJSON(t *testing.T) {
	r := Compile(`http.headers.X-Powered-By:"PHP"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "http_data") {
		t.Errorf("expected http_data table, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "$.X-Powered-By") {
		t.Errorf("expected $.X-Powered-By path, got: %s", r.Where)
	}
}

func TestCompileEnrichmentBooleanFalse(t *testing.T) {
	r := Compile(`enrichment.supports_tls:false`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "= 0") {
		t.Errorf("expected boolean false → = 0, got: %s", r.Where)
	}
}

func TestCompileEnrichmentWildcard(t *testing.T) {
	r := Compile(`enrichment.version*="5.7.*"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "GLOB") {
		t.Errorf("expected GLOB for wildcard on JSON, got: %s", r.Where)
	}
}

func TestCompileJSONExistsWrap(t *testing.T) {
	// enrichment.* fields are on services table → should generate EXISTS subquery
	r := Compile(`enrichment.version:"5.7"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "EXISTS") {
		t.Errorf("expected EXISTS subquery for services table JSON, got: %s", r.Where)
	}
}

func TestCompileHTTPHeaderExistsWrap(t *testing.T) {
	// http.headers.* is on http_data → should generate EXISTS with JOIN
	r := Compile(`http.headers.Server:"nginx"`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "EXISTS") {
		t.Errorf("expected EXISTS subquery, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "http_data") {
		t.Errorf("expected http_data in JOIN, got: %s", r.Where)
	}
}

func TestCompileJSONExistsCheckGuard(t *testing.T) {
	// enrichment.shares:* should guard against empty/null enrichment_data
	// before calling json_type, to avoid "malformed JSON" errors.
	r := Compile(`enrichment.shares:*`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	// Must have the guard on the raw column
	if !strings.Contains(r.Where, "IS NOT NULL") {
		t.Errorf("expected IS NOT NULL guard, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "!= ''") {
		t.Errorf("expected != '' guard, got: %s", r.Where)
	}
	// Must use json_type for the existence check
	if !strings.Contains(r.Where, "json_type(") {
		t.Errorf("expected json_type() for JSON exists check, got: %s", r.Where)
	}
	// Must NOT use json_extract for exists (json_type is safer for arrays/objects)
	if strings.Contains(r.Where, "json_extract(") {
		t.Errorf("should use json_type not json_extract for exists check, got: %s", r.Where)
	}
}

func TestCompileCombinedJSONAndRegular(t *testing.T) {
	// Mix regular fields with JSON fields
	r := Compile(`service:"ftp" and enrichment.anonymous_login:true`)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if !strings.Contains(r.Where, "AND") {
		t.Errorf("expected AND, got: %s", r.Where)
	}
	// Should have two EXISTS subqueries (both on services table)
	if strings.Count(r.Where, "EXISTS") < 2 {
		t.Errorf("expected 2 EXISTS subqueries, got: %s", r.Where)
	}
}

func TestCompileInvalidJSONPrefix(t *testing.T) {
	// enrichment. with no key after it should fail
	r := Compile(`enrichment.:true`)
	// This should fail because "enrichment." is lexed as ident "enrichment."
	// then ":" then value — but enrichment. resolves to empty path
	if r.Err == nil {
		t.Error("expected error for empty JSON path")
	}
}

// === Bug Fix Tests ===

func TestCompilePortColonExactMatch(t *testing.T) {
	// port:443 must generate "= 443" not "LIKE '%443%'"
	// which would incorrectly match ports 8443, 4431, etc.
	r := Compile("port:443")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if strings.Contains(r.Where, "LIKE") {
		t.Errorf("port:443 should NOT use LIKE, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "= ?") {
		t.Errorf("port:443 should use = ?, got: %s", r.Where)
	}
	// Verify the arg is int64(443), not string "%443%"
	if len(r.Args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(r.Args))
	}
	if n, ok := r.Args[0].(int64); !ok || n != 443 {
		t.Errorf("expected arg int64(443), got %v (%T)", r.Args[0], r.Args[0])
	}
}

func TestCompileHTTPStatusColonExactMatch(t *testing.T) {
	// http.status:200 must generate "= 200" not "LIKE '%200%'"
	r := Compile("http.status:200")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if strings.Contains(r.Where, "LIKE") {
		t.Errorf("http.status:200 should NOT use LIKE, got: %s", r.Where)
	}
}

func TestCompileASNColonExactMatch(t *testing.T) {
	// asn:15169 must generate "= 15169" not "LIKE '%15169%'"
	r := Compile("asn:15169")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if strings.Contains(r.Where, "LIKE") {
		t.Errorf("asn:15169 should NOT use LIKE, got: %s", r.Where)
	}
	if n, ok := r.Args[0].(int64); !ok || n != 15169 {
		t.Errorf("expected arg int64(15169), got %v (%T)", r.Args[0], r.Args[0])
	}
}

func TestCompileCIDRNonAligned(t *testing.T) {
	// /17 should use ip_int BETWEEN, not LIKE which is too broad
	tests := []struct {
		input    string
		wantSQL  string // substring that must appear in WHERE
		noLIKE   bool   // should NOT contain LIKE
	}{
		{"ip:10.200.128.0/17", "BETWEEN", true},
		{"ip:172.16.32.0/20", "BETWEEN", true},
		{"ip:192.168.1.128/25", "BETWEEN", false}, // /25+ uses SUBSTR approach
	}

	for _, tt := range tests {
		r := Compile(tt.input)
		if r.Err != nil {
			t.Errorf("Compile(%q) error: %v", tt.input, r.Err)
			continue
		}
		if !strings.Contains(r.Where, tt.wantSQL) {
			t.Errorf("Compile(%q): expected %q in WHERE, got: %s", tt.input, tt.wantSQL, r.Where)
		}
		if tt.noLIKE && strings.Contains(r.Where, "LIKE") {
			t.Errorf("Compile(%q): should NOT use LIKE for non-aligned CIDR, got: %s", tt.input, r.Where)
		}
	}
}

func TestCompileNewFieldsCompile(t *testing.T) {
	// Verify all newly added fields compile without error
	newFields := []string{
		`cloud.region:"us-east-1"`,
		`timezone:"America/New_York"`,
		`http.webserver:"nginx"`,
		`http.ssl:true`,
		`http.body_hash:"abc123"`,
		`tls.cert.issuer_org:"Let's Encrypt"`,
		`tls.cert.not_before>1700000000`,
		`tls.cert.is_ca:true`,
		`tls.cert.sig_algo:"sha256WithRSAEncryption"`,
		`tls.cert.serial:"01ab"`,
		`tls.chain_position:0`,
		`domain.source:"certificate"`,
	}
	for _, q := range newFields {
		r := Compile(q)
		if r.Err != nil {
			t.Errorf("Compile(%q) error: %v", q, r.Err)
		}
	}
}

func TestCompileBooleanColonMatch(t *testing.T) {
	// tls.self_signed:true should generate "= 1" not "LIKE '%true%'"
	r := Compile("tls.self_signed:true")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if strings.Contains(r.Where, "LIKE") {
		t.Errorf("tls.self_signed:true should NOT use LIKE, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "= 1") {
		t.Errorf("tls.self_signed:true should have = 1, got: %s", r.Where)
	}
}

// === Integration / Round-trip Tests ===

func TestRoundTrip(t *testing.T) {
	// These queries should parse and compile without error
	queries := []string{
		`port:443`,
		`port:443 country:US`,
		`port:443 and country:"US"`,
		`port:80 or port:443`,
		`not cloud:aws`,
		`(port:80 or port:443) and country:US`,
		`port:{80, 443, 8080, 8443}`,
		`ip:192.168.1.0/24`,
		`http.title:"login"`,
		`tls.cert.cn:"*.example.com"`,
		`banner:*`,
		`port>=1024 and port<=65535`,
		`service="ssh" and not country:"CN"`,
		`banner*="OpenSSH*" and country:US`,
		`product:"nginx" and http.status:200`,
		// JSON path queries
		`enrichment.anonymous_login:true`,
		`enrichment.tls.version:"TLS 1.3"`,
		`enrichment.features:"AUTH TLS"`,
		`enrichment.version="5.7.36"`,
		`enrichment.supports_tls:false`,
		`fingerprint.jarm:"2ad2ad"`,
		`http.headers.X-Powered-By:"PHP"`,
		`http.headers.Server:"nginx"`,
		`service:"ftp" and enrichment.anonymous_login:true`,
		`service:"ssh" and enrichment.host_key_algorithms:"ssh-rsa"`,
		`service:"smtp" and enrichment.auth_methods="PLAIN"`,
		`enrichment.version*="5.7.*"`,
		`enrichment.cvss_score>=7.0`,
		// New fields
		`cloud.region:"us-east-1"`,
		`timezone:"UTC"`,
		`http.webserver:"nginx"`,
		`http.ssl:true`,
		`http.body_hash:"abc"`,
		`tls.cert.issuer_org:"DigiCert"`,
		`tls.cert.not_before>0`,
		`tls.cert.is_ca:false`,
		`tls.cert.sig_algo:"sha256"`,
		`tls.cert.serial:"01ab"`,
		`tls.chain_position:0`,
		`domain.source:"certificate"`,
	}

	for _, q := range queries {
		r := Compile(q)
		if r.Err != nil {
			t.Errorf("Compile(%q) error: %v", q, r.Err)
		}
	}
}

// === Service-Centric Compilation ===

func TestCompileServiceCentric(t *testing.T) {
	// Service conditions should use "s." alias directly (no EXISTS wrapper)
	r := CompileServiceCentric(`port:{22,80,443}`)
	if r.Err != nil {
		t.Fatalf("CompileServiceCentric error: %v", r.Err)
	}
	if strings.Contains(r.Where, "EXISTS") {
		t.Errorf("service-centric port query should not use EXISTS, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "s.port") {
		t.Errorf("service-centric port query should use s.port, got: %s", r.Where)
	}
}

func TestCompileServiceCentricMixed(t *testing.T) {
	// Mixed: host condition (country) + service condition (port)
	r := CompileServiceCentric(`port:443 and country:US`)
	if r.Err != nil {
		t.Fatalf("CompileServiceCentric error: %v", r.Err)
	}
	// port should be direct on s.port, country direct on h.country_code
	if !strings.Contains(r.Where, "s.port") {
		t.Errorf("expected s.port in service-centric, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "h.country_code") {
		t.Errorf("expected h.country_code in service-centric, got: %s", r.Where)
	}
	// Neither condition should be wrapped in EXISTS
	if strings.Contains(r.Where, "EXISTS") {
		t.Errorf("service-centric mixed query should not use EXISTS for host/service conditions, got: %s", r.Where)
	}
}

func TestCompileServiceCentricHTTPData(t *testing.T) {
	// HTTP data should use EXISTS with s.ip/s.port join
	r := CompileServiceCentric(`http.title:"login"`)
	if r.Err != nil {
		t.Fatalf("CompileServiceCentric error: %v", r.Err)
	}
	if !strings.Contains(r.Where, "EXISTS") {
		t.Errorf("service-centric http query should use EXISTS, got: %s", r.Where)
	}
	if !strings.Contains(r.Where, "_hd.ip = s.ip") {
		t.Errorf("service-centric http query should join via s.ip, got: %s", r.Where)
	}
}

func TestCompileServiceCentricJSON(t *testing.T) {
	// JSON enrichment fields should use s.enrichment_data directly
	r := CompileServiceCentric(`enrichment.anonymous_login:true`)
	if r.Err != nil {
		t.Fatalf("CompileServiceCentric error: %v", r.Err)
	}
	if !strings.Contains(r.Where, "s.enrichment_data") {
		t.Errorf("service-centric enrichment query should use s.enrichment_data, got: %s", r.Where)
	}
	if strings.Contains(r.Where, "_s.") {
		t.Errorf("service-centric should not use _s. alias, got: %s", r.Where)
	}
}

// === ExtractFields ===

func TestExtractFields(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		expect []string
	}{
		{
			name:   "simple single field",
			query:  `port:443`,
			expect: []string{"port"},
		},
		{
			name:   "complex with OR and NOT",
			query:  `(country:"US" or port:80) and not cloud:aws`,
			expect: []string{"country", "port", "cloud"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.query)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.query, err)
			}
			got := ExtractFields(expr)
			if len(got) != len(tt.expect) {
				t.Fatalf("ExtractFields(%q) = %v, want %v", tt.query, got, tt.expect)
			}
			gotMap := make(map[string]bool, len(got))
			for _, f := range got {
				gotMap[f] = true
			}
			for _, want := range tt.expect {
				if !gotMap[want] {
					t.Errorf("ExtractFields(%q) missing field %q, got %v", tt.query, want, got)
				}
			}
		})
	}
}

func TestExtractFieldsNil(t *testing.T) {
	fields := ExtractFields(nil)
	if fields != nil {
		t.Errorf("ExtractFields(nil) = %v, want nil", fields)
	}
}

// === Security Tests ===

func TestCompileJSONPathInjectionBlocked(t *testing.T) {
	// Single quote injection
	r := Compile(`"enrichment.x') OR 1=1--":"test"`)
	if r.Err == nil {
		t.Error("should reject JSON path with single quotes")
	}

	// Parenthesis injection
	r = Compile(`"enrichment.x') UNION SELECT 1--":"test"`)
	if r.Err == nil {
		t.Error("should reject JSON path with parens")
	}

	// Space injection
	r = Compile(`"enrichment.x OR 1":"test"`)
	if r.Err == nil {
		t.Error("should reject JSON path with spaces")
	}
}

func TestCompileLegitJSONPathsStillWork(t *testing.T) {
	legit := []string{
		`enrichment.anonymous_login:true`,
		`enrichment.tls.version:"1.3"`,
		`http.headers.X-Powered-By:"PHP"`,
		`http.headers.Content-Type:"text"`,
		`fingerprint.jarm:"abc"`,
		`enrichment.ssh-hostkey.type:"rsa"`,
	}
	for _, q := range legit {
		r := Compile(q)
		if r.Err != nil {
			t.Errorf("Compile(%q) should succeed, got: %v", q, r.Err)
		}
	}
}

// TestSQLInjectionJSONPathComprehensive tests all common SQL injection vectors
// via JSON path field names across all 4 dynamic prefixes.
func TestSQLInjectionJSONPathComprehensive(t *testing.T) {
	// Each payload appended to each JSON prefix must be rejected
	prefixes := []string{"enrichment.", "fingerprint.", "http.headers.", "http.tech."}
	payloads := []struct {
		name    string
		suffix  string
	}{
		// Classic SQL injection
		{"single_quote", "x' OR '1'='1"},
		{"single_quote_close_paren", "x') OR 1=1--"},
		// Note: "x--" is NOT blocked because hyphens are allowed (e.g. X-Powered-By).
		// Double-dash is harmless inside a SQL string literal ('$.x--').
		{"hash_comment", "x#"},
		{"slash_star_comment", "x/**/OR/**/1=1"},
		{"semicolon_stacked", "x;DROP TABLE hosts"},
		{"semicolon_simple", "x;1"},

		// UNION-based injection
		{"union_select", "x') UNION SELECT * FROM hosts--"},
		{"union_all", "x' UNION ALL SELECT 1,2,3--"},

		// Boolean-based blind
		{"and_1_eq_1", "x' AND 1=1--"},
		{"or_1_eq_1", "x' OR 1=1--"},
		{"and_sleep", "x' AND (SELECT 1)--"},

		// Parentheses / subquery
		{"subquery", "x') AND (SELECT 1 FROM hosts)--"},
		{"open_paren", "x("},
		{"close_paren", "x)"},
		{"nested_parens", "x())"},

		// Whitespace variations
		{"space", "x y"},
		{"tab", "x\ty"},
		{"newline", "x\ny"},
		{"carriage_return", "x\ry"},

		// Quotes
		{"double_quote", `x"y`},
		{"backtick", "x`y"},

		// Special SQL characters
		{"at_sign", "x@y"},
		{"dollar", "x$y"},
		{"percent", "x%y"},
		{"ampersand", "x&y"},
		{"pipe", "x|y"},
		{"exclamation", "x!y"},
		{"tilde", "x~y"},
		{"caret", "x^y"},
		{"equals", "x=y"},
		{"less_than", "x<y"},
		{"greater_than", "x>y"},
		{"backslash", `x\y`},
		{"slash", "x/y"},
		{"colon", "x:y"},
		{"comma", "x,y"},
		{"square_bracket", "x[0]"},
		{"curly_brace", "x{y}"},
		{"plus", "x+y"},
		{"asterisk", "x*"},
	}

	for _, prefix := range prefixes {
		for _, p := range payloads {
			name := prefix + p.name
			field := prefix + p.suffix
			t.Run(name, func(t *testing.T) {
				// Try as unquoted ident (lexer may reject it too)
				r := Compile(field + `:test`)
				if r.Err == nil {
					t.Errorf("Compile(%q) should fail for injection payload", field+`:test`)
				}
				// Try as quoted field name
				r = Compile(`"` + field + `":"test"`)
				if r.Err == nil {
					t.Errorf(`Compile("%s":"test") should fail for injection payload`, field)
				}
			})
		}
	}
}

// TestSQLInjectionValueNeverInSQL verifies that user-supplied values never
// appear directly in the compiled SQL WHERE clause. All values must be
// parameterized as "?" placeholders.
func TestSQLInjectionValueNeverInSQL(t *testing.T) {
	// Use a sentinel without underscores so escapeLike doesn't alter it.
	// Underscores are LIKE wildcards and get escaped to \_, breaking contains checks.
	sentinel := "INJECTEDVALUE42"
	tests := []struct {
		name  string
		query string
	}{
		{"string_contains", `service:"` + sentinel + `"`},
		{"string_exact", `service="` + sentinel + `"`},
		{"string_not_equal", `service!="` + sentinel + `"`},
		{"string_wildcard", `banner*="` + sentinel + `*"`},
		{"string_regex", `banner=~"` + sentinel + `"`},
		{"json_contains", `enrichment.key:"` + sentinel + `"`},
		{"json_exact", `enrichment.key="` + sentinel + `"`},
		{"json_not_equal", `enrichment.key!="` + sentinel + `"`},
		{"json_wildcard", `enrichment.key*="` + sentinel + `*"`},
		{"json_regex", `enrichment.key=~"` + sentinel + `"`},
		{"http_header", `http.headers.Server:"` + sentinel + `"`},
		{"fingerprint", `fingerprint.data:"` + sentinel + `"`},
		{"http_tech", `http.tech.name:"` + sentinel + `"`},
		{"set_values", `service:{` + sentinel + `, OTHER}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if r.Err != nil {
				return // some may fail to parse, that's also safe
			}
			if strings.Contains(r.Where, sentinel) {
				t.Errorf("value %q found in WHERE clause (not parameterized): %s", sentinel, r.Where)
			}
			// Verify the sentinel IS in the args (may be wrapped in %...% for LIKE)
			found := false
			for _, arg := range r.Args {
				switch v := arg.(type) {
				case string:
					if strings.Contains(v, sentinel) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("value %q not found in args (may have been dropped), args=%v", sentinel, r.Args)
			}
		})
	}
}

// TestSQLInjectionValuePayloads verifies that classic SQL injection payloads
// in values are safely parameterized and never appear in SQL output.
func TestSQLInjectionValuePayloads(t *testing.T) {
	payloads := []string{
		"' OR '1'='1",
		"'; DROP TABLE hosts--",
		"' UNION SELECT * FROM hosts--",
		"1' AND 1=1--",
		"' OR 1=1#",
		"admin'--",
		"1; ATTACH DATABASE '/tmp/evil.db' AS evil--",
		"' OR ''='",
		"')) OR 1=1--",
		"' AND (SELECT COUNT(*) FROM hosts) > 0--",
	}

	for _, payload := range payloads {
		for _, field := range []string{"service", "country", "banner", "enrichment.key"} {
			name := field + "/" + payload[:min(len(payload), 20)]
			t.Run(name, func(t *testing.T) {
				query := field + `:"` + payload + `"`
				r := Compile(query)
				if r.Err != nil {
					return // safe: rejected
				}
				// Payload must NOT appear in SQL
				if strings.Contains(r.Where, payload) {
					t.Errorf("injection payload found in WHERE: %s", r.Where)
				}
				// Must be in args as parameterized value
				found := false
				for _, arg := range r.Args {
					if s, ok := arg.(string); ok && strings.Contains(s, payload) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("payload not in args (dropped?), where=%s", r.Where)
				}
			})
		}
	}
}

// TestSQLInjectionLIKEEscaping verifies that % and _ wildcards in user values
// are properly escaped so they don't act as SQL LIKE wildcards.
func TestSQLInjectionLIKEEscaping(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantArg  string // expected pattern in args
		noRawPct bool   // the value's % should be escaped as \%
	}{
		{
			name:     "percent_in_value",
			query:    `service:"100%"`,
			wantArg:  `%100\%%`,
			noRawPct: true,
		},
		{
			name:     "underscore_in_value",
			query:    `service:"a_b"`,
			wantArg:  `%a\_b%`,
			noRawPct: true,
		},
		{
			name:     "percent_and_underscore",
			query:    `banner:"%admin_"`,
			wantArg:  `%\%admin\_%`,
			noRawPct: true,
		},
		{
			name:     "multiple_percent",
			query:    `product:"%%exploit%%"`,
			wantArg:  `%\%\%exploit\%\%%`,
			noRawPct: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if r.Err != nil {
				t.Fatalf("Compile error: %v", r.Err)
			}
			found := false
			for _, arg := range r.Args {
				if s, ok := arg.(string); ok && s == tt.wantArg {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected arg %q, got args: %v", tt.wantArg, r.Args)
			}
		})
	}
}

// TestSQLInjectionLIKEEscapeClause verifies that ESCAPE '\' is present
// on all LIKE clauses that use escapeLike.
func TestSQLInjectionLIKEEscapeClause(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"string_contains", `service:"test"`},
		{"string_regex_fallback", `banner=~"complex(regex)"`},
		{"json_contains", `enrichment.key:"value"`},
		{"json_regex_fallback", `enrichment.key=~"complex(regex)"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if r.Err != nil {
				t.Fatalf("Compile error: %v", r.Err)
			}
			if strings.Contains(r.Where, "LIKE") {
				if !strings.Contains(r.Where, "ESCAPE") {
					t.Errorf("LIKE without ESCAPE clause: %s", r.Where)
				}
			}
		})
	}
}

// TestSQLInjectionNoSQLKeywordsFromValues ensures SQL keywords in values
// don't break out of parameterization. We verify by checking the args contain
// the value and the WHERE uses "?" placeholders instead of literal values.
func TestSQLInjectionNoSQLKeywordsFromValues(t *testing.T) {
	dangerousValues := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
		"UNION", "TABLE", "CREATE", "EXEC", "EXECUTE", "HAVING",
	}

	for _, keyword := range dangerousValues {
		t.Run(keyword, func(t *testing.T) {
			r := Compile(`service:"` + keyword + `"`)
			if r.Err != nil {
				return // safe
			}
			// The value must be in args (parameterized), never as raw SQL.
			// Note: SQL structural keywords like FROM, WHERE, JOIN naturally
			// appear in EXISTS subqueries and are NOT user-controlled.
			found := false
			for _, arg := range r.Args {
				if s, ok := arg.(string); ok && strings.Contains(s, keyword) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("SQL keyword %q not found in parameterized args", keyword)
			}
		})
	}
}

// TestIsValidJSONPath unit tests the path validator directly.
func TestIsValidJSONPath(t *testing.T) {
	valid := []string{
		"key",
		"nested.key",
		"deep.nested.key",
		"X-Powered-By",
		"Content-Type",
		"ssh-hostkey",
		"key_with_underscores",
		"CamelCase",
		"key123",
		"a.b.c.d.e",
		"abc",
	}
	for _, p := range valid {
		if !isValidJSONPath(p) {
			t.Errorf("isValidJSONPath(%q) = false, want true", p)
		}
	}

	invalid := []string{
		"x' OR 1=1",
		"x') --",
		"x;DROP",
		"x (y)",
		"x\ty",
		"x\ny",
		"x\"y",
		"x`y",
		"x%y",
		"x*y",
		"x=y",
		"x<y",
		"x>y",
		"x!y",
		"x|y",
		"x&y",
		"x[0]",
		"x{y}",
		"x y",
		"x+y",
		"x/y",
		"x:y",
		"x,y",
		"x@y",
		"x$y",
		"x#y",
		"x~y",
		"x^y",
		"x\\y",
		"x\x00y",
	}
	for _, p := range invalid {
		if isValidJSONPath(p) {
			t.Errorf("isValidJSONPath(%q) = true, want false", p)
		}
	}
}

// TestSafeJSONPathLiteral unit tests the defense-in-depth SQL escaping.
func TestSafeJSONPathLiteral(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"$.key", "'$.key'"},
		{"$.nested.key", "'$.nested.key'"},
		{"$.X-Powered-By", "'$.X-Powered-By'"},
		// Defense-in-depth: single quotes are doubled
		{"$.x'y", "'$.x''y'"},
		{"$.x'' OR 1=1--", "'$.x'''' OR 1=1--'"},
	}
	for _, tt := range tests {
		got := safeJSONPathLiteral(tt.input)
		if got != tt.want {
			t.Errorf("safeJSONPathLiteral(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestSQLInjectionServiceCentricVectors ensures service-centric compilation
// is equally safe against injection attempts.
func TestSQLInjectionServiceCentricVectors(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"value_sqli", `service:"' OR 1=1--"`},
		{"value_union", `product:"' UNION SELECT *--"`},
		{"json_value_sqli", `enrichment.key:"' OR 1=1--"`},
		{"json_exact_sqli", `enrichment.key="'; DROP TABLE hosts--"`},
		{"mixed_sqli", `port:443 and service:"' OR 1=1--"`},
		{"set_sqli", `port:{443} and service:"' OR 1=1--"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := CompileServiceCentric(tt.query)
			if r.Err != nil {
				return // safe: rejected
			}
			// Verify no raw injection in SQL
			if strings.Contains(r.Where, "OR 1=1") {
				t.Errorf("injection in service-centric WHERE: %s", r.Where)
			}
			if strings.Contains(r.Where, "DROP TABLE") {
				t.Errorf("DROP TABLE in service-centric WHERE: %s", r.Where)
			}
			if strings.Contains(r.Where, "UNION SELECT") {
				t.Errorf("UNION SELECT in service-centric WHERE: %s", r.Where)
			}
		})
	}
}

// TestSQLInjectionJSONExistsCheck ensures the exists operator (:*) on JSON
// fields doesn't leak user input into json_type() calls.
func TestSQLInjectionJSONExistsCheck(t *testing.T) {
	// These are all valid field names with :* operator
	// Verify the generated SQL only contains safe hardcoded path references
	queries := []string{
		`enrichment.key:*`,
		`fingerprint.jarm:*`,
		`http.headers.Server:*`,
		`http.tech.name:*`,
	}

	for _, q := range queries {
		r := Compile(q)
		if r.Err != nil {
			t.Errorf("Compile(%q) error: %v", q, r.Err)
			continue
		}
		// json_type should use escaped path literal
		if !strings.Contains(r.Where, "json_type(") {
			t.Errorf("Compile(%q): expected json_type, got: %s", q, r.Where)
		}
		// No raw user input should appear - all paths are known safe
		// Verify no args leaked (exists check should have 0 args)
		if len(r.Args) != 0 {
			t.Errorf("Compile(%q): exists check should have 0 args, got %d", q, len(r.Args))
		}
	}
}

// TestSQLInjectionJSONPathAllOperators tests injection resistance across
// all operators for JSON fields.
func TestSQLInjectionJSONPathAllOperators(t *testing.T) {
	payload := "' OR 1=1--"
	operators := []struct {
		name  string
		query string
	}{
		{"colon", `enrichment.safe_key:"` + payload + `"`},
		{"equal", `enrichment.safe_key="` + payload + `"`},
		{"not_equal", `enrichment.safe_key!="` + payload + `"`},
		{"gt", `enrichment.safe_key>"` + payload + `"`},
		{"lt", `enrichment.safe_key<"` + payload + `"`},
		{"gte", `enrichment.safe_key>="` + payload + `"`},
		{"lte", `enrichment.safe_key<="` + payload + `"`},
		{"wildcard", `enrichment.safe_key*="` + payload + `"`},
		{"regex", `enrichment.safe_key=~"` + payload + `"`},
	}

	for _, tt := range operators {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if r.Err != nil {
				return // safe: rejected at parse level
			}
			if strings.Contains(r.Where, "OR 1=1") {
				t.Errorf("injection payload in WHERE for operator %s: %s", tt.name, r.Where)
			}
		})
	}
}

// TestSQLInjectionNumericFieldTypeCoercion verifies that integer/float fields
// properly validate numeric input and don't allow string-based injection.
func TestSQLInjectionNumericFieldTypeCoercion(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"port_sqli", `port:"443 OR 1=1"`},
		{"port_gt_sqli", `port>"443 OR 1=1"`},
		{"asn_sqli", `asn:"15169; DROP TABLE hosts"`},
		{"http_status_sqli", `http.status:"200 UNION SELECT 1"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if r.Err != nil {
				return // safe: rejected
			}
			// If it compiled, the value must be parameterized
			if strings.Contains(r.Where, "OR 1=1") || strings.Contains(r.Where, "DROP TABLE") || strings.Contains(r.Where, "UNION SELECT") {
				t.Errorf("injection in WHERE: %s", r.Where)
			}
		})
	}
}

// TestSQLInjectionCIDRFieldValidation verifies that CIDR values are validated
// and malformed input doesn't inject SQL.
func TestSQLInjectionCIDRFieldValidation(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"valid_cidr", "ip:10.0.0.0/8", false},
		{"valid_ip", "ip:192.168.1.1", false},
		{"invalid_cidr_sqli", `ip:"10.0.0.0/8' OR 1=1--"`, false}, // parsed as string, parameterized
		{"cidr_with_junk", "ip:10.0.0.0/8;DROP", false},           // lexer stops at ;
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compile(tt.query)
			if tt.wantErr && r.Err == nil {
				t.Errorf("expected error for %q", tt.query)
			}
			if r.Err == nil {
				if strings.Contains(r.Where, "OR 1=1") || strings.Contains(r.Where, "DROP") {
					t.Errorf("injection in WHERE: %s", r.Where)
				}
			}
		})
	}
}

// TestSQLInjectionErrorDoesNotLeakSQL verifies that compilation errors
// don't contain internal SQL structure.
func TestSQLInjectionErrorDoesNotLeakSQL(t *testing.T) {
	badQueries := []string{
		"nonexistent:value",
		"enrichment.:value",
	}

	for _, q := range badQueries {
		r := Compile(q)
		if r.Err == nil {
			continue
		}
		errMsg := r.Err.Error()
		// Error should mention the field name, not SQL internals
		if strings.Contains(errMsg, "SELECT") || strings.Contains(errMsg, "FROM") ||
			strings.Contains(errMsg, "WHERE") || strings.Contains(errMsg, "json_extract") {
			t.Errorf("error message leaks SQL structure: %s", errMsg)
		}
	}
}

// TestSQLInjectionEscapeLikeFunction tests the escapeLike helper directly.
func TestSQLInjectionEscapeLikeFunction(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"100%", `100\%`},
		{"a_b", `a\_b`},
		{"%_%", `\%\_\%`},
		{"no special", "no special"},
		{`already\escaped`, `already\escaped`},
		{`\%`, `\\%`},
		{"%%%", `\%\%\%`},
		{"___", `\_\_\_`},
	}

	for _, tt := range tests {
		got := escapeLike(tt.input)
		if got != tt.want {
			t.Errorf("escapeLike(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// === Benchmark ===

func BenchmarkCompile(b *testing.B) {
	query := `(country:"US" or country:"DE") and not cloud:"aws" and port:{80, 443} and http.title:"login"`
	for i := 0; i < b.N; i++ {
		r := Compile(query)
		if r.Err != nil {
			b.Fatal(r.Err)
		}
	}
}
