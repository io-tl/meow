package meowql

import "fmt"

// Parser produces an AST from a token stream.
type Parser struct {
	tokens []Token
	pos    int
}

// Parse parses a MeowQL query string into an AST.
func Parse(input string) (Expression, error) {
	if input == "" {
		return nil, nil
	}

	tokens, err := Lex(input)
	if err != nil {
		return nil, err
	}

	p := &Parser{tokens: tokens}
	expr, err := p.parseOrExpr()
	if err != nil {
		return nil, err
	}

	if p.current().Type != TokenEOF {
		return nil, p.errorf("unexpected token %s at position %d, expected end of query", p.current(), p.current().Pos)
	}

	return expr, nil
}

// parseOrExpr: and_expr ("or" and_expr)*
func (p *Parser) parseOrExpr() (Expression, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}

	for p.current().Type == TokenOr {
		p.advance() // consume "or"
		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}
		left = &OrExpr{Left: left, Right: right}
	}

	return left, nil
}

// parseAndExpr: unary_expr (("and" | implicit_and) unary_expr)*
// Implicit AND: when next token can start a new condition and is not "or", ")", "}", EOF
func (p *Parser) parseAndExpr() (Expression, error) {
	left, err := p.parseUnaryExpr()
	if err != nil {
		return nil, err
	}

	for {
		cur := p.current()

		// Explicit "and"
		if cur.Type == TokenAnd {
			p.advance()
			right, err := p.parseUnaryExpr()
			if err != nil {
				return nil, err
			}
			left = &AndExpr{Left: left, Right: right}
			continue
		}

		// Implicit AND: next token starts a new expression
		if p.canStartExpr(cur) {
			right, err := p.parseUnaryExpr()
			if err != nil {
				return nil, err
			}
			left = &AndExpr{Left: left, Right: right}
			continue
		}

		break
	}

	return left, nil
}

// canStartExpr returns true if the token can begin a new expression (for implicit AND).
func (p *Parser) canStartExpr(t Token) bool {
	switch t.Type {
	case TokenIdent, TokenString, TokenNumber, TokenCIDR, TokenLParen, TokenNot:
		return true
	}
	return false
}

// parseUnaryExpr: "not" unary_expr | "-" condition | "(" or_expr ")" | condition
func (p *Parser) parseUnaryExpr() (Expression, error) {
	// NOT prefix
	if p.current().Type == TokenNot {
		p.advance()

		// Check if this is prefix negation "-field:value" (lexer emits TokenNot for "-")
		// In that case, just parse the next condition and set Negate
		expr, err := p.parseUnaryExpr()
		if err != nil {
			return nil, err
		}
		return &NotExpr{Expr: expr}, nil
	}

	// Parenthesized expression
	if p.current().Type == TokenLParen {
		p.advance() // consume "("
		expr, err := p.parseOrExpr()
		if err != nil {
			return nil, err
		}
		if p.current().Type != TokenRParen {
			return nil, p.errorf("expected ')' at position %d, got %s", p.current().Pos, p.current())
		}
		p.advance() // consume ")"
		return expr, nil
	}

	return p.parseCondition()
}

// parseCondition: field operator value | field ":" "*" | field ":" "{" values "}"
func (p *Parser) parseCondition() (Expression, error) {
	// Must start with a field name (ident), string, number, or CIDR
	cur := p.current()

	if cur.Type != TokenIdent && cur.Type != TokenString && cur.Type != TokenNumber && cur.Type != TokenCIDR {
		return nil, p.errorf("expected field name at position %d, got %s", cur.Pos, cur)
	}

	field := cur.Value
	p.advance()

	// Must be followed by an operator
	op := p.current()
	if !op.Type.IsOperator() {
		return nil, p.errorf("expected operator after %q at position %d, got %s", field, op.Pos, op)
	}
	p.advance()

	// For ":", check for special forms: field:* (exists) and field:{values} (set)
	if op.Type == TokenColon {
		// Exists check: field:*
		if p.current().Type == TokenStar {
			p.advance()
			return &Condition{
				Field:    field,
				Operator: TokenColon,
				Value:    "*",
			}, nil
		}

		// Set expression: field:{val1, val2, val3}
		if p.current().Type == TokenLBrace {
			values, err := p.parseSet()
			if err != nil {
				return nil, err
			}
			return &Condition{
				Field:    field,
				Operator: TokenColon,
				Values:   values,
			}, nil
		}
	}

	// Regular value
	val := p.current()
	if val.Type != TokenString && val.Type != TokenIdent && val.Type != TokenNumber && val.Type != TokenCIDR {
		return nil, p.errorf("expected value after operator at position %d, got %s", val.Pos, val)
	}
	p.advance()

	return &Condition{
		Field:    field,
		Operator: op.Type,
		Value:    val.Value,
	}, nil
}

// parseSet parses {val1, val2, val3} and returns the values.
func (p *Parser) parseSet() ([]string, error) {
	p.advance() // consume "{"

	var values []string
	for {
		cur := p.current()
		if cur.Type == TokenRBrace {
			p.advance()
			break
		}

		if cur.Type != TokenString && cur.Type != TokenIdent && cur.Type != TokenNumber {
			return nil, p.errorf("expected value in set at position %d, got %s", cur.Pos, cur)
		}
		values = append(values, cur.Value)
		p.advance()

		// Expect comma or closing brace
		if p.current().Type == TokenComma {
			p.advance()
		} else if p.current().Type != TokenRBrace {
			return nil, p.errorf("expected ',' or '}' in set at position %d, got %s", p.current().Pos, p.current())
		}
	}

	if len(values) == 0 {
		return nil, p.errorf("empty set expression")
	}

	return values, nil
}

func (p *Parser) current() Token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return Token{Type: TokenEOF, Pos: len(p.tokens)}
}

func (p *Parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}

func (p *Parser) errorf(format string, args ...any) error {
	return fmt.Errorf("meowql parser: "+format, args...)
}
