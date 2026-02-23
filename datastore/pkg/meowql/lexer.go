package meowql

import (
	"fmt"
	"strings"
	"unicode"
)

// Lexer tokenizes a MeowQL query string.
type Lexer struct {
	input  string
	pos    int
	tokens []Token
}

// Lex tokenizes the input string and returns all tokens.
func Lex(input string) ([]Token, error) {
	l := &Lexer{input: input}
	if err := l.scan(); err != nil {
		return nil, err
	}
	return l.tokens, nil
}

func (l *Lexer) scan() error {
	for l.pos < len(l.input) {
		l.skipWhitespace()
		if l.pos >= len(l.input) {
			break
		}

		ch := l.input[l.pos]
		start := l.pos

		switch {
		case ch == '(':
			l.emit(TokenLParen, "(", start)
		case ch == ')':
			l.emit(TokenRParen, ")", start)
		case ch == '{':
			l.emit(TokenLBrace, "{", start)
		case ch == '}':
			l.emit(TokenRBrace, "}", start)
		case ch == ',':
			l.emit(TokenComma, ",", start)
		case ch == ':':
			l.emit(TokenColon, ":", start)
		case ch == '!' && l.peek(1) == '=':
			l.pos++
			l.emit(TokenNotEqual, "!=", start)
		case ch == '=' && l.peek(1) == '~':
			l.pos++
			l.emit(TokenRegexOp, "=~", start)
		case ch == '=':
			l.emit(TokenEqual, "=", start)
		case ch == '*' && l.peek(1) == '=':
			l.pos++
			l.emit(TokenWildcard, "*=", start)
		case ch == '*':
			l.emit(TokenStar, "*", start)
		case ch == '>' && l.peek(1) == '=':
			l.pos++
			l.emit(TokenGTE, ">=", start)
		case ch == '>':
			l.emit(TokenGT, ">", start)
		case ch == '<' && l.peek(1) == '=':
			l.pos++
			l.emit(TokenLTE, "<=", start)
		case ch == '<':
			l.emit(TokenLT, "<", start)
		case ch == '-':
			// Prefix negation on a field: -port:443
			// Only if followed by an ident character (not a number, that would be negative number)
			if l.pos+1 < len(l.input) && isIdentStart(rune(l.input[l.pos+1])) {
				l.emit(TokenNot, "-", start)
			} else {
				return l.errorf("unexpected character '-' at position %d", start)
			}
		case ch == '"' || ch == '\'':
			tok, err := l.scanString(ch)
			if err != nil {
				return err
			}
			l.tokens = append(l.tokens, tok)
			continue // scanString already advanced pos
		default:
			if isIdentStart(rune(ch)) {
				tok := l.scanIdentOrKeyword()
				l.tokens = append(l.tokens, tok)
				continue // already advanced
			}
			if isDigit(ch) {
				tok := l.scanNumberOrCIDR()
				l.tokens = append(l.tokens, tok)
				continue
			}
			return l.errorf("unexpected character %q at position %d", ch, start)
		}

		l.pos++
	}

	l.tokens = append(l.tokens, Token{Type: TokenEOF, Pos: l.pos})
	return nil
}

func (l *Lexer) emit(typ TokenType, value string, pos int) {
	l.tokens = append(l.tokens, Token{Type: typ, Value: value, Pos: pos})
}

func (l *Lexer) peek(offset int) byte {
	idx := l.pos + offset
	if idx < len(l.input) {
		return l.input[idx]
	}
	return 0
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && (l.input[l.pos] == ' ' || l.input[l.pos] == '\t' || l.input[l.pos] == '\n' || l.input[l.pos] == '\r') {
		l.pos++
	}
}

// scanString scans a quoted string (double or single quotes).
func (l *Lexer) scanString(quote byte) (Token, error) {
	start := l.pos
	l.pos++ // skip opening quote
	var sb strings.Builder

	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			// Escape sequence
			next := l.input[l.pos+1]
			switch next {
			case '"', '\'', '\\':
				sb.WriteByte(next)
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				sb.WriteByte('\\')
				sb.WriteByte(next)
			}
			l.pos += 2
			continue
		}
		if ch == quote {
			l.pos++ // skip closing quote
			return Token{Type: TokenString, Value: sb.String(), Pos: start}, nil
		}
		sb.WriteByte(ch)
		l.pos++
	}

	return Token{}, l.errorf("unterminated string starting at position %d", start)
}

// scanIdentOrKeyword scans an identifier or keyword (and, or, not).
func (l *Lexer) scanIdentOrKeyword() Token {
	start := l.pos
	for l.pos < len(l.input) && isIdentChar(rune(l.input[l.pos])) {
		l.pos++
	}
	value := l.input[start:l.pos]

	// Check for keywords (case-insensitive)
	switch strings.ToLower(value) {
	case "and":
		return Token{Type: TokenAnd, Value: value, Pos: start}
	case "or":
		return Token{Type: TokenOr, Value: value, Pos: start}
	case "not":
		return Token{Type: TokenNot, Value: value, Pos: start}
	default:
		return Token{Type: TokenIdent, Value: value, Pos: start}
	}
}

// scanNumberOrCIDR scans a number or CIDR notation (e.g., 192.168.0.0/24).
func (l *Lexer) scanNumberOrCIDR() Token {
	start := l.pos
	hasDot := false
	hasSlash := false

	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if isDigit(ch) {
			l.pos++
		} else if ch == '.' {
			hasDot = true
			l.pos++
		} else if ch == '/' && hasDot && !hasSlash {
			// Could be CIDR notation: x.x.x.x/N
			hasSlash = true
			l.pos++
		} else if ch == ':' && hasDot {
			// IPv6-like notation or IP:port - stop before the colon
			break
		} else {
			break
		}
	}

	value := l.input[start:l.pos]

	if hasSlash && hasDot {
		return Token{Type: TokenCIDR, Value: value, Pos: start}
	}
	if hasDot && strings.Count(value, ".") == 3 {
		// Looks like an IP address without CIDR - treat as ident for matching
		return Token{Type: TokenIdent, Value: value, Pos: start}
	}

	return Token{Type: TokenNumber, Value: value, Pos: start}
}

func (l *Lexer) errorf(format string, args ...any) error {
	return fmt.Errorf("meowql lexer: "+format, args...)
}

func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_'
}

func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == '.' || ch == '-'
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}
