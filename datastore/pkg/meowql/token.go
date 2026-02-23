package meowql

import "fmt"

// TokenType represents the type of a lexer token.
type TokenType int

const (
	// Literals
	TokenIdent  TokenType = iota // field name or unquoted value
	TokenString                  // "quoted string" or 'quoted string'
	TokenNumber                  // 123, 3.14
	TokenCIDR                    // 192.168.0.0/24

	// Operators
	TokenColon    // :
	TokenEqual    // =
	TokenNotEqual // !=
	TokenRegexOp  // =~
	TokenWildcard // *=
	TokenGT       // >
	TokenLT       // <
	TokenGTE      // >=
	TokenLTE      // <=

	// Boolean keywords
	TokenAnd // and
	TokenOr  // or
	TokenNot // not

	// Delimiters
	TokenLParen // (
	TokenRParen // )
	TokenLBrace // {
	TokenRBrace // }
	TokenComma  // ,
	TokenStar   // * (for exists check: field:*)

	// Special
	TokenEOF
)

var tokenNames = map[TokenType]string{
	TokenIdent:    "IDENT",
	TokenString:   "STRING",
	TokenNumber:   "NUMBER",
	TokenCIDR:     "CIDR",
	TokenColon:    ":",
	TokenEqual:    "=",
	TokenNotEqual: "!=",
	TokenRegexOp:  "=~",
	TokenWildcard: "*=",
	TokenGT:       ">",
	TokenLT:       "<",
	TokenGTE:      ">=",
	TokenLTE:      "<=",
	TokenAnd:      "AND",
	TokenOr:       "OR",
	TokenNot:      "NOT",
	TokenLParen:   "(",
	TokenRParen:   ")",
	TokenLBrace:   "{",
	TokenRBrace:   "}",
	TokenComma:    ",",
	TokenStar:     "*",
	TokenEOF:      "EOF",
}

func (t TokenType) String() string {
	if name, ok := tokenNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TOKEN(%d)", int(t))
}

// IsOperator returns true if the token is a comparison operator.
func (t TokenType) IsOperator() bool {
	switch t {
	case TokenColon, TokenEqual, TokenNotEqual, TokenRegexOp,
		TokenWildcard, TokenGT, TokenLT, TokenGTE, TokenLTE:
		return true
	}
	return false
}

// Token represents a lexer token with its type, value, and position.
type Token struct {
	Type  TokenType
	Value string
	Pos   int // byte offset in the input
}

func (t Token) String() string {
	if t.Value != "" {
		return fmt.Sprintf("%s(%q)@%d", t.Type, t.Value, t.Pos)
	}
	return fmt.Sprintf("%s@%d", t.Type, t.Pos)
}
