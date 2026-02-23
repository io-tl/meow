package meowql

// Node is the interface for all AST nodes.
type Node interface {
	node()
}

// Expression is the interface for all expression nodes.
type Expression interface {
	Node
	expr()
}

// AndExpr represents a logical AND between two expressions.
type AndExpr struct {
	Left  Expression
	Right Expression
}

// OrExpr represents a logical OR between two expressions.
type OrExpr struct {
	Left  Expression
	Right Expression
}

// NotExpr represents a logical NOT of an expression.
type NotExpr struct {
	Expr Expression
}

// Condition represents a field comparison: field <op> value.
type Condition struct {
	Field    string    // dot-separated field path, e.g. "http.title" or "port"
	Operator TokenType // the comparison operator
	Value    string    // the value to compare against
	Values   []string  // for set expressions: port:{80, 443, 8080}
	Negate   bool      // for prefix negation: -port:443
}

func (*AndExpr) node()   {}
func (*OrExpr) node()    {}
func (*NotExpr) node()   {}
func (*Condition) node() {}

func (*AndExpr) expr()   {}
func (*OrExpr) expr()    {}
func (*NotExpr) expr()   {}
func (*Condition) expr() {}
