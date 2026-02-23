package meowql

// ExtractFields walks the AST and returns all unique field names
// referenced in Condition nodes. Returns nil for a nil expression.
func ExtractFields(expr Expression) []string {
	if expr == nil {
		return nil
	}
	seen := make(map[string]bool)
	extractFieldsWalk(expr, seen)
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	return fields
}

func extractFieldsWalk(expr Expression, seen map[string]bool) {
	switch e := expr.(type) {
	case *Condition:
		seen[e.Field] = true
	case *AndExpr:
		extractFieldsWalk(e.Left, seen)
		extractFieldsWalk(e.Right, seen)
	case *OrExpr:
		extractFieldsWalk(e.Left, seen)
		extractFieldsWalk(e.Right, seen)
	case *NotExpr:
		extractFieldsWalk(e.Expr, seen)
	}
}
