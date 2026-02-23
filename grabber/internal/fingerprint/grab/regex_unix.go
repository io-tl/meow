//go:build !windows

package grab

import "go.elara.ws/pcre"

// CompileOption represents PCRE2 compile-time options.
type CompileOption = pcre.CompileOption

const (
	Caseless = pcre.Caseless
	DotAll   = pcre.DotAll
)

// Regexp wraps a compiled PCRE2 pattern.
type Regexp = pcre.Regexp

// CompilePattern compiles a PCRE2 pattern with no options.
func CompilePattern(pattern string) (*Regexp, error) {
	return pcre.Compile(pattern)
}

// CompilePatternOpts compiles a PCRE2 pattern with the given options.
func CompilePatternOpts(pattern string, opts CompileOption) (*Regexp, error) {
	return pcre.CompileOpts(pattern, opts)
}
