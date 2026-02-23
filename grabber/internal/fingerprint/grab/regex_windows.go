//go:build windows

package grab

import "meow/grabber/internal/cpcre2"

// CompileOption represents PCRE2 compile-time options.
type CompileOption = cpcre2.CompileOption

const (
	Caseless = cpcre2.Caseless
	DotAll   = cpcre2.DotAll
)

// Regexp wraps a compiled PCRE2 pattern.
type Regexp = cpcre2.Regexp

// CompilePattern compiles a PCRE2 pattern with no options.
func CompilePattern(pattern string) (*Regexp, error) {
	return cpcre2.Compile(pattern)
}

// CompilePatternOpts compiles a PCRE2 pattern with the given options.
func CompilePatternOpts(pattern string, opts CompileOption) (*Regexp, error) {
	return cpcre2.CompileOpts(pattern, opts)
}
