package main

import "strings"

func normalizeCountryCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}
