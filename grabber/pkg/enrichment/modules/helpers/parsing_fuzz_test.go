package helpers

import (
	"testing"
)

func FuzzExtractNullTerminatedString(f *testing.F) {
	f.Add([]byte("hello\x00world"))
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte("no null here"))
	f.Add([]byte{0xFF, 0xFE, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_ = ExtractNullTerminatedString(data)
	})
}

func FuzzParseVersion(f *testing.F) {
	f.Add("v1.2.3")
	f.Add("1.2.3")
	f.Add("V2.0")
	f.Add("abc")
	f.Add("")
	f.Add("1.2.3-beta.1")
	f.Add("999.999.999")
	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic
		_ = ParseVersion(input)
	})
}

func FuzzParseKeyValue(f *testing.F) {
	f.Add("key: value", ":")
	f.Add("key=value", "=")
	f.Add("no separator", ":")
	f.Add("", ":")
	f.Add(": empty key", ":")
	f.Add("key:", ":")
	f.Fuzz(func(t *testing.T, line, sep string) {
		if len(sep) == 0 {
			return // skip empty separator
		}
		// Must not panic
		_, _ = ParseKeyValue(line, sep)
	})
}

func FuzzCleanString(f *testing.F) {
	f.Add("normal text")
	f.Add("\x00\x01\x02hello\x7f")
	f.Add("")
	f.Add("\t\n\r spaces")
	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic
		_ = CleanString(input)
	})
}
