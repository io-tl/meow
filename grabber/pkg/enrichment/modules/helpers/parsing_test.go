package helpers

import (
	"testing"
)

// --- ExtractNullTerminatedString ---

func TestExtractNullTerminatedString_Normal(t *testing.T) {
	got := ExtractNullTerminatedString([]byte("hello\x00world"))
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestExtractNullTerminatedString_MultipleNulls(t *testing.T) {
	got := ExtractNullTerminatedString([]byte("abc\x00def\x00ghi"))
	if got != "abc" {
		t.Errorf("got %q, want %q", got, "abc")
	}
}

func TestExtractNullTerminatedString_NoNull(t *testing.T) {
	got := ExtractNullTerminatedString([]byte("hello"))
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestExtractNullTerminatedString_Empty(t *testing.T) {
	got := ExtractNullTerminatedString([]byte{})
	if got != "" {
		t.Errorf("got %q, want %q", got, "")
	}
}

func TestExtractNullTerminatedString_StartsWithNull(t *testing.T) {
	got := ExtractNullTerminatedString([]byte("\x00data"))
	if got != "" {
		t.Errorf("got %q, want %q", got, "")
	}
}

func TestExtractNullTerminatedString_Binary(t *testing.T) {
	got := ExtractNullTerminatedString([]byte{0x01, 0x02, 0x03, 0x00, 0x04})
	if got != "\x01\x02\x03" {
		t.Errorf("got %q, want %q", got, "\x01\x02\x03")
	}
}

// --- ParseKeyValue ---

func TestParseKeyValue_Colon(t *testing.T) {
	k, v := ParseKeyValue("key: value", ":")
	if k != "key" || v != "value" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "key", "value")
	}
}

func TestParseKeyValue_Equals(t *testing.T) {
	k, v := ParseKeyValue("key=value", "=")
	if k != "key" || v != "value" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "key", "value")
	}
}

func TestParseKeyValue_NoSeparator(t *testing.T) {
	k, v := ParseKeyValue("noseparator", ":")
	if k != "" || v != "" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "", "")
	}
}

func TestParseKeyValue_EmptyValue(t *testing.T) {
	k, v := ParseKeyValue("key:", ":")
	if k != "key" || v != "" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "key", "")
	}
}

func TestParseKeyValue_EmptyKey(t *testing.T) {
	k, v := ParseKeyValue(":value", ":")
	if k != "" || v != "value" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "", "value")
	}
}

func TestParseKeyValue_Spaces(t *testing.T) {
	k, v := ParseKeyValue("  key  :  value  ", ":")
	if k != "key" || v != "value" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "key", "value")
	}
}

func TestParseKeyValue_MultipleSeparators(t *testing.T) {
	k, v := ParseKeyValue("key:val:ue", ":")
	if k != "key" || v != "val:ue" {
		t.Errorf("got (%q, %q), want (%q, %q)", k, v, "key", "val:ue")
	}
}

// --- ParseKeyValueMap ---

func TestParseKeyValueMap_Valid(t *testing.T) {
	lines := []string{"a:1", "b:2", "c:3"}
	m := ParseKeyValueMap(lines, ":")
	if len(m) != 3 || m["a"] != "1" || m["b"] != "2" || m["c"] != "3" {
		t.Errorf("got %v", m)
	}
}

func TestParseKeyValueMap_EmptyLinesIgnored(t *testing.T) {
	lines := []string{"a:1", "", "nosep", "b:2"}
	m := ParseKeyValueMap(lines, ":")
	if len(m) != 2 || m["a"] != "1" || m["b"] != "2" {
		t.Errorf("got %v", m)
	}
}

func TestParseKeyValueMap_DuplicateKeys(t *testing.T) {
	lines := []string{"a:1", "a:2"}
	m := ParseKeyValueMap(lines, ":")
	if m["a"] != "2" {
		t.Errorf("got %v, want last value to win", m)
	}
}

// --- ContainsAny ---

func TestContainsAny_Match(t *testing.T) {
	if !ContainsAny("hello world", []string{"world", "foo"}) {
		t.Error("expected true")
	}
}

func TestContainsAny_NoMatch(t *testing.T) {
	if ContainsAny("hello world", []string{"foo", "bar"}) {
		t.Error("expected false")
	}
}

func TestContainsAny_EmptySubstrings(t *testing.T) {
	if ContainsAny("hello", []string{}) {
		t.Error("expected false for empty substrings")
	}
}

func TestContainsAny_EmptyString(t *testing.T) {
	// Empty substring "" is contained in any string per strings.Contains
	if !ContainsAny("hello", []string{""}) {
		t.Error("expected true: empty substring is always contained")
	}
}

// --- ExtractBetween ---

func TestExtractBetween_Normal(t *testing.T) {
	got := ExtractBetween("prefix<value>suffix", "<", ">")
	if got != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}
}

func TestExtractBetween_StartAbsent(t *testing.T) {
	got := ExtractBetween("no start marker>", "<", ">")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractBetween_EndAbsent(t *testing.T) {
	got := ExtractBetween("<no end marker", "<", ">")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractBetween_Nested(t *testing.T) {
	got := ExtractBetween("<outer<inner>end>", "<", ">")
	if got != "outer<inner" {
		t.Errorf("got %q, want %q", got, "outer<inner")
	}
}

func TestExtractBetween_Empty(t *testing.T) {
	got := ExtractBetween("", "<", ">")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- ParseVersion ---

func TestParseVersion_WithV(t *testing.T) {
	got := ParseVersion("v1.2.3")
	if got != "1.2.3" {
		t.Errorf("got %q, want %q", got, "1.2.3")
	}
}

func TestParseVersion_WithCapitalV(t *testing.T) {
	got := ParseVersion("V2.0")
	if got != "2.0" {
		t.Errorf("got %q, want %q", got, "2.0")
	}
}

func TestParseVersion_Plain(t *testing.T) {
	got := ParseVersion("1.2.3")
	if got != "1.2.3" {
		t.Errorf("got %q, want %q", got, "1.2.3")
	}
}

func TestParseVersion_WithSuffix(t *testing.T) {
	got := ParseVersion("1.2.3-beta")
	if got != "1.2.3" {
		t.Errorf("got %q, want %q", got, "1.2.3")
	}
}

func TestParseVersion_NoVersion(t *testing.T) {
	got := ParseVersion("abc")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestParseVersion_Empty(t *testing.T) {
	got := ParseVersion("")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestParseVersion_Spaces(t *testing.T) {
	got := ParseVersion("  v3.0.1  ")
	if got != "3.0.1" {
		t.Errorf("got %q, want %q", got, "3.0.1")
	}
}

// --- ReadUint16BE / ReadUint16LE ---

func TestReadUint16BE_Normal(t *testing.T) {
	data := []byte{0x01, 0x02}
	got := ReadUint16BE(data, 0)
	if got != 0x0102 {
		t.Errorf("got 0x%04x, want 0x0102", got)
	}
}

func TestReadUint16BE_Offset(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02}
	got := ReadUint16BE(data, 1)
	if got != 0x0102 {
		t.Errorf("got 0x%04x, want 0x0102", got)
	}
}

func TestReadUint16BE_OOB(t *testing.T) {
	data := []byte{0x01}
	got := ReadUint16BE(data, 0)
	if got != 0 {
		t.Errorf("got %d, want 0 for OOB", got)
	}
}

func TestReadUint16BE_OffsetOOB(t *testing.T) {
	data := []byte{0x01, 0x02}
	got := ReadUint16BE(data, 5)
	if got != 0 {
		t.Errorf("got %d, want 0 for OOB offset", got)
	}
}

func TestReadUint16LE_Normal(t *testing.T) {
	data := []byte{0x02, 0x01}
	got := ReadUint16LE(data, 0)
	if got != 0x0102 {
		t.Errorf("got 0x%04x, want 0x0102", got)
	}
}

func TestReadUint16LE_OOB(t *testing.T) {
	got := ReadUint16LE([]byte{0x01}, 0)
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- ReadUint32BE / ReadUint32LE ---

func TestReadUint32BE_Normal(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	got := ReadUint32BE(data, 0)
	if got != 0x01020304 {
		t.Errorf("got 0x%08x, want 0x01020304", got)
	}
}

func TestReadUint32BE_OOB(t *testing.T) {
	got := ReadUint32BE([]byte{0x01, 0x02}, 0)
	if got != 0 {
		t.Errorf("got %d, want 0 for short slice", got)
	}
}

func TestReadUint32LE_Normal(t *testing.T) {
	data := []byte{0x04, 0x03, 0x02, 0x01}
	got := ReadUint32LE(data, 0)
	if got != 0x01020304 {
		t.Errorf("got 0x%08x, want 0x01020304", got)
	}
}

func TestReadUint32LE_OOB(t *testing.T) {
	got := ReadUint32LE([]byte{0x01}, 0)
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- SplitLines ---

func TestSplitLines_Normal(t *testing.T) {
	got := SplitLines("a\nb\nc")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v", got)
	}
}

func TestSplitLines_CRLF(t *testing.T) {
	got := SplitLines("a\r\nb\r\nc")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v", got)
	}
}

func TestSplitLines_EmptyLinesSkipped(t *testing.T) {
	got := SplitLines("a\n\n\nb")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got %v", got)
	}
}

func TestSplitLines_AllBlanks(t *testing.T) {
	got := SplitLines("\n\n\n")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// --- CleanString ---

func TestCleanString_ASCII(t *testing.T) {
	got := CleanString("Hello World!")
	if got != "Hello World!" {
		t.Errorf("got %q, want %q", got, "Hello World!")
	}
}

func TestCleanString_ControlChars(t *testing.T) {
	got := CleanString("Hello\x00\x01\x1f World")
	if got != "Hello World" {
		t.Errorf("got %q, want %q", got, "Hello World")
	}
}

func TestCleanString_NonASCII(t *testing.T) {
	got := CleanString("caf\xc3\xa9 test")
	if got != "caf test" {
		t.Errorf("got %q, want %q", got, "caf test")
	}
}

func TestCleanString_Empty(t *testing.T) {
	got := CleanString("")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCleanString_AllNonPrintable(t *testing.T) {
	got := CleanString("\x00\x01\x02\x03")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
