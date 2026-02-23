package helpers

import (
	"bytes"
	"testing"
)

func BenchmarkParseKeyValue(b *testing.B) {
	for b.Loop() {
		ParseKeyValue("Content-Type: application/json", ":")
	}
}

func BenchmarkReadUint16BE(b *testing.B) {
	data := []byte{0x01, 0x00, 0xBB, 0xFF}
	for b.Loop() {
		ReadUint16BE(data, 0)
	}
}

func BenchmarkJSONGet(b *testing.B) {
	m := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": "deep value",
			},
		},
	}
	for b.Loop() {
		JSONGet(m, "a.b.c")
	}
}

func BenchmarkReadUntil(b *testing.B) {
	data := bytes.Repeat([]byte("aaaa"), 250)
	data = append(data, '\n')
	for b.Loop() {
		conn := &MockConn{ReadBuf: bytes.NewBuffer(data)}
		ReadUntil(conn, []byte{'\n'}, 2048)
	}
}

func BenchmarkExtractNullTerminatedString(b *testing.B) {
	data := []byte("Hello World\x00Extra data after null")
	for b.Loop() {
		ExtractNullTerminatedString(data)
	}
}

func BenchmarkParseVersion(b *testing.B) {
	for b.Loop() {
		ParseVersion("v1.23.456-beta")
	}
}
