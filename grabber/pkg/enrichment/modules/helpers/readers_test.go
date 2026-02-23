package helpers

import (
	"io"
	"testing"
)

// --- ReadBannerLine ---

func TestReadBannerLine_WithNewline(t *testing.T) {
	conn := NewMockConn([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	got, err := ReadBannerLine(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("got %q, want %q", got, "SSH-2.0-OpenSSH_8.9")
	}
}

func TestReadBannerLine_NoNewline_EOF(t *testing.T) {
	conn := NewMockConn([]byte("partial banner"))
	got, err := ReadBannerLine(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "partial banner" {
		t.Errorf("got %q, want %q", got, "partial banner")
	}
}

func TestReadBannerLine_Empty(t *testing.T) {
	conn := NewMockConn([]byte{})
	got, err := ReadBannerLine(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestReadBannerLine_TrimSpaces(t *testing.T) {
	conn := NewMockConn([]byte("  hello  \n"))
	got, err := ReadBannerLine(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

// --- ReadResponseLines ---

func TestReadResponseLines_NLines(t *testing.T) {
	conn := NewMockConn([]byte("line1\nline2\nline3\n"))
	got, err := ReadResponseLines(conn, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3", len(got))
	}
	if got[0] != "line1" || got[1] != "line2" || got[2] != "line3" {
		t.Errorf("got %v", got)
	}
}

func TestReadResponseLines_EmptyLineStops(t *testing.T) {
	conn := NewMockConn([]byte("line1\nline2\n\nline3\n"))
	got, err := ReadResponseLines(conn, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d lines, want 2 (stops at empty line)", len(got))
	}
}

func TestReadResponseLines_MaxLines(t *testing.T) {
	conn := NewMockConn([]byte("a\nb\nc\nd\ne\n"))
	got, err := ReadResponseLines(conn, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d lines, want 3", len(got))
	}
}

func TestReadResponseLines_EOF_MidRead(t *testing.T) {
	conn := NewMockConn([]byte("line1\npartial"))
	got, err := ReadResponseLines(conn, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d lines, want 2", len(got))
	}
	if got[1] != "partial" {
		t.Errorf("got %q, want %q", got[1], "partial")
	}
}

// --- ReadUntil ---

func TestReadUntil_DelimiterFound(t *testing.T) {
	conn := NewMockConn([]byte("hello\x00world"))
	got, err := ReadUntil(conn, []byte{0x00}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello\x00" {
		t.Errorf("got %q", got)
	}
}

func TestReadUntil_MaxBytesReached(t *testing.T) {
	conn := NewMockConn([]byte("this is a long string without delimiter"))
	got, err := ReadUntil(conn, []byte{0xFF}, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 10 {
		t.Errorf("got %d bytes, want 10", len(got))
	}
}

func TestReadUntil_EOF_BeforeDelimiter(t *testing.T) {
	conn := NewMockConn([]byte("short"))
	got, err := ReadUntil(conn, []byte{0xFF}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("got %q, want %q", got, "short")
	}
}

func TestReadUntil_MultiByteDelimiter(t *testing.T) {
	conn := NewMockConn([]byte("data\r\nmore"))
	got, err := ReadUntil(conn, []byte("\r\n"), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "data\r\n" {
		t.Errorf("got %q", got)
	}
}

// --- ReadExactly ---

func TestReadExactly_Exact(t *testing.T) {
	conn := NewMockConn([]byte("abcdef"))
	got, err := ReadExactly(conn, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "abcd" {
		t.Errorf("got %q, want %q", got, "abcd")
	}
}

func TestReadExactly_EOF_Partial(t *testing.T) {
	conn := NewMockConn([]byte("ab"))
	got, err := ReadExactly(conn, 4)
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if string(got) != "ab" {
		t.Errorf("got %q, want %q", got, "ab")
	}
}

func TestReadExactly_ZeroBytes(t *testing.T) {
	conn := NewMockConn([]byte("data"))
	got, err := ReadExactly(conn, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}

// --- ReadAvailable ---

func TestReadAvailable_Normal(t *testing.T) {
	conn := NewMockConn([]byte("hello world"))
	got, err := ReadAvailable(conn, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestReadAvailable_ConnectionClosed(t *testing.T) {
	conn := NewMockConn([]byte{})
	got, err := ReadAvailable(conn, 100)
	// bytes.Buffer returns io.EOF which ReadAvailable ignores
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}

func TestReadAvailable_MaxBytes(t *testing.T) {
	conn := NewMockConn([]byte("abcdefghij"))
	got, err := ReadAvailable(conn, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("got %d bytes, want 5", len(got))
	}
}
