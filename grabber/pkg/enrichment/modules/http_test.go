package modules

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestScanHTTP_UsesHostHeaderForFaviconAndTracksFullBodyLength(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 110*1024)
	body = append([]byte(`<html><head><link rel="icon" href="/favicon.ico"></head><body>`), body...)
	body = append(body, []byte(`</body></html>`)...)

	var seenRootHost string
	var seenFaviconHost string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			seenRootHost = r.Host
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		case "/favicon.ico":
			seenFaviconHost = r.Host
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte("ico"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	result, err := scanHTTP(host, port, false, "example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenRootHost != "example.com" {
		t.Fatalf("root Host = %q, want %q", seenRootHost, "example.com")
	}
	if seenFaviconHost != "example.com" {
		t.Fatalf("favicon Host = %q, want %q", seenFaviconHost, "example.com")
	}
	if result.BodyLength != len(body) {
		t.Fatalf("BodyLength = %d, want %d", result.BodyLength, len(body))
	}
	if !result.BodyTruncated {
		t.Fatal("BodyTruncated = false, want true")
	}
	if len(result.Body) != 100*1024 {
		t.Fatalf("len(Body) = %d, want %d", len(result.Body), 100*1024)
	}
	if result.Favicon == nil {
		t.Fatal("Favicon = nil")
	}
	if !strings.Contains(result.Favicon.URL, "/favicon.ico") {
		t.Fatalf("favicon URL = %q", result.Favicon.URL)
	}
}

func TestScanGit_ReadsFragmentedPktLines(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		conn.Read(buf)

		payload := "1111111111111111111111111111111111111111 refs/heads/main\x00multi_ack thin-pack\n"
		pkt := []byte(fmt.Sprintf("%04x%s0000", len(payload)+4, payload))

		conn.Write(pkt[:2])
		time.Sleep(10 * time.Millisecond)
		conn.Write(pkt[2:7])
		time.Sleep(10 * time.Millisecond)
		conn.Write(pkt[7:])
	})

	result, err := (&GitModule{}).Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gitResult := result.(*GitResult)
	if gitResult.RefCount != 1 {
		t.Fatalf("RefCount = %d, want 1", gitResult.RefCount)
	}
	if gitResult.Branches["main"] != "11111111" {
		t.Fatalf("Branches[main] = %q", gitResult.Branches["main"])
	}
	if len(gitResult.Capabilities) == 0 {
		t.Fatal("Capabilities empty")
	}
}
