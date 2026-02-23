package helpers

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
)

// ReadBannerLine reads a single line banner from connection
func ReadBannerLine(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ReadResponseLines reads multiple lines until empty line or limit
func ReadResponseLines(conn net.Conn, maxLines int) ([]string, error) {
	reader := bufio.NewReader(conn)
	var lines []string

	for i := 0; i < maxLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				lines = append(lines, strings.TrimSpace(line))
			}
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		lines = append(lines, trimmed)
	}

	return lines, nil
}

// ReadUntil reads from connection until delimiter or max bytes.
// Uses buffered reads for performance instead of one syscall per byte.
func ReadUntil(conn net.Conn, delimiter []byte, maxBytes int) ([]byte, error) {
	reader := bufio.NewReaderSize(conn, 4096)
	buffer := make([]byte, 0, maxBytes)

	for len(buffer) < maxBytes {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF && len(buffer) > 0 {
				return buffer, nil
			}
			return buffer, err
		}

		buffer = append(buffer, b)
		if bytes.HasSuffix(buffer, delimiter) {
			return buffer, nil
		}
	}

	return buffer, nil
}

// ReadExactly reads exactly n bytes from connection
func ReadExactly(conn net.Conn, n int) ([]byte, error) {
	buffer := make([]byte, n)
	totalRead := 0

	for totalRead < n {
		bytesRead, err := conn.Read(buffer[totalRead:])
		if err != nil {
			return buffer[:totalRead], err
		}
		totalRead += bytesRead
	}

	return buffer, nil
}

// ReadAvailable reads all available data up to maxBytes
func ReadAvailable(conn net.Conn, maxBytes int) ([]byte, error) {
	buffer := make([]byte, maxBytes)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buffer[:n], nil
}
