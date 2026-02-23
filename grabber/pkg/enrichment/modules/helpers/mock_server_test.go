package helpers

import (
	"net"
	"testing"
)

// StartMockTCPServer starts a TCP server on a random port that handles one connection.
// Returns the address (host:port) and a cleanup function.
func StartMockTCPServer(t *testing.T, handler func(net.Conn)) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP server: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

// StartMockUDPServer starts a UDP server on a random port.
// Returns the address and a cleanup function.
func StartMockUDPServer(t *testing.T, handler func(*net.UDPConn)) (addr string, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock UDP server: %v", err)
	}
	udpConn := pc.(*net.UDPConn)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(udpConn)
	}()

	return pc.LocalAddr().String(), func() {
		pc.Close()
		<-done
	}
}
