package helpers

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DialTCP establishes a TCP connection with timeout and deadline.
// The deadline is set to the remaining time after dial so the total
// operation stays within the specified timeout.
func DialTCP(ip string, port int, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	return conn, nil
}

// DialUDP establishes a UDP connection with timeout and deadline.
func DialUDP(ip string, port int, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	return conn, nil
}

// DialTLS establishes a TLS connection with timeout, deadline and optional SNI.
func DialTLS(ip string, port int, domain string, timeout time.Duration) (*tls.Conn, error) {
	serverName := domain
	if serverName == "" {
		serverName = ip
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	}

	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{
		Timeout:  timeout,
		Deadline: deadline,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(deadline)
	return conn, nil
}

// DialTLSWithConfig establishes a TLS connection with custom config.
func DialTLSWithConfig(ip string, port int, config *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{
		Timeout:  timeout,
		Deadline: deadline,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(deadline)
	return conn, nil
}
