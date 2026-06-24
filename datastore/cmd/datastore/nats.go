package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// peerName generates a unique NATS client name like "datastore-myhost-a3f1"
func peerName(serviceName string) string {
	host, _ := os.Hostname()
	if len(host) > 12 {
		host = host[:12]
	}
	b := make([]byte, 2)
	rand.Read(b)
	return fmt.Sprintf("%s-%s-%x", serviceName, host, b)
}

func initNATS(cfg *Config) (*nats.Conn, *natsserver.Server, error) {
	var ns *natsserver.Server
	var err error

	if cfg.NATSMode == "embedded" {
		log.Info().
			Str("listen", fmt.Sprintf("%s:%d", cfg.NATSHost, cfg.NATSPort)).
			Str("auth", cfg.NATSAuthMode).
			Msg("Starting NATS ...")

		ns, err = startEmbeddedNATS(cfg.NATSHost, cfg.NATSPort, cfg.NATSAuthMode, cfg.NATSAuthToken, cfg.NATSAuthUser, cfg.NATSAuthPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to start embedded NATS: %w", err)
		}
		time.Sleep(500 * time.Millisecond)

		// Build URL for internal client (without credentials)
		// Use the same host the server is bound to, so the client connects to the right interface
		clientHost := cfg.NATSHost
		if clientHost == "" || clientHost == "0.0.0.0" {
			clientHost = "localhost"
		}
		cfg.NATSURL = fmt.Sprintf("nats://%s:%d", clientHost, cfg.NATSPort)
	}

	// Build connection options based on auth mode
	opts := []nats.Option{
		nats.Name(peerName("datastore")),
		nats.Timeout(10 * time.Second),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(5),
	}

	// Add auth options for client mode or embedded with auth
	if cfg.NATSMode == "client" {
		// For client mode, credentials are in the URL
		// Format: nats://user:pass@host:port or nats://token@host:port
	} else if cfg.NATSMode == "embedded" {
		// For embedded mode, add auth based on mode
		switch cfg.NATSAuthMode {
		case "token":
			opts = append(opts, nats.Token(cfg.NATSAuthToken))
		case "user":
			opts = append(opts, nats.UserInfo(cfg.NATSAuthUser, cfg.NATSAuthPassword))
		}
	}

	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		if ns != nil {
			ns.Shutdown()
		}
		return nil, nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	log.Info().Str("url", maskURL(cfg.NATSURL)).Msg("Connected to NATS")
	return nc, ns, nil
}

// maskURL masks sensitive data in NATS URL for logging
func maskURL(url string) string {
	// Replace credentials with ***
	if len(url) > 7 && url[:7] == "nats://" {
		parts := url[7:]
		if idx := len(parts); idx > 0 {
			for i, c := range parts {
				if c == '@' {
					return "nats://***@" + parts[i+1:]
				}
			}
		}
	}
	return url
}

func startEmbeddedNATS(host string, port int, authMode, authToken, authUser, authPassword string) (*natsserver.Server, error) {
	opts := &natsserver.Options{
		Host:    host,
		Port:    port,
		NoLog:   false,
		NoSigs:  true,
		MaxConn: 100,
	}

	// Configure authentication
	switch authMode {
	case "token":
		if authToken == "" {
			return nil, fmt.Errorf("auth token is required when using token authentication")
		}
		opts.Authorization = authToken
	case "user":
		if authUser == "" || authPassword == "" {
			return nil, fmt.Errorf("auth user and password are required when using user authentication")
		}
		opts.Username = authUser
		opts.Password = authPassword
	case "none":
		log.Warn().Msg("NATS authentication: DISABLED (not recommended for production)")
	default:
		return nil, fmt.Errorf("invalid auth mode: %s (valid: token, user, none)", authMode)
	}

	ns, err := natsserver.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create NATS server: %w", err)
	}

	go ns.Start()

	// Fail fast if the server can't bind (e.g. port already in use)
	time.Sleep(250 * time.Millisecond)
	if !ns.Running() {
		return nil, fmt.Errorf("NATS server failed to start on %s:%d (port may already be in use)", host, port)
	}

	if !ns.ReadyForConnections(5 * time.Second) {
		if !ns.Running() {
			return nil, fmt.Errorf("NATS server failed to start on %s:%d (port may already be in use)", host, port)
		}
		return nil, fmt.Errorf("NATS server not ready after timeout on %s:%d", host, port)
	}

	return ns, nil
}
