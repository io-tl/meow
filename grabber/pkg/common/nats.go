package common

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// peerName generates a unique NATS client name like "fingerprint-myhost-a3f1"
func peerName(serviceName string) string {
	host, _ := os.Hostname()
	if len(host) > 12 {
		host = host[:12]
	}
	b := make([]byte, 2)
	rand.Read(b)
	return fmt.Sprintf("%s-%s-%x", serviceName, host, b)
}

// ConnectNATS établit une connexion à NATS avec authentification.
// Retourne la connexion et un channel qui sera fermé si la connexion
// est définitivement perdue (auth violation, connection closed).
func ConnectNATS(cfg NATSConfig, serviceName string) (*nats.Conn, <-chan struct{}, error) {
	closedCh := make(chan struct{})
	closeOnce := sync.Once{}
	signalClosed := func() {
		closeOnce.Do(func() { close(closedCh) })
	}

	name := peerName(serviceName)
	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				log.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info().Str("server", nc.ConnectedUrl()).Msg("NATS reconnected")
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			if err == nats.ErrAuthorization {
				log.Error().Msg("NATS authorization violation — token may have changed, shutting down")
				nc.Close()
				signalClosed()
			} else {
				log.Error().Err(err).Msg("NATS error")
			}
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Warn().Msg("NATS connection permanently closed")
			signalClosed()
		}),
	}

	// Add token authentication if provided
	if cfg.Auth.Token != "" {
		opts = append(opts, nats.Token(cfg.Auth.Token))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, nil, err
	}

	return nc, closedCh, nil
}
