package publisher

import (
	"encoding/json"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"meow/grabber/pkg/fingerprint/types"
)

// Publisher handles publishing results to NATS
type Publisher struct {
	nc      *nats.Conn
	subject string
}

// NewPublisher creates a new NATS publisher
func NewPublisher(nc *nats.Conn, subject string) *Publisher {
	return &Publisher{
		nc:      nc,
		subject: subject,
	}
}

// Publish publishes a fingerprint event to NATS
func (p *Publisher) Publish(event types.FingerprintEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal fingerprint event")
		return err
	}

	if err := p.nc.Publish(p.subject, data); err != nil {
		log.Error().Err(err).Str("subject", p.subject).Msg("Failed to publish event")
		return err
	}

	log.Debug().
		Str("scan_id", event.ScanID).
		Str("ip", event.IP).
		Int("port", event.Port).
		Str("service", event.Service).
		Str("product", event.Product).
		Msg("Fingerprint event published")

	return nil
}
