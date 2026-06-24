package nats

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"meow/grabber/pkg/enrichment/types"
)

// Consumer handles NATS message consumption from one or more subjects
type Consumer struct {
	nc            *nats.Conn
	subscriptions []*nats.Subscription
	handler       func(*types.EnrichmentRequest) bool
	subjects      []string
}

// NewConsumer creates a new NATS consumer for multiple subjects
func NewConsumer(nc *nats.Conn, subjects []string, handler func(*types.EnrichmentRequest) bool) (*Consumer, error) {
	return &Consumer{
		nc:       nc,
		subjects: subjects,
		handler:  handler,
	}, nil
}

// Start begins consuming messages from NATS on all configured subjects
func (c *Consumer) Start() error {
	msgHandler := func(msg *nats.Msg) {
		// Parse enrichment request
		var req types.EnrichmentRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Error().Err(err).Msg("Failed to parse enrichment request")
			// NAK on parse error so the message can be redelivered or sent to dead letter
			if msg.Reply != "" {
				msg.Nak()
			}
			return
		}

		log.Debug().
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Str("domain", req.Domain).
			Str("subject", msg.Subject).
			Msg("Received enrichment request")

		// Handle the request. Only ACK if it was accepted locally.
		if c.handler(&req) {
			if msg.Reply != "" {
				msg.Ack()
			}
			return
		}

		if msg.Reply != "" {
			msg.Nak()
		}
	}

	for _, subject := range c.subjects {
		sub, err := c.nc.QueueSubscribe(subject, "enrichment-workers", msgHandler)
		if err != nil {
			return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
		}

		// 512 MB pending limit (default is 64 MB)
		sub.SetPendingLimits(-1, 512*1024*1024)

		c.subscriptions = append(c.subscriptions, sub)

		log.Info().
			Str("subject", subject).
			Str("queue_group", "enrichment-workers").
			Msg("Subscribed to enrichment subject with queue group (load balanced)")
	}

	return nil
}

// Stop stops consuming messages from all subscriptions
func (c *Consumer) Stop() error {
	var lastErr error
	for _, sub := range c.subscriptions {
		if err := sub.Unsubscribe(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Publisher handles NATS message publishing
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

// Publish publishes an enrichment result to NATS
func (p *Publisher) Publish(result *types.EnrichmentResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := p.nc.Publish(p.subject, data); err != nil {
		return fmt.Errorf("failed to publish to %s: %w", p.subject, err)
	}

	log.Debug().
		Str("ip", result.IP).
		Int("port", result.Port).
		Str("service", result.Service).
		Str("subject", p.subject).
		Msg("Published enrichment result")

	return nil
}

// PublishWithRetry publishes with retry logic
func (p *Publisher) PublishWithRetry(result *types.EnrichmentResult, maxRetries int) error {
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		err := p.Publish(result)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Warn().
			Err(err).
			Int("attempt", i+1).
			Int("max_retries", maxRetries).
			Msg("Failed to publish, retrying...")

		// Exponential backoff: 100ms, 200ms, 400ms, 800ms...
		time.Sleep(time.Duration(1<<uint(i)) * 100 * time.Millisecond)
	}

	return fmt.Errorf("failed to publish after %d retries: %w", maxRetries, lastErr)
}
