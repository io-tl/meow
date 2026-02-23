package consumer

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"meow/grabber/pkg/fingerprint/types"
)

// Consumer gère la consommation des événements NATS
type Consumer struct {
	nc        *nats.Conn
	sub       *nats.Subscription
	subject   string
	eventChan chan types.OpenPortEvent
	stopChan  chan struct{}
	closed    bool
	mu        sync.Mutex

	dropCount   atomic.Uint64
	lastDropLog atomic.Int64 // unix nano
}

// NewConsumer crée un nouveau consumer NATS
func NewConsumer(nc *nats.Conn, subject string, bufferSize int) *Consumer {
	return &Consumer{
		nc:        nc,
		subject:   subject,
		eventChan: make(chan types.OpenPortEvent, bufferSize),
		stopChan:  make(chan struct{}),
		closed:    false,
	}
}

// Start démarre la consommation des événements
func (c *Consumer) Start() error {
	var err error
	c.sub, err = c.nc.QueueSubscribe(c.subject, "fingerprint-workers", c.handleMessage)
	if err != nil {
		return err
	}

	// 512 MB pending limit (default is 64 MB)
	c.sub.SetPendingLimits(-1, 512*1024*1024)

	log.Info().
		Str("topic", c.subject).
		Str("queue_group", "fingerprint-workers").
		Msg("Subscribed with queue group (load balanced)")
	return nil
}

// handleMessage traite un message NATS entrant (blocking with timeout)
func (c *Consumer) handleMessage(msg *nats.Msg) {
	var event types.OpenPortEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal event")
		if msg.Reply != "" {
			msg.Nak()
		}
		return
	}

	// Block up to 30s waiting for channel space — applies backpressure to NATS
	// instead of silently dropping events
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case c.eventChan <- event:
		log.Debug().
			Str("scan_id", event.ScanID).
			Str("ip", event.IP).
			Int("port", event.Port).
			Msg("Event received")
		if msg.Reply != "" {
			msg.Ack()
		}
	case <-timer.C:
		c.dropCount.Add(1)
		c.logDropOnce()
		if msg.Reply != "" {
			msg.Nak()
		}
	case <-c.stopChan:
		if msg.Reply != "" {
			msg.Nak()
		}
		return
	}
}

// logDropOnce logs a drop warning at most once per 5 seconds
func (c *Consumer) logDropOnce() {
	now := time.Now().UnixNano()
	last := c.lastDropLog.Load()
	if now-last < int64(5*time.Second) {
		return
	}
	if c.lastDropLog.CompareAndSwap(last, now) {
		log.Warn().
			Uint64("total_dropped", c.dropCount.Load()).
			Int("queue_len", len(c.eventChan)).
			Int("queue_cap", cap(c.eventChan)).
			Msg("Event channel full, dropping events (pipeline backpressure)")
	}
}

// Events retourne le channel des événements
func (c *Consumer) Events() <-chan types.OpenPortEvent {
	return c.eventChan
}

// Stop arrête le consumer
func (c *Consumer) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	close(c.stopChan)
	c.closed = true

	if c.sub != nil {
		c.sub.Unsubscribe()
	}

	close(c.eventChan)
	log.Info().Msg("Consumer stopped")
}
