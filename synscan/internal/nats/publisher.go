package nats

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"meow/synscan/pkg/types"

	"github.com/nats-io/nats.go"
)

// Publisher publishes scan results to NATS
type Publisher struct {
	nc     *nats.Conn
	scanID string
}

// PeerName generates a unique NATS client name like "synscan-myhost-a3f1"
func PeerName() string {
	host, _ := os.Hostname()
	if len(host) > 12 {
		host = host[:12]
	}
	b := make([]byte, 2)
	rand.Read(b)
	return fmt.Sprintf("synscan-%s-%x", host, b)
}

// NewPublisher creates a new NATS publisher
func NewPublisher(url, token, user, password, scanID string) (*Publisher, error) {
	var opts []nats.Option

	opts = append(opts, nats.Name(PeerName()))

	// Configure authentication
	if token != "" {
		opts = append(opts, nats.Token(token))
	} else if user != "" && password != "" {
		opts = append(opts, nats.UserInfo(user, password))
	}

	// Connect to NATS
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	return &Publisher{
		nc:     nc,
		scanID: scanID,
	}, nil
}

// PublishResult publishes a scan result
func (p *Publisher) PublishResult(result *types.ScanResult) error {
	// Only publish open ports
	if result.State != types.PortOpen {
		return nil
	}

	event := types.OpenPortEvent{
		ScanID:    p.scanID,
		IP:        result.IP,
		Port:      result.Port,
		Timestamp: result.Timestamp.Unix(),
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	return p.nc.Publish("scan.port.open", data)
}

// PublishBatch publishes multiple results
func (p *Publisher) PublishBatch(results []*types.ScanResult) error {
	for _, result := range results {
		if err := p.PublishResult(result); err != nil {
			log.Printf("Failed to publish result: %v", err)
		}
	}
	return nil
}

// Conn returns the underlying NATS connection
func (p *Publisher) Conn() *nats.Conn {
	return p.nc
}

// PublishHeartbeat publishes a scanner heartbeat message
func (p *Publisher) PublishHeartbeat(hb *types.ScannerHeartbeat) error {
	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}
	return p.nc.Publish("scan.status.heartbeat", data)
}

// Close closes the NATS connection
func (p *Publisher) Close() error {
	p.nc.Close()
	return nil
}
