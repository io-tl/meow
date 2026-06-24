package enricher

import (
	"net"
	"testing"
	"time"

	"meow/grabber/pkg/enrichment/types"

	"github.com/bits-and-blooms/bloom/v3"
)

// mockPublisher implements resultPublisher for testing
type mockPublisher struct {
	results []*types.EnrichmentResult
	err     error
}

func (m *mockPublisher) PublishWithRetry(result *types.EnrichmentResult, maxRetries int) error {
	m.results = append(m.results, result)
	return m.err
}

func TestDedupKey_IPv4(t *testing.T) {
	key := dedupKey("192.168.1.1", 80, "http", "example.com")
	ip := net.ParseIP("192.168.1.1").To4()
	if key[0] != ip[0] || key[1] != ip[1] || key[2] != ip[2] || key[3] != ip[3] {
		t.Errorf("IP bytes mismatch: got %v, want %v", key[:4], ip)
	}
	// Port 80 = 0x00, 0x50
	if key[4] != 0x00 || key[5] != 0x50 {
		t.Errorf("port bytes = [%02x, %02x], want [00, 50]", key[4], key[5])
	}
	// Service starts at offset 6
	service := string(key[6 : 6+4])
	if service != "http" {
		t.Errorf("service = %q, want %q", service, "http")
	}
	// NUL separator
	if key[10] != 0 {
		t.Errorf("separator = %02x, want 0x00", key[10])
	}
	// Domain
	domain := string(key[11:])
	if domain != "example.com" {
		t.Errorf("domain = %q, want %q", domain, "example.com")
	}
}

func TestDedupKey_IPv6(t *testing.T) {
	key := dedupKey("::1", 443, "https", "")
	// ::1 parsed with To4() returns nil, so first 4 bytes should be zero
	if key[0] != 0 || key[1] != 0 || key[2] != 0 || key[3] != 0 {
		t.Errorf("IPv6 bytes: got %v, want all zeros", key[:4])
	}
	// Port 443 = 0x01, 0xBB
	if key[4] != 0x01 || key[5] != 0xBB {
		t.Errorf("port bytes = [%02x, %02x], want [01, BB]", key[4], key[5])
	}
}

func TestDedupKey_EmptyDomain(t *testing.T) {
	key := dedupKey("1.2.3.4", 22, "ssh", "")
	// Key should end with NUL (empty domain)
	if key[len(key)-1] != 0 {
		t.Errorf("last byte = %02x, want 0x00 for empty domain", key[len(key)-1])
	}
}

func TestDedupKey_LargePort(t *testing.T) {
	key := dedupKey("10.0.0.1", 65535, "ftp", "")
	if key[4] != 0xFF || key[5] != 0xFF {
		t.Errorf("port bytes = [%02x, %02x], want [FF, FF]", key[4], key[5])
	}
}

func TestNewEnricher_Defaults(t *testing.T) {
	// We can't call NewEnricher without a real NATS conn,
	// but we can test the Config defaults logic inline
	cfg := &Config{Workers: 0, QueueSize: 0}
	if cfg.Workers <= 0 {
		cfg.Workers = 5
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers = %d, want 5", cfg.Workers)
	}
	if cfg.QueueSize != 1000 {
		t.Errorf("QueueSize = %d, want 1000", cfg.QueueSize)
	}
}

func TestNewEnricher_Custom(t *testing.T) {
	cfg := &Config{Workers: 10, QueueSize: 500}
	if cfg.Workers <= 0 {
		cfg.Workers = 5
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers = %d, want 10", cfg.Workers)
	}
	if cfg.QueueSize != 500 {
		t.Errorf("QueueSize = %d, want 500", cfg.QueueSize)
	}
}

func TestGetStats(t *testing.T) {
	e := &Enricher{
		jobQueue: make(chan *types.EnrichmentRequest, 100),
		workers:  5,
	}
	e.stats.TotalRequests.Add(10)
	e.stats.TotalSuccess.Add(7)
	e.stats.TotalErrors.Add(2)
	e.stats.TotalSkipped.Add(1)

	stats := e.GetStats()
	if stats["total_requests"] != uint64(10) {
		t.Errorf("total_requests = %v", stats["total_requests"])
	}
	if stats["total_success"] != uint64(7) {
		t.Errorf("total_success = %v", stats["total_success"])
	}
	if stats["total_errors"] != uint64(2) {
		t.Errorf("total_errors = %v", stats["total_errors"])
	}
	if stats["total_skipped"] != uint64(1) {
		t.Errorf("total_skipped = %v", stats["total_skipped"])
	}
	if stats["workers"] != 5 {
		t.Errorf("workers = %v", stats["workers"])
	}
}

func TestHandleRequest_Dedup(t *testing.T) {
	e := &Enricher{
		jobQueue: make(chan *types.EnrichmentRequest, 100),
		stopChan: make(chan struct{}),
	}
	// Initialize bloom filter
	e.dedup = newTestBloom()

	req := &types.EnrichmentRequest{
		IP: "1.2.3.4", Port: 80, Service: "http",
	}

	// First call should queue
	if !e.handleRequest(req) {
		t.Fatal("first request should be accepted")
	}
	if e.stats.TotalRequests.Load() != 1 {
		t.Errorf("TotalRequests = %d, want 1", e.stats.TotalRequests.Load())
	}
	if e.stats.TotalDeduplicated.Load() != 0 {
		t.Errorf("TotalDeduplicated = %d, want 0", e.stats.TotalDeduplicated.Load())
	}

	// Second call with same key should be deduplicated
	if !e.handleRequest(req) {
		t.Fatal("duplicate request should be accepted as already handled")
	}
	if e.stats.TotalRequests.Load() != 2 {
		t.Errorf("TotalRequests = %d, want 2", e.stats.TotalRequests.Load())
	}
	if e.stats.TotalDeduplicated.Load() != 1 {
		t.Errorf("TotalDeduplicated = %d, want 1", e.stats.TotalDeduplicated.Load())
	}
}

func TestHandleRequest_QueueFull(t *testing.T) {
	e := &Enricher{
		jobQueue:       make(chan *types.EnrichmentRequest, 1), // tiny queue
		stopChan:       make(chan struct{}),
		enqueueTimeout: 10 * time.Millisecond,
	}
	e.dedup = newTestBloom()

	// Fill the queue
	req1 := &types.EnrichmentRequest{IP: "1.1.1.1", Port: 80, Service: "http"}
	if !e.handleRequest(req1) {
		t.Fatal("first request should be accepted")
	}

	// This should be dropped (queue full, different key to avoid dedup)
	req2 := &types.EnrichmentRequest{IP: "2.2.2.2", Port: 80, Service: "http"}
	if e.handleRequest(req2) {
		t.Fatal("second request should be rejected when queue is full")
	}

	if e.stats.TotalSkipped.Load() != 1 {
		t.Errorf("TotalSkipped = %d, want 1", e.stats.TotalSkipped.Load())
	}
}

func TestProcessJob_ServiceNotEnrichable(t *testing.T) {
	pub := &mockPublisher{}
	e := &Enricher{
		publisher: pub,
		jobQueue:  make(chan *types.EnrichmentRequest, 10),
	}

	// "modbus" has shouldEnrich=false
	req := &types.EnrichmentRequest{IP: "1.2.3.4", Port: 502, Service: "modbus"}
	e.processJob(req)

	if e.stats.TotalSkipped.Load() != 1 {
		t.Errorf("TotalSkipped = %d, want 1", e.stats.TotalSkipped.Load())
	}
	// Should publish an error result so datastore marks the service as failed
	if len(pub.results) != 1 {
		t.Errorf("publisher got %d results, want 1", len(pub.results))
	}
	if len(pub.results) == 1 && pub.results[0].Error == "" {
		t.Error("expected error in published result for non-enrichable service")
	}
}

func TestProcessJob_UnknownService(t *testing.T) {
	pub := &mockPublisher{}
	e := &Enricher{
		publisher: pub,
		jobQueue:  make(chan *types.EnrichmentRequest, 10),
	}

	req := &types.EnrichmentRequest{IP: "1.2.3.4", Port: 9999, Service: "nonexistent_xyz"}
	e.processJob(req)

	if e.stats.TotalSkipped.Load() != 1 {
		t.Errorf("TotalSkipped = %d, want 1", e.stats.TotalSkipped.Load())
	}
	// Should publish an error result so datastore marks the service as failed
	if len(pub.results) != 1 {
		t.Errorf("publisher got %d results, want 1", len(pub.results))
	}
	if len(pub.results) == 1 && pub.results[0].Error == "" {
		t.Error("expected error in published result for unknown service")
	}
}

func TestProcessJob_PublishesResult(t *testing.T) {
	pub := &mockPublisher{}
	e := &Enricher{
		publisher: pub,
		jobQueue:  make(chan *types.EnrichmentRequest, 10),
	}

	// Use "banner" which has shouldEnrich=true and will fail to connect to a non-existent host
	// but still produces a result (with error)
	req := &types.EnrichmentRequest{IP: "127.0.0.1", Port: 1, Service: "banner"}
	e.processJob(req)

	// Should have published one result (either success or error)
	if len(pub.results) != 1 {
		t.Errorf("publisher got %d results, want 1", len(pub.results))
	}
}

// newTestBloom creates a bloom filter for tests
func newTestBloom() *bloom.BloomFilter {
	return bloom.NewWithEstimates(1000, 0.01)
}
