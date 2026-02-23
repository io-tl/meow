package enricher

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	natsclient "meow/grabber/internal/enrichment/nats"
	"meow/grabber/pkg/enrichment/modules"
	"meow/grabber/pkg/enrichment/types"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// resultPublisher is an interface for publishing enrichment results (enables test mocking)
type resultPublisher interface {
	PublishWithRetry(result *types.EnrichmentResult, maxRetries int) error
}

// Enricher orchestrates enrichment operations with a worker pool
type Enricher struct {
	consumer  *natsclient.Consumer
	publisher resultPublisher
	workers   int
	jobQueue  chan *types.EnrichmentRequest
	wg        sync.WaitGroup
	stopChan  chan struct{}
	stopped   atomic.Bool

	// Timeouts
	enrichTimeout time.Duration
	globalTimeout time.Duration

	// Deduplication
	dedup     *bloom.BloomFilter
	dedupLock sync.Mutex

	// Statistics
	stats Stats
}

// Stats holds enrichment statistics
type Stats struct {
	TotalRequests      atomic.Uint64
	TotalSuccess       atomic.Uint64
	TotalErrors        atomic.Uint64
	TotalSkipped       atomic.Uint64
	TotalDeduplicated  atomic.Uint64
	ActiveWorkers      atomic.Int32
}

// Config holds enricher configuration
type Config struct {
	Workers              int
	QueueSize            int
	NATSConn             *nats.Conn
	InputSubject         string
	EnrichRequestSubject string
	OutputSubject        string
	EnrichTimeout        time.Duration // per-module scan timeout (0 = use module default)
	GlobalTimeout        time.Duration // hard deadline for entire job (0 = no limit)
}

// NewEnricher creates a new enricher instance
func NewEnricher(cfg *Config) (*Enricher, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 5
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}

	e := &Enricher{
		workers:       cfg.Workers,
		jobQueue:      make(chan *types.EnrichmentRequest, cfg.QueueSize),
		stopChan:      make(chan struct{}),
		publisher:     natsclient.NewPublisher(cfg.NATSConn, cfg.OutputSubject),
		dedup:         bloom.NewWithEstimates(10_000_000, 0.001), // 10M entries, 0.1% FP (~18MB)
		enrichTimeout: cfg.EnrichTimeout,
		globalTimeout: cfg.GlobalTimeout,
	}

	// Build list of subjects to consume from
	subjects := []string{cfg.InputSubject}
	if cfg.EnrichRequestSubject != "" {
		subjects = append(subjects, cfg.EnrichRequestSubject)
	}

	// Create consumer with handler
	consumer, err := natsclient.NewConsumer(cfg.NATSConn, subjects, e.handleRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer: %w", err)
	}
	e.consumer = consumer

	return e, nil
}

// Start starts the enricher workers and consumer
func (e *Enricher) Start() error {
	// Start consumer
	if err := e.consumer.Start(); err != nil {
		return fmt.Errorf("failed to start consumer: %w", err)
	}

	// Start worker pool
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// Start periodic stats logging
	go e.statsLoop()

	log.Info().
		Int("workers", e.workers).
		Int("queue_size", cap(e.jobQueue)).
		Msg("Enricher started")

	return nil
}

// Stop stops the enricher gracefully
func (e *Enricher) Stop() {
	if e.stopped.Swap(true) {
		return // Already stopped
	}

	log.Info().Msg("Stopping enricher...")

	// Stop consumer
	if err := e.consumer.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping consumer")
	}

	// Close job queue to signal workers
	close(e.jobQueue)

	// Wait for workers to finish
	e.wg.Wait()

	// Signal stop
	close(e.stopChan)

	log.Info().Msg("Enricher stopped")
}

// dedupKey builds a compact key for bloom filter dedup: 4 bytes IP + 2 bytes port + service + NUL + domain
func dedupKey(ip string, port int, service, domain string) []byte {
	parsed := net.ParseIP(ip).To4()
	buf := make([]byte, 6+len(service)+1+len(domain))
	if parsed != nil {
		copy(buf[0:4], parsed)
	}
	buf[4] = byte(port >> 8)
	buf[5] = byte(port)
	copy(buf[6:], service)
	buf[6+len(service)] = 0 // separator
	copy(buf[7+len(service):], domain)
	return buf
}

// handleRequest is called by the NATS consumer for each message
func (e *Enricher) handleRequest(req *types.EnrichmentRequest) {
	e.stats.TotalRequests.Add(1)

	// Dedup via bloom filter using TestAndAdd for atomicity
	key := dedupKey(req.IP, req.Port, req.Service, req.Domain)
	e.dedupLock.Lock()
	if e.dedup.TestAndAdd(key) {
		e.dedupLock.Unlock()
		e.stats.TotalDeduplicated.Add(1)
		log.Debug().
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Msg("Skipping duplicate enrichment request")
		return
	}
	e.dedupLock.Unlock()

	// Try to queue the job (non-blocking)
	select {
	case e.jobQueue <- req:
		// Job queued successfully
	case <-e.stopChan:
		// Enricher is stopping
		return
	default:
		// Queue is full, drop the job
		log.Warn().
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Msg("Job queue full, dropping request")
		e.stats.TotalSkipped.Add(1)
	}
}

// worker processes enrichment jobs from the queue
func (e *Enricher) worker(id int) {
	defer e.wg.Done()

	log.Debug().Int("worker_id", id).Msg("Worker started")

	for job := range e.jobQueue {
		e.stats.ActiveWorkers.Add(1)

		log.Debug().
			Int("worker_id", id).
			Str("ip", job.IP).
			Int("port", job.Port).
			Str("service", job.Service).
			Msg("Processing enrichment job")

		e.processJob(job)

		e.stats.ActiveWorkers.Add(-1)
	}

	log.Debug().Int("worker_id", id).Msg("Worker stopped")
}

// processJob performs the actual enrichment for a job
func (e *Enricher) processJob(req *types.EnrichmentRequest) {
	// Check if service should be enriched
	if !modules.ShouldEnrich(req.Service) {
		log.Debug().
			Str("service", req.Service).
			Msg("Service not configured for enrichment, skipping")
		result := types.NewEnrichmentError(req.IP, req.Port, req.Service, req.Domain,
			fmt.Errorf("no enrichment module for service '%s'", req.Service))
		if err := e.publisher.PublishWithRetry(result, 3); err != nil {
			log.Error().Err(err).Str("service", req.Service).Msg("Failed to publish skipped enrichment result")
		}
		e.stats.TotalSkipped.Add(1)
		return
	}

	// Get the appropriate module
	module, ok := modules.Get(req.Service)
	if !ok {
		log.Warn().
			Str("service", req.Service).
			Msg("No module found for service")
		result := types.NewEnrichmentError(req.IP, req.Port, req.Service, req.Domain,
			fmt.Errorf("no enrichment module for service '%s'", req.Service))
		if err := e.publisher.PublishWithRetry(result, 3); err != nil {
			log.Error().Err(err).Str("service", req.Service).Msg("Failed to publish skipped enrichment result")
		}
		e.stats.TotalSkipped.Add(1)
		return
	}

	// Determine timeout: config enrich_timeout overrides module default
	scanTimeout := module.DefaultTimeout()
	if e.enrichTimeout > 0 {
		scanTimeout = e.enrichTimeout
	}
	// Global timeout caps everything
	globalTimeout := e.globalTimeout

	// Pick the effective deadline (smallest non-zero)
	effectiveTimeout := scanTimeout
	if globalTimeout > 0 && (effectiveTimeout == 0 || globalTimeout < effectiveTimeout) {
		effectiveTimeout = globalTimeout
	}

	// Perform enrichment with timeout
	startTime := time.Now()

	type scanResult struct {
		data interface{}
		err  error
	}
	ch := make(chan scanResult, 1)

	go func() {
		var data interface{}
		var err error
		if req.Domain != "" {
			data, err = module.ScanWithSNI(req.IP, req.Port, req.Domain)
			if data == nil && err == nil {
				data, err = module.Scan(req.IP, req.Port)
			}
		} else {
			data, err = module.Scan(req.IP, req.Port)
		}
		ch <- scanResult{data, err}
	}()

	var data interface{}
	var err error

	if effectiveTimeout > 0 {
		timer := time.NewTimer(effectiveTimeout)
		select {
		case res := <-ch:
			timer.Stop()
			data, err = res.data, res.err
		case <-timer.C:
			err = fmt.Errorf("enrichment timeout after %s", effectiveTimeout)
		}
	} else {
		res := <-ch
		data, err = res.data, res.err
	}

	duration := time.Since(startTime)

	// Validate module result structure (non-blocking warnings)
	if data != nil && err == nil {
		if warnings := validateModuleResult(req.Service, data); len(warnings) > 0 {
			for _, w := range warnings {
				log.Warn().
					Str("service", req.Service).
					Str("ip", req.IP).
					Int("port", req.Port).
					Msg(w)
			}
		}
	}

	// Create result
	var result *types.EnrichmentResult
	if err != nil {
		log.Error().
			Err(err).
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Dur("duration", duration).
			Msg("Enrichment failed")

		result = types.NewEnrichmentError(req.IP, req.Port, req.Service, req.Domain, err)
		e.stats.TotalErrors.Add(1)
	} else {
		log.Info().
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Dur("duration", duration).
			Msg("Enrichment completed")

		result = types.NewEnrichmentResult(req.IP, req.Port, req.Service, req.Domain, data)
		e.stats.TotalSuccess.Add(1)
	}

	// Publish result to NATS
	if err := e.publisher.PublishWithRetry(result, 3); err != nil {
		log.Error().
			Err(err).
			Str("ip", req.IP).
			Int("port", req.Port).
			Str("service", req.Service).
			Msg("Failed to publish enrichment result")
	}
}

// statsLoop periodically logs pool stats (mirrors fingerprint pool behavior)
func (e *Enricher) statsLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastLog string

	for {
		select {
		case <-ticker.C:
			scanned := e.stats.TotalRequests.Load()
			success := e.stats.TotalSuccess.Load()
			errors := e.stats.TotalErrors.Load()
			skipped := e.stats.TotalSkipped.Load()
			deduped := e.stats.TotalDeduplicated.Load()
			active := e.stats.ActiveWorkers.Load()
			queueLen := len(e.jobQueue)

			successRate := 0.0
			errorRate := 0.0
			processed := success + errors
			if processed > 0 {
				successRate = float64(success) / float64(processed) * 100
				errorRate = float64(errors) / float64(processed) * 100
			}

			cur := fmt.Sprintf("w=%d s=%d sr=%.1f er=%.1f q=%d",
				active, scanned, successRate, errorRate, queueLen)
			if cur == lastLog {
				continue
			}
			lastLog = cur

			log.Info().
				Int32("workers", active).
				Uint64("scanned", scanned).
				Float64("success_rate", successRate).
				Float64("error_rate", errorRate).
				Int("queue_input", queueLen).
				Uint64("skipped", skipped).
				Uint64("deduplicated", deduped).
				Msg("Pool stats")

		case <-e.stopChan:
			return
		}
	}
}

// GetStats returns current statistics
func (e *Enricher) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_requests":      e.stats.TotalRequests.Load(),
		"total_success":       e.stats.TotalSuccess.Load(),
		"total_errors":        e.stats.TotalErrors.Load(),
		"total_skipped":       e.stats.TotalSkipped.Load(),
		"total_deduplicated":  e.stats.TotalDeduplicated.Load(),
		"active_workers":      e.stats.ActiveWorkers.Load(),
		"queue_length":        len(e.jobQueue),
		"workers":             e.workers,
	}
}

// validateModuleResult checks that a module result follows JSON conventions.
// Returns a list of warning strings (empty if valid). Non-blocking: callers log warnings.
func validateModuleResult(moduleName string, data interface{}) []string {
	raw, err := json.Marshal(data)
	if err != nil {
		return []string{fmt.Sprintf("module %s: result not JSON-serializable: %v", moduleName, err)}
	}

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return []string{fmt.Sprintf("module %s: result is not a JSON object: %v", moduleName, err)}
	}

	var warnings []string

	// Check "protocol" field exists and is a non-empty string
	proto, ok := m["protocol"]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("module %s: missing 'protocol' field", moduleName))
	} else if s, ok := proto.(string); !ok || s == "" {
		warnings = append(warnings, fmt.Sprintf("module %s: 'protocol' field is empty or not a string", moduleName))
	}

	// Check "error" field type if present
	if errVal, ok := m["error"]; ok {
		if _, ok := errVal.(string); !ok {
			warnings = append(warnings, fmt.Sprintf("module %s: 'error' field is not a string", moduleName))
		}
	}

	return warnings
}
