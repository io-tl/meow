package cmd

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"meow/grabber/internal/enrichment/enricher"
	"meow/grabber/internal/fingerprint/consumer"
	"meow/grabber/internal/fingerprint/grab"
	"meow/grabber/internal/fingerprint/publisher"
	"meow/grabber/pkg/common"
	"meow/grabber/pkg/fingerprint/types"

	"github.com/rs/zerolog/log"

	// Import all modules to register them for the embedded enricher.
	_ "meow/grabber/pkg/enrichment/modules"
)

// HostTracker detects hosts that SYN-ACK all ports (false positive floods)
type HostTracker struct {
	mu        sync.Mutex
	counts    map[string]int
	warned    map[string]bool
	threshold int
}

func NewHostTracker(threshold int) *HostTracker {
	return &HostTracker{
		counts:    make(map[string]int),
		warned:    make(map[string]bool),
		threshold: threshold,
	}
}

// ShouldSkip returns true if the host has reached the port threshold
func (h *HostTracker) ShouldSkip(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.counts[ip]++
	if h.counts[ip] >= h.threshold {
		if !h.warned[ip] {
			h.warned[ip] = true
			log.Warn().
				Str("ip", ip).
				Int("ports_seen", h.counts[ip]).
				Int("threshold", h.threshold).
				Msg("Host flood detected, skipping further ports (likely SYN-ACKs all)")
		}
		return true
	}
	return false
}

// processResult handles a scan result and publishes it (including failures)
func processResult(result grab.ScanResult, pub *publisher.Publisher) {
	fpEvent := types.FingerprintEvent{
		IP:        result.Host,
		Port:      result.Port,
		Timestamp: time.Now(),
	}

	if result.Error != nil {
		fpEvent.Failed = true
		fpEvent.FailReason = result.Error.Error()

		log.Debug().
			Str("ip", result.Host).
			Int("port", result.Port).
			Err(result.Error).
			Str("timeout_type", result.TimeoutType).
			Msg("Fingerprint failed")

	} else if result.Result == nil {
		fpEvent.Failed = true
		fpEvent.FailReason = "no_match"

		log.Debug().
			Str("ip", result.Host).
			Int("port", result.Port).
			Msg("No service detected")

	} else {
		r := result.Result
		fpEvent.Service = r.Service
		fpEvent.Product = r.Product
		fpEvent.Version = r.Version
		fpEvent.Info = r.Info
		fpEvent.Hostname = r.Hostname
		fpEvent.OS = r.OS
		fpEvent.DeviceType = r.DeviceType
		fpEvent.CPE = r.CPE
		fpEvent.Banner = r.RawResponse
		fpEvent.ProbeUsed = r.Probe
		fpEvent.Uncertain = r.Uncertain
		fpEvent.TLSVersion = r.TLSVersion
		fpEvent.CipherSuite = r.CipherSuite
		fpEvent.ServerName = r.ServerName
		fpEvent.CertificatesPEM = r.CertificatesPEM
		fpEvent.JARMFingerprint = r.JARMFingerprint

		log.Info().
			Str("ip", result.Host).
			Int("port", result.Port).
			Str("service", r.Service).
			Str("product", r.Product).
			Str("version", r.Version).
			Msg("Fingerprint completed")
	}

	if err := pub.Publish(fpEvent); err != nil {
		log.Error().
			Str("ip", result.Host).
			Int("port", result.Port).
			Err(err).
			Msg("Failed to publish fingerprint result")
	}
}

// Main starts both fingerprint and enrichment services in a single process.
func Main(cfg *common.Config) {
	// Setup logging (once)
	common.SetupLogging(cfg.Logging)

	log.Info().
		Str("nats_url", cfg.NATS.URL).
		Int("finger_workers", cfg.Fingerprint.Workers).
		Int("enrich_workers", cfg.Enrichment.Workers).
		Msg("Starting local mode (fingerprint + enrichment)")

	// --- NATS connections (two isolated connections) ---
	ncFinger, natsClosedFinger, err := common.ConnectNATS(cfg.NATS, "local-finger")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to NATS (fingerprint)")
	}
	defer ncFinger.Close()

	ncEnrich, natsClosedEnrich, err := common.ConnectNATS(cfg.NATS, "local-enrich")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to NATS (enrichment)")
	}
	defer ncEnrich.Close()

	log.Info().Str("server", ncFinger.ConnectedUrl()).Msg("Connected to NATS")

	// --- Init fingerprint ---
	cons := consumer.NewConsumer(ncFinger, cfg.GetFingerprintInputTopic(), 1000)
	pub := publisher.NewPublisher(ncFinger, cfg.GetFingerprintOutputTopic())

	poolConfig := grab.DefaultWorkerPoolConfig()
	poolConfig.NumWorkers = cfg.Fingerprint.Workers
	poolConfig.AutoTune = true
	poolConfig.ProbeTimeout = cfg.Fingerprint.ProbeTimeout()
	poolConfig.GlobalTimeout = cfg.Fingerprint.GlobalTimeout()
	poolConfig.Intensity = 5

	pool, err := grab.NewWorkerPool(poolConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create fingerprint worker pool")
	}

	if err := cons.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start fingerprint consumer")
	}

	// --- Init enrichment ---
	enricherCfg := &enricher.Config{
		Workers:              cfg.Enrichment.Workers,
		QueueSize:            1000,
		NATSConn:             ncEnrich,
		InputSubject:         cfg.GetEnrichmentInputTopic(),
		EnrichRequestSubject: cfg.GetEnrichmentRequestTopic(),
		OutputSubject:        cfg.GetEnrichmentOutputTopic(),
		EnrichTimeout:        cfg.Enrichment.EnrichTimeout(),
		GlobalTimeout:        cfg.Enrichment.GlobalTimeout(),
	}

	e, err := enricher.NewEnricher(enricherCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create enricher")
	}

	if err := e.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start enricher")
	}

	// --- Goroutines fingerprint ---
	done := make(chan struct{})
	hostTracker := NewHostTracker(49)

	// Feed events to the pool with flood detection
	go func() {
		for {
			select {
			case event, ok := <-cons.Events():
				if !ok {
					return
				}
				if hostTracker.ShouldSkip(event.IP) {
					continue
				}
				req := grab.ScanRequest{
					Host:          event.IP,
					Port:          event.Port,
					ProbeTimeout:  cfg.Fingerprint.ProbeTimeout(),
					Intensity:     5,
					GlobalTimeout: cfg.Fingerprint.GlobalTimeout(),
				}
				if err := pool.Submit(req); err != nil {
					log.Warn().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("Pool submit failed")
				}
			case <-done:
				return
			}
		}
	}()

	// Process results and publish
	go func() {
		for {
			select {
			case result, ok := <-pool.Results():
				if !ok {
					return
				}
				processResult(result, pub)
			case <-done:
				return
			}
		}
	}()

	// Log fingerprint stats periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stats := pool.DetailedStats()
				log.Info().
					Int("workers", stats["workers"].(int)).
					Uint64("scanned", stats["scanned"].(uint64)).
					Float64("success_rate", stats["success_rate"].(float64)).
					Float64("timeout_rate", stats["timeout_rate"].(float64)).
					Int("queue_input", stats["queue_input"].(int)).
					Int("queue_output", stats["queue_output"].(int)).
					Msg("Fingerprint pool stats")
			case <-done:
				return
			}
		}
	}()

	log.Info().Msg("Local mode running (fingerprint + enrichment). Press Ctrl+C to stop.")

	// --- Signal handler ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
		log.Info().Msg("Shutdown signal received, stopping...")
	case <-natsClosedFinger:
		log.Fatal().Msg("NATS connection lost (fingerprint), exiting")
	case <-natsClosedEnrich:
		log.Fatal().Msg("NATS connection lost (enrichment), exiting")
	}

	// --- Ordered shutdown: fingerprint first, then enrichment ---
	close(done)
	cons.Stop()
	pool.Close()
	log.Info().Msg("Fingerprint stopped")

	e.Stop()
	enrichStats := e.GetStats()
	log.Info().Interface("enrichment_stats", enrichStats).Msg("Enrichment stopped")

	log.Info().Msg("Local mode shutdown complete")
}
