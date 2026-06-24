package cmd

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"meow/grabber/internal/fingerprint/consumer"
	"meow/grabber/internal/fingerprint/grab"
	"meow/grabber/internal/fingerprint/publisher"
	"meow/grabber/pkg/common"
	"meow/grabber/pkg/fingerprint/types"

	"github.com/rs/zerolog/log"
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

func Main(cfg *common.Config) {
	// Setup logging
	common.SetupLogging(cfg.Logging)

	log.Info().
		Str("nats_url", cfg.NATS.URL).
		Str("input_topic", cfg.GetFingerprintInputTopic()).
		Str("output_topic", cfg.GetFingerprintOutputTopic()).
		Int("workers", cfg.Fingerprint.Workers).
		Bool("auto_tune", true).
		Msg("Starting fingerprint service with auto-tuning WorkerPool")

	// Connect to NATS
	nc, natsClosed, err := common.ConnectNATS(cfg.NATS, "fingerprint")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to NATS")
	}
	defer nc.Close()

	log.Info().Str("server", nc.ConnectedUrl()).Msg("Connected to NATS")

	// Create consumer and publisher (using constant topics)
	cons := consumer.NewConsumer(nc, cfg.GetFingerprintInputTopic(), 1000)
	pub := publisher.NewPublisher(nc, cfg.GetFingerprintOutputTopic())

	// Create WorkerPool with auto-tuning (intensity is internal constant: 5)
	poolConfig := grab.DefaultWorkerPoolConfig()
	poolConfig.NumWorkers = cfg.Fingerprint.Workers
	poolConfig.AutoTune = true
	poolConfig.ProbeTimeout = cfg.Fingerprint.ProbeTimeout()
	poolConfig.GlobalTimeout = cfg.Fingerprint.GlobalTimeout()
	poolConfig.Intensity = 5 // Internal constant (was configurable)

	pool, err := grab.NewWorkerPool(poolConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create worker pool")
	}
	defer pool.Close()

	// Start consumer
	if err := cons.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start consumer")
	}
	defer cons.Stop()

	// Channel to signal shutdown
	done := make(chan struct{})

	// Goroutine to feed events to the pool with flood detection
	hostTracker := NewHostTracker(49)

	go func() {
		for {
			select {
			case event, ok := <-cons.Events():
				if !ok {
					return
				}

				// Fast path: skip hosts that SYN-ACK everything
				if hostTracker.ShouldSkip(event.IP) {
					continue
				}

				req := grab.ScanRequest{
					Host:          event.IP,
					Port:          event.Port,
					ProbeTimeout:  cfg.Fingerprint.ProbeTimeout(),
					Intensity:     5, // Internal constant
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

	// Goroutine to process results and publish
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

	// Goroutine to log stats periodically
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
					Msg("Pool stats")
			case <-done:
				return
			}
		}
	}()

	log.Info().Msg("Fingerprint service started with auto-tuning pool")

	// Wait for shutdown signal or NATS connection loss
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
		log.Info().Msg("Shutdown signal received, stopping...")
	case <-natsClosed:
		log.Fatal().Msg("NATS connection lost permanently, exiting")
	}
	close(done)
	cons.Stop()
	// pool.Close() called via defer
	log.Info().Msg("Service stopped")
}

// processResult handles a scan result and publishes it (including failures)
func processResult(result grab.ScanResult, pub *publisher.Publisher) {
	fpEvent := types.FingerprintEvent{
		IP:        result.Host,
		Port:      result.Port,
		Timestamp: time.Now(),
	}

	if result.Error != nil {
		// Fingerprint failed — still publish so datastore knows we tried
		fpEvent.Failed = true
		fpEvent.FailReason = result.Error.Error()

		log.Debug().
			Str("ip", result.Host).
			Int("port", result.Port).
			Err(result.Error).
			Str("timeout_type", result.TimeoutType).
			Msg("Fingerprint failed")

	} else if result.Result == nil {
		// No service detected — still publish so datastore knows we tried
		fpEvent.Failed = true
		fpEvent.FailReason = "no_match"

		log.Debug().
			Str("ip", result.Host).
			Int("port", result.Port).
			Msg("No service detected")

	} else {
		// Success
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

	// Always publish — success or failure
	if err := pub.Publish(fpEvent); err != nil {
		log.Error().
			Str("ip", result.Host).
			Int("port", result.Port).
			Err(err).
			Msg("Failed to publish fingerprint result")
	}
}
