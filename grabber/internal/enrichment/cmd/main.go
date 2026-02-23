package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"meow/grabber/internal/enrichment/enricher"
	"meow/grabber/pkg/common"

	// Import all modules to register them
	_ "meow/grabber/pkg/enrichment/modules"
)

// Main starts the enrichment NATS service.
func Main(cfg *common.Config) {
	// Setup logging
	common.SetupLogging(cfg.Logging)

	log.Info().
		Str("nats_url", cfg.NATS.URL).
		Str("input_topic", cfg.GetEnrichmentInputTopic()).
		Str("enrich_request_topic", cfg.GetEnrichmentRequestTopic()).
		Str("output_topic", cfg.GetEnrichmentOutputTopic()).
		Int("workers", cfg.Enrichment.Workers).
		Msg("Starting enrichment service")

	// Connect to NATS
	nc, natsClosed, err := common.ConnectNATS(cfg.NATS, "enrichment")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to NATS")
	}
	defer nc.Close()

	log.Info().Str("server", nc.ConnectedUrl()).Msg("Connected to NATS")

	// Create enricher
	enricherCfg := &enricher.Config{
		Workers:              cfg.Enrichment.Workers,
		QueueSize:            1000,
		NATSConn:             nc,
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

	// Start enricher
	if err := e.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start enricher")
	}

	log.Info().Msg("Enrichment service running. Press Ctrl+C to stop.")

	// Wait for interrupt signal or NATS connection loss
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
		log.Info().Msg("Shutting down...")
	case <-natsClosed:
		log.Error().Msg("NATS connection lost permanently, exiting")
	}

	// Stop enricher gracefully
	e.Stop()

	// Print final stats
	stats := e.GetStats()
	log.Info().
		Interface("stats", stats).
		Msg("Final statistics")

	log.Info().Msg("Shutdown complete")
}
