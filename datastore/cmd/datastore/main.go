package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const version = "0.1"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			printUsage()
			return
		case "-v", "--version", "version":
			fmt.Printf("datastore v%s\n", version)
			return
		}
	}

	cfg := loadConfig()
	setupLogging(cfg.Verbose)

	log.Info().Msg("Meow datastore service starting...")

	db, err := initDB(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer db.Close()

	if err := runMigrations(db); err != nil {
		log.Fatal().Err(err).Msg("Failed to run migrations")
	}

	nc, ns, err := initNATS(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize NATS")
	}
	defer nc.Close()
	if ns != nil {
		defer ns.Shutdown()
	}

	scanTracker := NewScannerTracker()

	consumer, err := newConsumer(cfg, nc, db, scanTracker)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize consumer")
	}

	if err := consumer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start consumer")
	}

	if cfg.EnableAPI {
		if cfg.APIPassword != "" {
			log.Info().Msg("API password protection enabled")
		}
		go startAPI(cfg, db, nc, ns, scanTracker, consumer.eventFeed)
	}

	awaitShutdown()
	consumer.Stop()
}

func setupLogging(verbose bool) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func awaitShutdown() {
	log.Info().Msg("Datastore service running. Press Ctrl+C to stop.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	log.Info().Msg("Shutting down...")
}

