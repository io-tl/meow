package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
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

	// Run PRAGMA optimize to update query planner statistics
	if _, err := db.Exec("PRAGMA optimize"); err != nil {
		log.Warn().Err(err).Msg("PRAGMA optimize failed (non-fatal)")
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
	// ANSI codes matching meow cyber theme
	const (
		reset     = "\x1b[0m"
		bold      = "\x1b[1m"
		dim       = "\x1b[2m"
		cyan      = "\x1b[36m" // --cyber-primary #00d4ff
		blue      = "\x1b[34m" // --accent-primary #4a9eff
		brightCyn = "\x1b[96m" // bright cyan
		brightBlu = "\x1b[94m" // bright blue
		white     = "\x1b[97m"
		yellow    = "\x1b[33m" // --warning
		red       = "\x1b[31m" // --error
		green     = "\x1b[32m" // --success
		magenta   = "\x1b[35m" // --cyber-secondary #ff00ff
	)

	w := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "15:04:05",
		FormatTimestamp: func(i interface{}) string {
			s := fmt.Sprintf("%s", i)
			// Truncate to HH:MM:SS if longer (zerolog may pass full RFC3339)
			if len(s) > 8 {
				s = s[11:19]
			}
			return dim + blue + s + reset
		},
		FormatLevel: func(i interface{}) string {
			level := strings.ToUpper(fmt.Sprintf("%s", i))
			switch level {
			case "DEBUG":
				return dim + cyan + "DBG" + reset
			case "INFO":
				return bold + brightCyn + "INF" + reset
			case "WARN":
				return bold + yellow + "WRN" + reset
			case "ERROR":
				return bold + red + "ERR" + reset
			case "FATAL":
				return bold + red + "FTL" + reset
			default:
				return level
			}
		},
		FormatCaller: func(i interface{}) string {
			caller := fmt.Sprintf("%s", i)
			// Keep path relative to datastore/
			if idx := strings.Index(caller, "datastore/"); idx != -1 {
				caller = caller[idx:]
			}
			return dim + magenta + caller + reset
		},
		FormatMessage: func(i interface{}) string {
			return bold + white + fmt.Sprintf("%s", i) + reset
		},
		FormatFieldName: func(i interface{}) string {
			return brightBlu + fmt.Sprintf("%s", i) + "=" + reset
		},
		FormatFieldValue: func(i interface{}) string {
			return cyan + fmt.Sprintf("%s", i) + reset
		},
	}

	log.Logger = zerolog.New(w).With().Timestamp().Caller().Logger()
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
