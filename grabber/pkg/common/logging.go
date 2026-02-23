package common

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// SetupLogging configure le logger zerolog
func SetupLogging(cfg LoggingConfig) {
	// Configure time format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set log level
	switch cfg.Level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Set log format
	if cfg.Format == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Add caller information in debug mode
	if cfg.Level == "debug" {
		log.Logger = log.With().Caller().Logger()
	}
}
