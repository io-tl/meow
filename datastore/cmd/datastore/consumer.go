package main

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/oschwald/geoip2-golang"
	"github.com/projectdiscovery/cdncheck"
	"github.com/rs/zerolog/log"
	"meow/datastore"
)

// NATS Event Flow:
//
// 1. scan.port.open (Scanner -> Datastore + Grabber Fingerprint)
//    - Scanner detects an open port and publishes the event
//    - Datastore: stores the port in database (passive storage)
//    - Grabber Fingerprint: performs service detection
//
// 2. scan.port.fingerprinted (Grabber Fingerprint -> Datastore + Grabber Enrichment)
//    - Grabber publishes fingerprint results (service, product, version, certificates)
//    - Datastore: stores fingerprint data and certificates
//    - Grabber Enrichment: performs deep service interrogation
//
// 3. scan.port.enriched (Grabber Enrichment -> Datastore)
//    - Grabber publishes enrichment data (HTTP headers, technologies, etc.)
//    - Datastore: stores enrichment data
//
// Important: The datastore is a PASSIVE component - it only consumes and stores.
// It does NOT republish events to avoid duplicates. The grabber services handle
// all active scanning/fingerprinting/enrichment tasks.

type Consumer struct {
	cfg          *Config
	nc           *nats.Conn
	db           *DB
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	subs         []*nats.Subscription
	geoipCity    *geoip2.Reader
	geoipASN     *geoip2.Reader
	cdnCheck     *cdncheck.Client
	scanTracker  *ScannerTracker
	eventFeed    *EventFeed

	// domainIPCount tracks how many distinct IPs have been seen per domain.
	// Used to skip enrichment for domains from widely-shared default certificates.
	domainIPCount   map[string]int
	domainIPCountMu sync.Mutex
}

func newConsumer(cfg *Config, nc *nats.Conn, db *DB, scanTracker *ScannerTracker) (*Consumer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Consumer{
		cfg:           cfg,
		nc:            nc,
		db:            db,
		ctx:           ctx,
		cancel:        cancel,
		subs:          make([]*nats.Subscription, 0),
		domainIPCount: make(map[string]int),
		scanTracker:   scanTracker,
		eventFeed:     NewEventFeed(100),
	}

	c.initGeoIP(cfg)
	c.initCDNCheck()

	return c, nil
}

// initCDNCheck initializes the CDN/Cloud/WAF detection client
func (c *Consumer) initCDNCheck() {
	client, err := cdncheck.NewWithOpts(3, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize CDN check client")
		return
	}
	c.cdnCheck = client
	log.Info().Msg("CDN check initialized")
}

// loadGeoIPDB loads a GeoIP database from a file path or embedded data.
// Returns the reader and source description ("file", "embedded", or "disabled").
func loadGeoIPDB(name, filePath string, embeddedData []byte) (*geoip2.Reader, string) {
	if filePath != "" {
		reader, err := geoip2.Open(filePath)
		if err != nil {
			log.Error().Err(err).Str("path", filePath).Msgf("Failed to open GeoIP %s database from file", name)
			return nil, "disabled"
		}
		return reader, "file"
	}
	if len(embeddedData) > 0 {
		reader, err := geoip2.FromBytes(embeddedData)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to load embedded GeoIP %s database", name)
			return nil, "disabled"
		}
		return reader, "embedded"
	}
	log.Warn().Msgf("GeoIP %s not available (no file, no embedded data)", name)
	return nil, "disabled"
}

// initGeoIP initializes GeoIP databases from file paths or embedded data
func (c *Consumer) initGeoIP(cfg *Config) {
	var citySource, asnSource string
	c.geoipCity, citySource = loadGeoIPDB("City", cfg.GeoIPCityPath, datastore.EmbeddedGeoIPCity)
	c.geoipASN, asnSource = loadGeoIPDB("ASN", cfg.GeoIPASNPath, datastore.EmbeddedGeoIPASN)

	log.Info().
		Str("city", citySource).
		Str("asn", asnSource).
		Msg("GeoIP loaded")
}

func (c *Consumer) Start() error {
	log.Info().Msg("Starting datastore consumer...")

	// Subscribe to all topics
	topics := []struct {
		topic   string
		handler nats.MsgHandler
	}{
		{TopicOpenPort, c.handleOpenPort},
		{TopicFingerprinted, c.handleFingerprinted},
		{TopicEnriched, c.handleEnriched},
	}

	for _, t := range topics {
		// Always use queue subscription to prevent duplicates
		sub, err := c.nc.QueueSubscribe(t.topic, c.cfg.QueueGroup, t.handler)
		if err != nil {
			return err
		}

		log.Info().
			Str("topic", t.topic).
			Str("queue_group", c.cfg.QueueGroup).
			Msg("Subscribed with LB queue group")

		c.subs = append(c.subs, sub)
	}

	// Subscribe to heartbeats without queue group (every datastore instance needs all heartbeats)
	hbSub, err := c.nc.Subscribe(TopicHeartbeat, c.handleHeartbeat)
	if err != nil {
		return err
	}
	log.Info().Str("topic", TopicHeartbeat).Msg("Subscribed to scanner heartbeats")
	c.subs = append(c.subs, hbSub)

	return nil
}

func (c *Consumer) handleHeartbeat(msg *nats.Msg) {
	var hb ScannerHeartbeat
	if err := json.Unmarshal(msg.Data, &hb); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal scanner heartbeat")
		return
	}
	c.scanTracker.UpdateHeartbeat(&hb)
}

func (c *Consumer) Stop() {
	log.Info().Msg("Stopping consumer...")
	c.cancel()
	for _, sub := range c.subs {
		sub.Unsubscribe()
	}
	c.wg.Wait()
}

