package main

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"meow/datastore"
)

func startAPI(cfg *Config, db *DB, nc *nats.Conn, ns *natsserver.Server, scanTracker *ScannerTracker, eventFeed *EventFeed) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(zerologGinMiddleware())

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, X-API-Key, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// No-cache middleware for HTML and static files
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Writer.Header().Set("Pragma", "no-cache")
		c.Writer.Header().Set("Expires", "0")
		c.Next()
	})

	api := &API{db: db, nc: nc, ns: ns, scanTracker: scanTracker, eventFeed: eventFeed, verbose: cfg.Debug}
	api.responseCache = newAPIResponseCache()

	// Serve static files from embedded filesystem
	staticFS, _ := fs.Sub(datastore.StaticFS, "web/static")
	r.StaticFS("/static", http.FS(staticFS))

	// Serve favicon at root
	r.GET("/favicon.svg", func(c *gin.Context) {
		c.FileFromFS("web/static/favicon.svg", http.FS(datastore.StaticFS))
	})
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.FileFromFS("web/static/favicon.svg", http.FS(datastore.StaticFS))
	})

	// Load templates from embedded filesystem
	tmpl := template.Must(template.ParseFS(datastore.TemplatesFS, "web/templates/partials/*.html", "web/templates/*.html"))
	r.SetHTMLTemplate(tmpl)

	// Web interface routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/dashboard")
	})

	r.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"PageTitle":   "Dashboard",
			"Breadcrumb":  "Dashboard",
			"ActivePage":  "dashboard",
			"LoadingText": "Loading...",
			"ExtraCSS":    []string{"/static/css/dashboard.css"},
			"HeadScripts": []string{"/static/vendor/chart.min.js"},
			"FootScripts": []string{"/static/js/dashboard.js"},
		})
	})

	r.GET("/hosts", func(c *gin.Context) {
		c.HTML(http.StatusOK, "hosts.html", gin.H{
			"PageTitle":   "Hosts",
			"Breadcrumb":  "Network Intelligence",
			"ActivePage":  "hosts",
			"LoadingText": "Loading hosts...",
			"ExtraCSS":    []string{"/static/css/dashboard.css", "/static/css/hosts.css"},
			"FootScripts": []string{"/static/js/service_renderers.js", "/static/js/hosts_search.js"},
		})
	})

	r.GET("/certificates", func(c *gin.Context) {
		c.HTML(http.StatusOK, "certificates.html", gin.H{
			"PageTitle":   "Certificates",
			"Breadcrumb":  "TLS & X.509",
			"ActivePage":  "certificates",
			"LoadingText": "Loading certificates...",
			"ExtraCSS":    []string{"/static/css/certificates.css"},
			"FootScripts": []string{"/static/js/certificates.js"},
		})
	})

	r.GET("/domains", func(c *gin.Context) {
		c.HTML(http.StatusOK, "domains.html", gin.H{
			"PageTitle":   "Domains",
			"Breadcrumb":  "Domain Intelligence",
			"ActivePage":  "domains",
			"LoadingText": "Loading domains...",
			"ExtraCSS":    []string{"/static/css/domains.css"},
			"FootScripts": []string{"/static/js/domains.js"},
		})
	})

	r.GET("/map", func(c *gin.Context) {
		c.HTML(http.StatusOK, "map.html", gin.H{
			"PageTitle":   "Map",
			"Breadcrumb":  "Geographic Distribution",
			"ActivePage":  "map",
			"LoadingText": "Loading map data...",
			"ExtraCSS":    []string{"/static/css/map.css", "/static/vendor/leaflet.css"},
			"HeadScripts": []string{"/static/vendor/leaflet.js"},
			"FootScripts": []string{"/static/js/map.js"},
		})
	})

	r.GET("/query", func(c *gin.Context) {
		c.HTML(http.StatusOK, "query.html", gin.H{
			"PageTitle":   "Query",
			"Breadcrumb":  "MeowQL Search",
			"ActivePage":  "query",
			"LoadingText": "Loading...",
			"ExtraCSS":    []string{"/static/css/hosts.css", "/static/css/query.css"},
			"FootScripts": []string{"/static/js/service_renderers.js", "/static/js/query.js"},
		})
	})

	r.GET("/docs", func(c *gin.Context) {
		c.HTML(http.StatusOK, "docs.html", gin.H{
			"PageTitle":   "Documentation",
			"Breadcrumb":  "API & Reference",
			"ActivePage":  "docs",
			"LoadingText": "Loading...",
			"ExtraCSS":    []string{"/static/css/docs.css"},
			"FootScripts": []string{"/static/js/docs.js"},
		})
	})

	r.GET("/scan", func(c *gin.Context) {
		c.HTML(http.StatusOK, "scan.html", gin.H{
			"PageTitle":   "Scan",
			"Breadcrumb":  "On-Demand Scanner",
			"ActivePage":  "scan",
			"LoadingText": "Loading...",
			"ExtraCSS":    []string{"/static/css/scan.css"},
			"FootScripts": []string{"/static/js/scan.js"},
		})
	})

	r.GET("/status", func(c *gin.Context) {
		c.HTML(http.StatusOK, "debug.html", gin.H{
			"PageTitle":   "Status",
			"Breadcrumb":  "System Monitoring",
			"ActivePage":  "status",
			"LoadingText": "Loading...",
			"ExtraCSS":    []string{"/static/css/debug.css"},
			"FootScripts": []string{"/static/js/debug.js"},
		})
	})

	r.GET("/mobile", func(c *gin.Context) {
		c.HTML(http.StatusOK, "mobile.html", gin.H{
			"PageTitle":   "Mobile Dashboard",
			"ActivePage":  "mobile",
			"HeadScripts": []string{"/static/vendor/chart.min.js"},
			"FootScripts": []string{"/static/js/mobile.js"},
		})
	})

	r.GET("/mobile/hosts", func(c *gin.Context) {
		c.HTML(http.StatusOK, "mobile_hosts.html", gin.H{
			"PageTitle":   "Hosts",
			"ActivePage":  "mobile_hosts",
			"ExtraCSS":    []string{"/static/css/mobile_hosts.css"},
			"FootScripts": []string{"/static/js/mobile_hosts.js"},
		})
	})

	r.GET("/mobile/query", func(c *gin.Context) {
		c.HTML(http.StatusOK, "mobile_query.html", gin.H{
			"PageTitle":   "Query",
			"ActivePage":  "mobile_query",
			"ExtraCSS":    []string{"/static/css/mobile_query.css"},
			"FootScripts": []string{"/static/js/mobile_query.js"},
		})
	})

	r.GET("/mobile/scan", func(c *gin.Context) {
		c.HTML(http.StatusOK, "mobile_scan.html", gin.H{
			"PageTitle":   "Scan",
			"ActivePage":  "mobile_scan",
			"ExtraCSS":    []string{"/static/css/mobile_scan.css"},
			"FootScripts": []string{"/static/js/mobile_scan.js"},
		})
	})

	// Shell RC (no auth — bootstrap script only, no data)
	r.GET("/api/rc", api.getShellRC)

	// API routes group (protected by API key when -api-pass is set)
	apiGroup := r.Group("/api")
	apiGroup.Use(apiAuthMiddleware(cfg.APIPassword))

	// MCP (Model Context Protocol) — Streamable HTTP, same auth as /api/*
	mcpHTTP := newMCPHandler(db, nc, scanTracker)
	mcpGroup := r.Group("/mcp")
	mcpGroup.Use(apiAuthMiddleware(cfg.APIPassword))
	mcpGroup.Any("", gin.WrapH(mcpHTTP))

	// Cyberpunk interface endpoints
	apiGroup.GET("/hosts", api.searchHosts)
	apiGroup.GET("/hosts/:ip", api.getHostDetails)
	apiGroup.GET("/services", api.searchServices)
	apiGroup.GET("/certificates", api.searchCertificates)
	apiGroup.GET("/certificates/:fingerprint", api.getCertificateDetail)
	apiGroup.GET("/certificates/:fingerprint/hosts", api.getCertificateHosts)
	apiGroup.GET("/stats/dashboard", api.getDashboardStats)
	apiGroup.GET("/stats/countries", api.getCountryStats)
	apiGroup.GET("/stats/services", api.getServiceStats)
	apiGroup.GET("/stats/cloud", api.getCloudStats)
	apiGroup.GET("/stats/technologies", api.getTechnologyStats)
	apiGroup.GET("/stats/products", api.getProductStats)

	// Domain endpoints
	apiGroup.GET("/domains", api.searchDomains)
	apiGroup.GET("/domains/stats", api.getDomainStats)
	apiGroup.GET("/domains/:domain/services", api.getDomainServices)

	// Shared preview body endpoint (used by Domains + Hosts pages)
	apiGroup.GET("/body", api.getPreviewBody)

	// MeowQL search endpoints
	apiGroup.GET("/search", api.searchQuery)
	apiGroup.GET("/search/services", api.searchQueryServices)
	apiGroup.GET("/autocomplete", api.getAutocomplete)

	// Advanced endpoints
	apiGroup.GET("/facets", api.getFacets)
	apiGroup.GET("/geomap", api.getGeoMap)
	apiGroup.GET("/geomap/country/:code", api.getGeoMapCountryDetails)
	apiGroup.GET("/export", api.exportData)

	// Scan endpoints
	apiGroup.GET("/scanners", api.getScanners)
	apiGroup.POST("/scan", api.submitScan)
	apiGroup.GET("/events/recent", api.getRecentEvents)

	// Tools endpoints
	apiGroup.GET("/tools/dns", api.dnsResolve)

	// Debug endpoints
	apiGroup.GET("/debug/stats", api.getDebugStats)

	addr := fmt.Sprintf("%s:%d", cfg.APIBind, cfg.APIPort)
	log.Info().Str("addr", addr).Msg("Starting API server...")

	if err := r.Run(addr); err != nil {
		log.Error().Err(err).Msg("API server failed")
	}
}

type API struct {
	db            *DB
	nc            *nats.Conn
	ns            *natsserver.Server
	scanTracker   *ScannerTracker
	eventFeed     *EventFeed
	verbose       bool
	responseCache *apiResponseCache
}

func zerologGinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		evt := log.Info()
		status := c.Writer.Status()
		if status >= 500 {
			evt = log.Error()
		} else if status >= 400 {
			evt = log.Warn()
		}

		evt.Int("status", status).
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Str("client_ip", c.ClientIP()).
			Dur("latency", latency)

		if c.Request.URL.RawQuery != "" {
			evt.Str("query", c.Request.URL.RawQuery)
		}

		if len(c.Errors) > 0 {
			evt.Str("errors", c.Errors.ByType(gin.ErrorTypePrivate).String())
		}

		evt.Msg("HTTP request")
	}
}

func apiAuthMiddleware(password string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if password == "" {
			c.Next()
			return
		}
		// Accept API key from header or query parameter (for window.open exports)
		if c.GetHeader("X-API-Key") == password || c.Query("key") == password {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
	}
}
