package modules

import "time"

// ServiceModule represents an enrichment module for a specific service/protocol
type ServiceModule interface {
	// Name returns the primary name of the service
	Name() string

	// Aliases returns possible aliases for this service (for matching)
	Aliases() []string

	// Scan performs the enrichment scan
	// Returns enriched data as interface{} (can be marshaled to JSON)
	Scan(ip string, port int) (interface{}, error)

	// ScanWithSNI performs enrichment with SNI support (optional, for HTTPS)
	ScanWithSNI(ip string, port int, domain string) (interface{}, error)

	// ShouldEnrich indicates if this service should be enriched
	// (false = skip silently in enrichment pool)
	ShouldEnrich() bool

	// DefaultTimeout returns the default timeout for this service
	DefaultTimeout() time.Duration
}

// BaseModule provides default implementation for common methods
type BaseModule struct {
	name           string
	aliases        []string
	shouldEnrich   bool
	defaultTimeout time.Duration
}

func (b *BaseModule) Name() string {
	return b.name
}

func (b *BaseModule) Aliases() []string {
	return b.aliases
}

func (b *BaseModule) ShouldEnrich() bool {
	return b.shouldEnrich
}

func (b *BaseModule) DefaultTimeout() time.Duration {
	if b.defaultTimeout == 0 {
		return 15 * time.Second
	}
	return b.defaultTimeout
}

// ScanWithSNI provides a default implementation (fallback to regular Scan)
func (b *BaseModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	// Default: ignore SNI and use regular scan
	// Modules can override this method if they support SNI
	return nil, nil
}

// NewBaseModule creates a BaseModule with the given parameters
func NewBaseModule(name string, aliases []string, shouldEnrich bool, timeout time.Duration) BaseModule {
	return BaseModule{
		name:           name,
		aliases:        aliases,
		shouldEnrich:   shouldEnrich,
		defaultTimeout: timeout,
	}
}
