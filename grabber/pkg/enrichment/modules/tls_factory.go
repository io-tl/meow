package modules

import "time"

// PlainTLSModule wraps a scan function as a ServiceModule (plain or TLS).
type PlainTLSModule struct {
	BaseModule
	useTLS bool
	scanFn func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error)
}

func (m *PlainTLSModule) Scan(ip string, port int) (interface{}, error) {
	return m.scanFn(ip, port, m.useTLS, "", m.DefaultTimeout())
}

func (m *PlainTLSModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.scanFn(ip, port, m.useTLS, domain, m.DefaultTimeout())
}

// RegisterPlainAndTLS registers both a plain and TLS variant of a protocol module.
func RegisterPlainAndTLS(
	plainName string, plainAliases []string,
	tlsName string, tlsAliases []string,
	shouldEnrich bool, timeout time.Duration,
	scanFn func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error),
) {
	Register(&PlainTLSModule{
		BaseModule: NewBaseModule(plainName, plainAliases, shouldEnrich, timeout),
		useTLS:     false,
		scanFn:     scanFn,
	})
	Register(&PlainTLSModule{
		BaseModule: NewBaseModule(tlsName, tlsAliases, shouldEnrich, timeout),
		useTLS:     true,
		scanFn:     scanFn,
	})
}
