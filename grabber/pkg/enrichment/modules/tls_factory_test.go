package modules

import (
	"testing"
	"time"
)

func TestRegisterPlainAndTLS_RegistersBothModules(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	RegisterPlainAndTLS(
		"testplain", []string{"tp"},
		"testtls", []string{"ttls"},
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return map[string]interface{}{"tls": useTLS, "domain": domain}, nil
		},
	)

	plain, ok := Get("testplain")
	if !ok {
		t.Fatal("plain module not registered")
	}
	tls, ok := Get("testtls")
	if !ok {
		t.Fatal("TLS module not registered")
	}
	if plain.Name() != "testplain" {
		t.Errorf("plain Name() = %q", plain.Name())
	}
	if tls.Name() != "testtls" {
		t.Errorf("TLS Name() = %q", tls.Name())
	}
}

func TestPlainTLSModule_Scan_PlainPassesUseTLSFalse(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	var capturedUseTLS bool
	RegisterPlainAndTLS(
		"p_scan", nil, "t_scan", nil,
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			capturedUseTLS = useTLS
			return "ok", nil
		},
	)

	mod, _ := Get("p_scan")
	mod.Scan("1.2.3.4", 80)
	if capturedUseTLS {
		t.Error("plain module should pass useTLS=false")
	}
}

func TestPlainTLSModule_Scan_TLSPassesUseTLSTrue(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	var capturedUseTLS bool
	RegisterPlainAndTLS(
		"p_tls", nil, "t_tls", nil,
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			capturedUseTLS = useTLS
			return "ok", nil
		},
	)

	mod, _ := Get("t_tls")
	mod.Scan("1.2.3.4", 993)
	if !capturedUseTLS {
		t.Error("TLS module should pass useTLS=true")
	}
}

func TestPlainTLSModule_ScanWithSNI_PassesDomain(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	var capturedDomain string
	var capturedUseTLS bool
	RegisterPlainAndTLS(
		"p_sni", nil, "t_sni", nil,
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			capturedDomain = domain
			capturedUseTLS = useTLS
			return "sni-result", nil
		},
	)

	mod, _ := Get("t_sni")
	result, err := mod.ScanWithSNI("1.2.3.4", 993, "mail.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedDomain != "mail.example.com" {
		t.Errorf("domain = %q, want %q", capturedDomain, "mail.example.com")
	}
	if !capturedUseTLS {
		t.Error("TLS module ScanWithSNI should pass useTLS=true")
	}
	if result != "sni-result" {
		t.Errorf("result = %v, want %q", result, "sni-result")
	}
}

func TestPlainTLSModule_Aliases(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	RegisterPlainAndTLS(
		"pop3_test", []string{"pop-3"},
		"pop3s_test", []string{"pop3-ssl"},
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return nil, nil
		},
	)

	if _, ok := Get("pop-3"); !ok {
		t.Error("plain alias not registered")
	}
	if _, ok := Get("pop3-ssl"); !ok {
		t.Error("TLS alias not registered")
	}
}

func TestPlainTLSModule_ShouldEnrich(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	RegisterPlainAndTLS(
		"se_plain", nil, "se_tls", nil,
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return nil, nil
		},
	)

	if !ShouldEnrich("se_plain") {
		t.Error("plain module should be enrichable")
	}
	if !ShouldEnrich("se_tls") {
		t.Error("TLS module should be enrichable")
	}
}
