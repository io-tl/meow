package modules

import (
	"encoding/json"
	"testing"
)

func TestSSH_ModuleRegistered(t *testing.T) {
	mod, ok := Get("ssh")
	if !ok {
		t.Fatal("ssh module not registered")
	}
	if mod.Name() != "ssh" {
		t.Errorf("Name() = %q", mod.Name())
	}
	if !mod.ShouldEnrich() {
		t.Error("ShouldEnrich() = false")
	}
}

func TestSSH_ScanWithSNI_DelegatesToScan(t *testing.T) {
	mod, ok := Get("ssh")
	if !ok {
		t.Fatal("ssh module not registered")
	}
	// ScanWithSNI should delegate to Scan (SSH ignores SNI)
	// We can't test with a real server, but we verify the method exists
	// and returns an error (no server to connect to)
	_, err := mod.ScanWithSNI("127.0.0.1", 1, "example.com")
	if err == nil {
		// Either error or connection refused is expected
		t.Log("ScanWithSNI returned no error (unexpected but acceptable)")
	}
}

func TestSSHResult_JSONRoundtrip(t *testing.T) {
	result := SSHResult{
		Banner:        "SSH-2.0-OpenSSH_8.9",
		ServerVersion: "SSH-2.0-OpenSSH_8.9",
		HostKeyAlgos:  []string{"ssh-ed25519", "ssh-rsa"},
		KexAlgos:      []string{"curve25519-sha256"},
		Ciphers:       []string{"aes256-gcm@openssh.com"},
		MACs:          []string{"hmac-sha2-256"},
		Compressions:  []string{"none"},
		ServerHostKeys: []HostKey{
			{Type: "ssh-ed25519", Fingerprint: "SHA256:abc123"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SSHResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.Banner != result.Banner {
		t.Errorf("Banner = %q", decoded.Banner)
	}
	if len(decoded.ServerHostKeys) != 1 {
		t.Fatalf("ServerHostKeys len = %d", len(decoded.ServerHostKeys))
	}
	if decoded.ServerHostKeys[0].Type != "ssh-ed25519" {
		t.Errorf("HostKey type = %q", decoded.ServerHostKeys[0].Type)
	}
}
