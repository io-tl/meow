package modules

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- NNTP ---

func TestScanNNTP_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("200 NNTP Service Ready\r\n"))
		buf := make([]byte, 256)
		conn.Read(buf) // CAPABILITIES
		conn.Write([]byte("101 Capability list:\r\nVERSION 2\r\nREADER\r\nPOST\r\n.\r\n"))
		conn.Read(buf) // QUIT
	})

	mod, ok := Get("nntp")
	if !ok {
		t.Fatal("nntp not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*NNTPResult)
	if result.Banner != "200 NNTP Service Ready" {
		t.Errorf("Banner = %q", result.Banner)
	}
	if len(result.Capabilities) == 0 {
		t.Error("Capabilities empty")
	}
}

func TestNNTP_ModuleRegistered(t *testing.T) {
	_, ok := Get("nntp")
	if !ok {
		t.Fatal("nntp not registered")
	}
}

// --- Rsync ---

func TestScanRsync_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("@RSYNCD: 31.0\n"))
		buf := make([]byte, 256)
		conn.Read(buf) // #list
		conn.Write([]byte("backup\tBackup module\ndata\tData module\n@RSYNCD: EXIT\n"))
	})

	result, err := scanRsync(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "31.0" {
		t.Errorf("Version = %q, want %q", result.Version, "31.0")
	}
	if len(result.Modules) != 2 {
		t.Errorf("Modules = %v, want 2 entries", result.Modules)
	}
}

func TestScanRsync_NoModules(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("@RSYNCD: 30.0\n"))
		buf := make([]byte, 256)
		conn.Read(buf)
		conn.Write([]byte("@RSYNCD: EXIT\n"))
	})

	result, err := scanRsync(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "30.0" {
		t.Errorf("Version = %q", result.Version)
	}
	if len(result.Modules) != 0 {
		t.Errorf("Modules = %v, want empty", result.Modules)
	}
}

func TestRsync_ModuleRegistered(t *testing.T) {
	_, ok := Get("rsync")
	if !ok {
		t.Fatal("rsync not registered")
	}
}

// --- Memcached ---

func TestScanMemcached_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		conn.Read(buf) // stats
		conn.Write([]byte("STAT version 1.6.22\r\nSTAT pid 1234\r\nSTAT uptime 3600\r\nEND\r\n"))
		conn.Read(buf) // quit
	})

	result, err := scanMemcached(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "1.6.22" {
		t.Errorf("Version = %q, want %q", result.Version, "1.6.22")
	}
	if result.Stats["pid"] != "1234" {
		t.Errorf("Stats[pid] = %q", result.Stats["pid"])
	}
	if result.Stats["uptime"] != "3600" {
		t.Errorf("Stats[uptime] = %q", result.Stats["uptime"])
	}
}

func TestScanMemcached_NoResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		conn.Read(buf)
		// Close without response
	})

	result, _ := scanMemcached(host, port, 3*time.Second)
	if result.Error == "" {
		t.Error("expected Error for no response")
	}
}

func TestMemcached_ModuleRegistered(t *testing.T) {
	mod, ok := Get("memcached")
	if !ok {
		t.Fatal("memcached not registered")
	}
	if mod.Name() != "memcached" {
		t.Errorf("Name() = %q", mod.Name())
	}
	_, ok = Get("memcache")
	if !ok {
		t.Fatal("memcache alias not registered")
	}
}

// --- Syslog ---

func TestSyslog_ModuleRegistered(t *testing.T) {
	_, ok := Get("syslog")
	if !ok {
		t.Fatal("syslog not registered")
	}
}

func TestSyslog_ShouldNotEnrich(t *testing.T) {
	if ShouldEnrich("syslog") {
		t.Error("syslog ShouldEnrich = true, want false")
	}
}

// --- IRC ---

func TestScanIRC_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf) // NICK + USER
		conn.Write([]byte(":irc.test 001 scanner :Welcome\r\n"))
		conn.Write([]byte(":irc.test 004 scanner irc.test ircd-2.0 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ\r\n"))
		conn.Write([]byte(":irc.test 375 scanner :- irc.test Message of the Day -\r\n"))
		conn.Write([]byte(":irc.test 372 scanner :- Welcome to the test IRC\r\n"))
		conn.Write([]byte(":irc.test 376 scanner :End of /MOTD command.\r\n"))
	})

	result, err := scanIRC(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "irc" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if len(result.MOTD) == 0 {
		t.Error("MOTD empty")
	}
}

func TestIRC_ModuleRegistered(t *testing.T) {
	_, ok := Get("irc")
	if !ok {
		t.Fatal("irc not registered")
	}
}

// --- NTP (UDP) ---

func TestScanNTP_ValidResponse(t *testing.T) {
	host, port := startTestUDPServer(t, func(conn *net.UDPConn) {
		buf := make([]byte, 48)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil || n < 48 {
			return
		}

		// Build NTP response (48 bytes)
		resp := make([]byte, 48)
		// LI=0, VN=3, Mode=4 (server) = 0x1c
		resp[0] = 0x1c
		// Stratum = 1 (primary)
		resp[1] = 0x01
		// Reference ID
		binary.BigEndian.PutUint32(resp[12:16], 0x47505300) // "GPS\0"
		// Reference timestamp (arbitrary nonzero value)
		binary.BigEndian.PutUint64(resp[16:24], 0xE5D4C3B200000000)

		conn.WriteToUDP(resp, addr)
	})

	result, err := scanNTP(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != 3 {
		t.Errorf("Version = %d, want 3", result.Version)
	}
	if result.Stratum != 1 {
		t.Errorf("Stratum = %d, want 1", result.Stratum)
	}
	if result.ReferenceID != "0x47505300" {
		t.Errorf("ReferenceID = %q", result.ReferenceID)
	}
}

func TestNTP_ModuleRegistered(t *testing.T) {
	_, ok := Get("ntp")
	if !ok {
		t.Fatal("ntp not registered")
	}
}

// --- Git ---

func TestScanGit_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf) // git-upload-pack request
		// Respond with pkt-line format refs
		// "003f" = 63 bytes (including the 4-byte length prefix)
		line1 := "003fabcdef1234567890abcdef1234567890abcdef refs/heads/main\x00multi_ack\n"
		line2 := "003fabcdef1234567890abcdef1234567890abcdef refs/tags/v1.0\n"
		flush := "0000"
		conn.Write([]byte(line1 + line2 + flush))
	})

	mod, ok := Get("git")
	if !ok {
		t.Fatal("git not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*GitResult)
	if result.Version != "detected" {
		t.Errorf("Version = %q", result.Version)
	}
	if result.RefCount == 0 {
		t.Error("RefCount = 0")
	}
}

func TestGit_ModuleRegistered(t *testing.T) {
	_, ok := Get("git")
	if !ok {
		t.Fatal("git not registered")
	}
}
