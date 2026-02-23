package modules

import (
	"testing"
)

func TestAllModulesRegistered(t *testing.T) {
	expected := []string{
		"ssh", "ftp", "smtp", "pop3", "pop3s", "imap", "imaps",
		"ldap", "ldaps", "mysql", "postgres", "mongodb", "redis",
		"http", "telnet", "vnc", "rdp", "dns", "banner", "minecraft",
		"oracle", "mssql", "cassandra", "memcached", "elasticsearch",
		"couchdb", "influxdb", "ipp", "icecast", "amqp", "xmpp",
		"irc", "mumble", "teamspeak", "modbus", "ntp", "coap",
		"rsync", "tftp", "nfs", "upnp", "sip", "ldp", "rpc",
		"rtsp", "git", "syslog", "nntp", "lpd", "mpd", "pptp",
		"afp", "ajp13", "x11", "openvpn", "smb", "netbios", "snmp",
		"mqtt",
	}
	for _, name := range expected {
		if _, ok := Get(name); !ok {
			t.Errorf("module %q not registered", name)
		}
	}
}

func TestNoModulePanicsOnInit(t *testing.T) {
	modules := GetAll()
	if len(modules) < 50 {
		t.Errorf("expected at least 50 modules, got %d", len(modules))
	}
}

func TestListServicesNotEmpty(t *testing.T) {
	services := ListServices()
	if len(services) < 50 {
		t.Errorf("ListServices() returned %d entries, want at least 50", len(services))
	}
}
