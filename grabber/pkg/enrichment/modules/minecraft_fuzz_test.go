package modules

import (
	"strings"
	"testing"
)

func FuzzBuildMinecraftHandshake(f *testing.F) {
	f.Add("localhost", uint16(25565))
	f.Add("", uint16(0))
	f.Add(strings.Repeat("a", 300), uint16(65535))
	f.Add("192.168.1.1", uint16(1))
	f.Add("example.com", uint16(25565))
	f.Fuzz(func(t *testing.T, host string, port uint16) {
		result := buildMinecraftHandshake(host, port)
		if len(result) == 0 {
			t.Error("empty handshake")
		}
	})
}
