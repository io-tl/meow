package modules

import (
	"net"
	"testing"
	"time"
)

func TestScanLDAP_ValidSearchResult(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Read search request
		buf := make([]byte, 1024)
		conn.Read(buf)

		// Build minimal BER-encoded SearchResultEntry for rootDSE
		// SEQUENCE {
		//   INTEGER messageID=1
		//   SearchResultEntry (0x64) {
		//     OCTET STRING "" (empty DN)
		//     SEQUENCE {
		//       SEQUENCE { OCTET STRING "supportedLDAPVersion", SET { OCTET STRING "3" } }
		//       SEQUENCE { OCTET STRING "namingContexts", SET { OCTET STRING "DC=test,DC=local" } }
		//     }
		//   }
		// }
		// Build attribute: supportedLDAPVersion = ["3"]
		attr1Name := []byte("supportedLDAPVersion")
		attr1Val := []byte("3")
		attr1ValSet := append([]byte{0x04, byte(len(attr1Val))}, attr1Val...)
		attr1Set := append([]byte{0x31, byte(len(attr1ValSet))}, attr1ValSet...)
		attr1NameEnc := append([]byte{0x04, byte(len(attr1Name))}, attr1Name...)
		attr1Seq := append([]byte{0x30, byte(len(attr1NameEnc) + len(attr1Set))}, append(attr1NameEnc, attr1Set...)...)

		// Build attribute: namingContexts = ["DC=test,DC=local"]
		attr2Name := []byte("namingContexts")
		attr2Val := []byte("DC=test,DC=local")
		attr2ValSet := append([]byte{0x04, byte(len(attr2Val))}, attr2Val...)
		attr2Set := append([]byte{0x31, byte(len(attr2ValSet))}, attr2ValSet...)
		attr2NameEnc := append([]byte{0x04, byte(len(attr2Name))}, attr2Name...)
		attr2Seq := append([]byte{0x30, byte(len(attr2NameEnc) + len(attr2Set))}, append(attr2NameEnc, attr2Set...)...)

		// Attributes sequence
		attrsContent := append(attr1Seq, attr2Seq...)
		attrsSeq := append([]byte{0x30, byte(len(attrsContent))}, attrsContent...)

		// Empty DN
		dn := []byte{0x04, 0x00}

		// SearchResultEntry content
		entryContent := append(dn, attrsSeq...)
		entry := append([]byte{0x64, byte(len(entryContent))}, entryContent...)

		// Message ID
		msgID := []byte{0x02, 0x01, 0x01}

		// Full message
		msgContent := append(msgID, entry...)
		msg := append([]byte{0x30, byte(len(msgContent))}, msgContent...)

		conn.Write(msg)

		// Read unbind and ignore
		conn.Read(buf)
	})

	result, err := scanLDAP(host, port, false, "", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "ldap" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "ldap")
	}
	if len(result.SupportedLDAPVersion) == 0 {
		t.Error("SupportedLDAPVersion empty")
	}
	if len(result.NamingContexts) == 0 {
		t.Error("NamingContexts empty")
	}
}

func TestScanLDAP_EmptyResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 1024)
		conn.Read(buf)
		// Send too-short response
		conn.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	})

	result, _ := scanLDAP(host, port, false, "", 3*time.Second)
	if result.Protocol != "ldap" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

func TestDecodeLDAPLength_Short(t *testing.T) {
	length, bytesRead := decodeLDAPLength([]byte{0x05})
	if length != 5 || bytesRead != 1 {
		t.Errorf("decodeLDAPLength(0x05) = (%d, %d), want (5, 1)", length, bytesRead)
	}
}

func TestDecodeLDAPLength_Long(t *testing.T) {
	// 0x81 0x80 = 128 bytes
	length, bytesRead := decodeLDAPLength([]byte{0x81, 0x80})
	if length != 128 || bytesRead != 2 {
		t.Errorf("decodeLDAPLength(0x81,0x80) = (%d, %d), want (128, 2)", length, bytesRead)
	}
}

func TestDecodeLDAPLength_Empty(t *testing.T) {
	length, bytesRead := decodeLDAPLength([]byte{})
	if length != 0 || bytesRead != 0 {
		t.Errorf("decodeLDAPLength([]) = (%d, %d), want (0, 0)", length, bytesRead)
	}
}

func TestExtractDomainAndSite(t *testing.T) {
	result := &LDAPResult{
		RootDSE:              make(map[string][]string),
		DefaultNamingContext: "DC=example,DC=com",
		ServerName:           "CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com",
	}
	extractDomainAndSite(result)
	if result.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", result.Domain, "example.com")
	}
}

func TestLDAP_ModulesRegistered(t *testing.T) {
	_, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap not registered")
	}
	_, ok = Get("ldaps")
	if !ok {
		t.Fatal("ldaps not registered")
	}
}
