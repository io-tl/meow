package grab

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JARM fingerprinting implementation
// Based on https://github.com/salesforce/jarm

// probeConfig represents a JARM probe configuration
type probeConfig struct {
	version  uint16
	ciphers  string
	order    string
	grease   bool
	alpn     string
	v13mode  string
	extOrder string
}

// getProbes returns the 10 standard JARM probes
func getProbes() []probeConfig {
	return []probeConfig{
		{tls.VersionTLS12, "ALL", "FORWARD", false, "ALPN", "1.2_SUPPORT", "REVERSE"},
		{tls.VersionTLS12, "ALL", "REVERSE", false, "ALPN", "1.2_SUPPORT", "FORWARD"},
		{tls.VersionTLS12, "ALL", "TOP_HALF", false, "NO_SUPPORT", "NO_SUPPORT", "FORWARD"},
		{tls.VersionTLS12, "ALL", "BOTTOM_HALF", false, "RARE_ALPN", "NO_SUPPORT", "FORWARD"},
		{tls.VersionTLS12, "ALL", "MIDDLE_OUT", true, "RARE_ALPN", "NO_SUPPORT", "REVERSE"},
		{tls.VersionTLS11, "ALL", "FORWARD", false, "ALPN", "NO_SUPPORT", "FORWARD"},
		{tls.VersionTLS13, "ALL", "FORWARD", false, "ALPN", "1.3_SUPPORT", "REVERSE"},
		{tls.VersionTLS13, "ALL", "REVERSE", false, "ALPN", "1.3_SUPPORT", "FORWARD"},
		{tls.VersionTLS13, "NO1.3", "FORWARD", false, "ALPN", "1.3_SUPPORT", "FORWARD"},
		{tls.VersionTLS13, "ALL", "MIDDLE_OUT", true, "ALPN", "1.3_SUPPORT", "REVERSE"},
	}
}

// calculateJARMHash performs JARM fingerprinting with parallel probes
func calculateJARMHash(host string, port uint) string {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover from panics
		}
	}()

	address := fmt.Sprintf("%s:%d", host, port)
	probes := getProbes()
	results := make([]string, len(probes))

	// Run all 10 probes in parallel
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(idx int, p probeConfig) {
			defer wg.Done()
			packet := buildProbe(host, p)
			results[idx] = sendProbe(address, packet, p)
		}(i, probe)
	}
	wg.Wait()

	return rawToJARM(strings.Join(results, ","))
}

// buildProbe constructs a ClientHello packet
func buildProbe(hostname string, p probeConfig) []byte {
	payload := []byte{0x16}
	hello := []byte{}

	// TLS record version
	switch p.version {
	case tls.VersionTLS13:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x03)
	case tls.VersionTLS12:
		payload = append(payload, 0x03, 0x03)
		hello = append(hello, 0x03, 0x03)
	case tls.VersionTLS11:
		payload = append(payload, 0x03, 0x02)
		hello = append(hello, 0x03, 0x02)
	default:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x01)
	}

	// Random bytes and session ID
	hello = append(hello, randBytes(32)...)
	sessionID := randBytes(32)
	hello = append(hello, byte(len(sessionID)))
	hello = append(hello, sessionID...)

	// Cipher suites
	ciphers := getCiphers(p)
	hello = append(hello, uint16Bytes(len(ciphers))...)
	hello = append(hello, ciphers...)

	// Compression methods
	hello = append(hello, 0x01, 0x00)

	// Extensions
	hello = append(hello, getExtensions(hostname, p)...)

	// Handshake header
	handshake := []byte{0x01, 0x00}
	handshake = append(handshake, uint16Bytes(len(hello))...)
	handshake = append(handshake, hello...)

	// Final payload
	payload = append(payload, uint16Bytes(len(handshake))...)
	payload = append(payload, handshake...)

	return payload
}

// getCiphers returns cipher suite bytes
func getCiphers(p probeConfig) []byte {
	var cipherList [][]byte

	if p.ciphers == "ALL" {
		cipherList = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0x13, 0x02}, {0x13, 0x01},
			{0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28},
			{0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04},
			{0x13, 0x03}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0},
			{0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba},
			{0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	} else {
		cipherList = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0xcc, 0x14}, {0xc0, 0x07},
			{0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60},
			{0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f},
			{0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1},
			{0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	}

	cipherList = reorderCiphers(cipherList, p.order)
	if p.grease {
		cipherList = append([][]byte{randomGrease()}, cipherList...)
	}

	result := []byte{}
	for _, c := range cipherList {
		result = append(result, c...)
	}
	return result
}

// reorderCiphers reorders cipher list based on strategy
func reorderCiphers(ciphers [][]byte, order string) [][]byte {
	n := len(ciphers)
	switch order {
	case "REVERSE":
		result := make([][]byte, n)
		for i := 0; i < n; i++ {
			result[i] = ciphers[n-1-i]
		}
		return result
	case "TOP_HALF":
		if n%2 == 1 {
			return reorderCiphers(reorderCiphers(ciphers, "REVERSE"), "BOTTOM_HALF")
		}
		return reorderCiphers(reorderCiphers(ciphers, "REVERSE"), "BOTTOM_HALF")
	case "BOTTOM_HALF":
		if n%2 == 1 {
			return ciphers[(n/2)+1:]
		}
		return ciphers[n/2:]
	case "MIDDLE_OUT":
		result := [][]byte{}
		mid := n / 2
		if n%2 == 1 {
			result = append(result, ciphers[mid])
			for i := 1; i <= mid; i++ {
				result = append(result, ciphers[mid+i], ciphers[mid-i])
			}
		} else {
			for i := 1; i <= mid; i++ {
				result = append(result, ciphers[mid-1+i], ciphers[mid-i])
			}
		}
		return result
	}
	return ciphers
}

// getExtensions builds TLS extensions
func getExtensions(hostname string, p probeConfig) []byte {
	ext := []byte{}

	if p.grease {
		ext = append(ext, randomGrease()...)
		ext = append(ext, 0x00, 0x00)
	}

	// SNI
	sni := []byte{0x00, 0x00}
	sni = append(sni, uint16Bytes(len(hostname)+5)...)
	sni = append(sni, uint16Bytes(len(hostname)+3)...)
	sni = append(sni, 0x00)
	sni = append(sni, uint16Bytes(len(hostname))...)
	sni = append(sni, []byte(hostname)...)
	ext = append(ext, sni...)

	// Standard extensions
	ext = append(ext, 0x00, 0x17, 0x00, 0x00)                                                             // extended_master_secret
	ext = append(ext, 0x00, 0x01, 0x00, 0x01, 0x01)                                                       // max_fragment_length
	ext = append(ext, 0xff, 0x01, 0x00, 0x01, 0x00)                                                       // renegotiation_info
	ext = append(ext, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19) // supported_groups
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)                                                 // ec_point_formats
	ext = append(ext, 0x00, 0x23, 0x00, 0x00)                                                             // session_ticket

	// ALPN
	if p.alpn == "ALPN" {
		alpnList := [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39}, // http/0.9
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30}, // http/1.0
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31}, // http/1.1
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},             // spdy/1
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},             // spdy/2
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},             // spdy/3
			{0x02, 0x68, 0x32},       // h2
			{0x03, 0x68, 0x32, 0x63}, // h2c
			{0x02, 0x68, 0x71},       // hq
		}
		if p.extOrder != "FORWARD" {
			alpnList = reorderCiphers(alpnList, p.extOrder)
		}
		alpnBytes := []byte{}
		for _, a := range alpnList {
			alpnBytes = append(alpnBytes, a...)
		}
		alpnExt := []byte{0x00, 0x10}
		alpnExt = append(alpnExt, uint16Bytes(len(alpnBytes)+2)...)
		alpnExt = append(alpnExt, uint16Bytes(len(alpnBytes))...)
		alpnExt = append(alpnExt, alpnBytes...)
		ext = append(ext, alpnExt...)
	} else if p.alpn == "RARE_ALPN" {
		alpnList := [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
			{0x03, 0x68, 0x32, 0x63},
			{0x02, 0x68, 0x71},
		}
		alpnBytes := []byte{}
		for _, a := range alpnList {
			alpnBytes = append(alpnBytes, a...)
		}
		alpnExt := []byte{0x00, 0x10}
		alpnExt = append(alpnExt, uint16Bytes(len(alpnBytes)+2)...)
		alpnExt = append(alpnExt, uint16Bytes(len(alpnBytes))...)
		alpnExt = append(alpnExt, alpnBytes...)
		ext = append(ext, alpnExt...)
	}

	// signature_algorithms
	ext = append(ext, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)

	// key_share
	keyShare := []byte{0x00, 0x33}
	shareBytes := []byte{}
	if p.grease {
		shareBytes = append(shareBytes, randomGrease()...)
		shareBytes = append(shareBytes, 0x00, 0x01, 0x00)
	}
	shareBytes = append(shareBytes, 0x00, 0x1d, 0x00, 0x20)
	shareBytes = append(shareBytes, randBytes(32)...)
	keyShare = append(keyShare, uint16Bytes(len(shareBytes)+2)...)
	keyShare = append(keyShare, uint16Bytes(len(shareBytes))...)
	keyShare = append(keyShare, shareBytes...)
	ext = append(ext, keyShare...)

	// psk_key_exchange_modes
	ext = append(ext, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01)

	// supported_versions
	if p.version == tls.VersionTLS13 || p.v13mode == "1.2_SUPPORT" {
		versions := [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}}
		if p.v13mode == "1.3_SUPPORT" {
			versions = append(versions, []byte{0x03, 0x04})
		}
		if p.extOrder != "FORWARD" {
			versions = reorderCiphers(versions, p.extOrder)
		}
		verBytes := []byte{}
		if p.grease {
			verBytes = append(verBytes, randomGrease()...)
		}
		for _, v := range versions {
			verBytes = append(verBytes, v...)
		}
		verExt := []byte{0x00, 0x2b}
		verExt = append(verExt, uint16Bytes(len(verBytes)+1)...)
		verExt = append(verExt, byte(len(verBytes)))
		verExt = append(verExt, verBytes...)
		ext = append(ext, verExt...)
	}

	result := uint16Bytes(len(ext))
	result = append(result, ext...)
	return result
}

// sendProbe sends probe and parses response
func sendProbe(address string, packet []byte, p probeConfig) string {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return "|||"
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return "|||"
	}

	response := make([]byte, 1484)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return "|||"
	}

	return parseServerHello(response[:n])
}

// parseServerHello extracts fingerprint from ServerHello
func parseServerHello(data []byte) string {
	if len(data) == 0 || data[0] == 21 {
		return "|||"
	}
	if !(data[0] == 22 && len(data) > 5 && data[5] == 2) || len(data) < 44 {
		return "|||"
	}

	serverHelloLen := int(binary.BigEndian.Uint16(data[3:5]))
	sidLen := int(data[43])
	cipherOffset := sidLen + 44

	if len(data) < cipherOffset+2 {
		return "|||"
	}

	cipher := hex.EncodeToString(data[cipherOffset : cipherOffset+2])
	version := hex.EncodeToString(data[9:11])
	extInfo := parseExtensions(data, sidLen, serverHelloLen)

	return fmt.Sprintf("%s|%s|%s", cipher, version, extInfo)
}

// parseExtensions extracts extension information
func parseExtensions(data []byte, offset int, helloLen int) string {
	if len(data) < 85 || len(data) < (offset+53) || data[offset+47] == 11 || offset+42 >= helloLen {
		return "|"
	}
	if bytes.Equal(data[offset+50:offset+53], []byte{0x0e, 0xac, 0x0b}) || (len(data) >= 85 && bytes.Equal(data[82:85], []byte{0x0f, 0xf0, 0x0b})) {
		return "|"
	}

	ecnt := offset + 49
	elen := int(binary.BigEndian.Uint16(data[offset+47 : offset+49]))
	emax := elen + ecnt - 1

	var etypes, evals [][]byte
	for ecnt < emax && len(data) >= ecnt+4 {
		extType := data[ecnt : ecnt+2]
		extLen := int(binary.BigEndian.Uint16(data[ecnt+2 : ecnt+4]))
		if len(data) < ecnt+4+extLen {
			break
		}

		etypes = append(etypes, extType)
		if extLen == 0 {
			evals = append(evals, []byte{})
		} else {
			evals = append(evals, data[ecnt+4:ecnt+4+extLen])
		}
		ecnt += extLen + 4
	}

	alpn := ""
	for i, t := range etypes {
		if bytes.Equal(t, []byte{0x00, 0x10}) && i < len(evals) {
			if eval := evals[i]; len(eval) >= 4 {
				alpn = string(eval[3:])
			}
		}
	}

	extList := []string{}
	for _, t := range etypes {
		extList = append(extList, hex.EncodeToString(t))
	}

	return alpn + "|" + strings.Join(extList, "-")
}

// rawToJARM converts raw fingerprints to JARM hash
func rawToJARM(raw string) string {
	if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return "00000000000000000000000000000000000000000000000000000000000000"
	}

	hash := ""
	alpex := ""
	for _, hs := range strings.Split(raw, ",") {
		parts := strings.Split(hs, "|")
		if len(parts) != 4 {
			return "00000000000000000000000000000000000000000000000000000000000000"
		}
		hash += cipherIndex(parts[0]) + versionByte(parts[1])
		alpex += parts[2] + parts[3]
	}

	sha := sha256.Sum256([]byte(alpex))
	hash += hex.EncodeToString(sha[:])[0:32]
	return hash
}

// cipherIndex converts cipher to index
func cipherIndex(c string) string {
	if c == "" {
		return "00"
	}
	ciphers := []string{
		"0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039", "003c", "003d", "0041", "0045", "0067", "006b", "0084",
		"0088", "009a", "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4", "c007", "c008", "c009", "c00a", "c011", "c012",
		"c013", "c014", "c023", "c024", "c027", "c028", "c02b", "c02c", "c02f", "c030", "c060", "c061", "c072", "c073", "c076", "c077",
		"c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1", "c0a2", "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8", "cca9",
		"1301", "1302", "1303", "1304", "1305",
	}
	for i, cipher := range ciphers {
		if cipher == c {
			return fmt.Sprintf("%.2x", i+1)
		}
	}
	return fmt.Sprintf("%.2x", len(ciphers)+1)
}

// versionByte converts version to byte
func versionByte(v string) string {
	if len(v) < 4 {
		return "0"
	}
	if n, err := strconv.Atoi(v[3:4]); err == nil {
		return string(byte(0x61 + n))
	}
	return "0"
}

// Helper functions
func randBytes(n int) []byte {
	b := make([]byte, n)
	binary.Read(crand.Reader, binary.BigEndian, &b)
	return b
}

func uint16Bytes(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func randomGrease() []byte {
	r := byte(rand.Int31() % 16)
	return []byte{0x0a + (r << 4), 0x0a + (r << 4)}
}
