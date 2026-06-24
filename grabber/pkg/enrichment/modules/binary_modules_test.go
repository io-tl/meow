package modules

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- AMQP ---

func TestScanAMQP_ValidConnectionStart(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Read AMQP header
		buf := make([]byte, 8)
		conn.Read(buf)

		// Build connection.start frame
		// Protocol version 0-9
		payload := []byte{0, 9} // version major, minor

		// Server properties table (empty for simplicity)
		propTable := []byte{}
		propTableLen := make([]byte, 4)
		binary.BigEndian.PutUint32(propTableLen, uint32(len(propTable)))
		payload = append(payload, propTableLen...)
		payload = append(payload, propTable...)

		// Mechanisms (long-string): "PLAIN"
		mechStr := []byte("PLAIN")
		mechLen := make([]byte, 4)
		binary.BigEndian.PutUint32(mechLen, uint32(len(mechStr)))
		payload = append(payload, mechLen...)
		payload = append(payload, mechStr...)

		// Locales (long-string): "en_US"
		localeStr := []byte("en_US")
		localeLen := make([]byte, 4)
		binary.BigEndian.PutUint32(localeLen, uint32(len(localeStr)))
		payload = append(payload, localeLen...)
		payload = append(payload, localeStr...)

		// Frame header: type=1 (method), channel=0, size, method=0x000A000A (connection.start)
		frameSize := uint32(4 + len(payload)) // method (4) + payload
		frame := []byte{1}                    // type = method frame
		chanBytes := make([]byte, 2)
		frame = append(frame, chanBytes...)

		sizeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeBytes, frameSize)
		frame = append(frame, sizeBytes...)

		// Method: connection.start (class=10, method=10)
		method := make([]byte, 4)
		binary.BigEndian.PutUint32(method, 0x000A000A)
		frame = append(frame, method...)

		frame = append(frame, payload...)
		frame = append(frame, 0xCE) // frame end

		conn.Write(frame)
	})

	mod, ok := Get("amqp")
	if !ok {
		t.Fatal("amqp not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*AMQPResult)
	if result.Version != "0-9" {
		t.Errorf("Version = %q, want %q", result.Version, "0-9")
	}
	if result.Mechanisms != "PLAIN" {
		t.Errorf("Mechanisms = %q, want %q", result.Mechanisms, "PLAIN")
	}
	if result.Locales != "en_US" {
		t.Errorf("Locales = %q, want %q", result.Locales, "en_US")
	}
}

func TestScanAMQP_TruncatedResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 8)
		conn.Read(buf)
		conn.Write([]byte{1, 0, 0}) // Only 3 bytes
	})

	mod, _ := Get("amqp")
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*AMQPResult)
	if result.Error == "" {
		t.Error("expected Error for truncated response")
	}
}

// --- Cassandra ---

func TestScanCassandra_ValidSupportedResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Read OPTIONS frame
		buf := make([]byte, 9)
		conn.Read(buf)

		// Build SUPPORTED response (v4)
		// Header: version=0x84, flags=0, stream=0x0001, opcode=0x06
		header := []byte{0x84, 0x00, 0x00, 0x01, 0x06}

		// Body: multimap with CQL_VERSION -> ["3.4.5"]
		var body []byte
		// num pairs = 1
		body = append(body, 0x00, 0x01)
		// key: "CQL_VERSION"
		key := "CQL_VERSION"
		body = append(body, byte(len(key)>>8), byte(len(key)))
		body = append(body, []byte(key)...)
		// values: 1 value "3.4.5"
		body = append(body, 0x00, 0x01)
		val := "3.4.5"
		body = append(body, byte(len(val)>>8), byte(len(val)))
		body = append(body, []byte(val)...)

		// Body length
		bodyLen := make([]byte, 4)
		binary.BigEndian.PutUint32(bodyLen, uint32(len(body)))
		header = append(header, bodyLen...)
		header = append(header, body...)

		conn.Write(header)

		// Read potential QUERY frame and ignore
		qbuf := make([]byte, 1024)
		conn.Read(qbuf)
	})

	mod, ok := Get("cassandra")
	if !ok {
		t.Fatal("cassandra not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*CassandraResult)
	if result.ProtocolVersion != "v4" {
		t.Errorf("ProtocolVersion = %q, want %q", result.ProtocolVersion, "v4")
	}
	if len(result.CQLVersions) == 0 {
		t.Error("CQLVersions empty")
	}
}

func TestScanCassandra_TruncatedResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 9)
		conn.Read(buf)
		conn.Write([]byte{0x84, 0x00, 0x00}) // Too short
	})

	mod, _ := Get("cassandra")
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*CassandraResult)
	// Should not panic, ProtocolVersion may be empty
	if result.Protocol != "cassandra" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

// --- Modbus ---

func TestScanModbus_ValidDeviceID(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 12)
		conn.Read(buf)

		// Build response
		resp := make([]byte, 20)
		binary.BigEndian.PutUint16(resp[0:2], 1)  // Transaction ID
		binary.BigEndian.PutUint16(resp[2:4], 0)  // Protocol ID
		binary.BigEndian.PutUint16(resp[4:6], 14) // Length
		resp[6] = 1                               // Unit ID
		resp[7] = 0x2B                            // Function code
		resp[8] = 0x0E                            // MEI type
		resp[9] = 0x01                            // Read device ID
		resp[10] = 0x00                           // Conformity level
		resp[11] = 0x00                           // More follows
		resp[12] = 0x00                           // Object ID (VendorName)
		resp[13] = 4                              // Object length
		resp[14] = 'T'
		resp[15] = 'e'
		resp[16] = 's'
		resp[17] = 't'
		conn.Write(resp[:18])
	})

	mod, ok := Get("modbus")
	if !ok {
		t.Fatal("modbus not registered")
	}
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*ModbusResult)
	if !result.Detected {
		t.Error("Detected = false")
	}
	if result.VendorName != "Test" {
		t.Errorf("VendorName = %q, want %q", result.VendorName, "Test")
	}
}

func TestModbus_ShouldNotEnrich(t *testing.T) {
	if ShouldEnrich("modbus") {
		t.Error("modbus ShouldEnrich = true, want false")
	}
}

// --- MSSQL ---

func TestScanMSSQL_ValidTDSResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		conn.Read(buf)

		// Build TDS prelogin response with VERSION, ENCRYPTION, INSTOPT, THREADID and MARS.
		payload := []byte{
			0x00, 0x00, 0x1a, 0x00, 0x06, // VERSION
			0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION
			0x02, 0x00, 0x21, 0x00, 0x0c, // INSTOPT
			0x03, 0x00, 0x2d, 0x00, 0x04, // THREADID
			0x04, 0x00, 0x31, 0x00, 0x01, // MARS
			0xff,
			0x10, 0x00, 0x03, 0xe8, 0x00, 0x06, // 16.00.1000.6
			0x03, // encryption required
			'M', 'S', 'S', 'Q', 'L', 'S', 'E', 'R', 'V', 'E', 'R', 0x00,
			0x00, 0x00, 0x00, 0x2a,
			0x01,
		}

		resp := make([]byte, 8+len(payload))
		resp[0] = 0x04 // Response packet type
		resp[1] = 0x01 // Status
		binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)))
		copy(resp[8:], payload)
		conn.Write(resp)
	})

	result, err := scanMSSQL(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "mssql" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if result.VersionNumber != "16.00.1000.6" {
		t.Fatalf("VersionNumber = %q", result.VersionNumber)
	}
	if result.Product != "Microsoft SQL Server 2022" {
		t.Fatalf("Product = %q", result.Product)
	}
	if result.InstanceName != "MSSQLSERVER" {
		t.Fatalf("InstanceName = %q", result.InstanceName)
	}
	if result.Encryption != "required" {
		t.Fatalf("Encryption = %q", result.Encryption)
	}
	if !result.MARSSupported {
		t.Fatal("MARSSupported = false")
	}
	if result.ThreadID != 42 {
		t.Fatalf("ThreadID = %d", result.ThreadID)
	}
}

func TestScanMSSQL_InvalidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 100)
		conn.Read(buf)
		// Invalid packet type
		resp := make([]byte, 8)
		resp[0] = 0xFF
		conn.Write(resp)
	})

	result, _ := scanMSSQL(host, port, 3*time.Second)
	if result.Error == "" {
		t.Error("expected Error for invalid TDS response")
	}
}

func TestMSSQL_ModuleRegistered(t *testing.T) {
	mod, ok := Get("mssql")
	if !ok {
		t.Fatal("mssql not registered")
	}
	// Check aliases
	_, ok = Get("ms-sql")
	if !ok {
		t.Fatal("ms-sql alias not registered")
	}
	if mod.Name() != "mssql" {
		t.Errorf("Name() = %q", mod.Name())
	}
}

func TestParseMSSQLBrowserResponse(t *testing.T) {
	data := []byte("\x05ServerName;db-prod;InstanceName;MSSQLSERVER;IsClustered;No;Version;16.0.1000.6;tcp;1433;;ServerName;db-prod;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;51433;;")

	instances := parseMSSQLBrowserResponse(data)
	if len(instances) != 2 {
		t.Fatalf("len(instances) = %d, want 2", len(instances))
	}
	if instances[0].ServerName != "db-prod" {
		t.Fatalf("ServerName = %q", instances[0].ServerName)
	}
	if instances[0].InstanceName != "MSSQLSERVER" {
		t.Fatalf("InstanceName = %q", instances[0].InstanceName)
	}
	if instances[0].TCPPort != "1433" {
		t.Fatalf("TCPPort = %q", instances[0].TCPPort)
	}
	if instances[1].InstanceName != "SQLEXPRESS" {
		t.Fatalf("InstanceName = %q", instances[1].InstanceName)
	}
}

func TestNormalizeMSSQLInstanceName(t *testing.T) {
	if got := normalizeMSSQLInstanceName([]byte{0x01}); got != "" {
		t.Fatalf("normalizeMSSQLInstanceName(control) = %q, want empty", got)
	}
	if got := normalizeMSSQLInstanceName([]byte("MSSQLSERVER\x00")); got != "MSSQLSERVER" {
		t.Fatalf("normalizeMSSQLInstanceName(valid) = %q", got)
	}
}

// --- Oracle ---

func TestScanOracle_ValidTNSResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf)

		// Build TNS REFUSE response
		resp := make([]byte, 10)
		resp[0] = 0x00
		resp[1] = 0x0A // Length = 10
		resp[4] = 0x04 // Type = REFUSE
		conn.Write(resp)
	})

	result, err := scanOracle(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "detected" {
		t.Errorf("Version = %q, want %q", result.Version, "detected")
	}
}

func TestScanOracle_TruncatedResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf)
		conn.Write([]byte{0x00, 0x02}) // Too short
	})

	result, _ := scanOracle(host, port, 3*time.Second)
	// Should not panic
	if result.Protocol != "oracle" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

func TestScanOracle_ParsesDescriptorAndErrors(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf)

		payload := []byte("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)(INSTANCE_NAME=orcl1))(VERSION=19.0.0.0.0))TNS-12514: TNS:listener does not currently know of service requested in connect descriptor")
		resp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(resp[0:2], uint16(len(resp)))
		resp[4] = 0x04
		copy(resp[8:], payload)
		conn.Write(resp)
	})

	result, err := scanOracle(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PacketType != "REFUSE" {
		t.Fatalf("PacketType = %q, want REFUSE", result.PacketType)
	}
	if result.ServiceName != "orcl" {
		t.Fatalf("ServiceName = %q, want orcl", result.ServiceName)
	}
	if result.InstanceName != "orcl1" {
		t.Fatalf("InstanceName = %q, want orcl1", result.InstanceName)
	}
	if result.Host != "db.example" {
		t.Fatalf("Host = %q, want db.example", result.Host)
	}
	if result.Port != "1521" {
		t.Fatalf("Port = %q, want 1521", result.Port)
	}
	if result.Version != "19.0.0.0.0" {
		t.Fatalf("Version = %q, want 19.0.0.0.0", result.Version)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("Errors = %v, want 1 entry", result.Errors)
	}
}

func TestOracle_ModuleRegistered(t *testing.T) {
	_, ok := Get("oracle")
	if !ok {
		t.Fatal("oracle not registered")
	}
	_, ok = Get("oracle-tns")
	if !ok {
		t.Fatal("oracle-tns alias not registered")
	}
}

// --- Mumble (UDP) ---

func TestScanMumble_ValidPingResponse(t *testing.T) {
	host, port := startTestUDPServer(t, func(conn *net.UDPConn) {
		buf := make([]byte, 12)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil || n < 4 {
			return
		}

		// Build response: version + timestamp echo + users + maxUsers + bandwidth
		resp := make([]byte, 24)
		// Version: 1.5.0 = (1 << 16) | (5 << 8) | 0 = 0x00010500
		binary.BigEndian.PutUint32(resp[0:4], 0x00010500)
		// Timestamp echo
		copy(resp[4:8], buf[0:4])
		// Users = 10
		binary.BigEndian.PutUint32(resp[8:12], 10)
		// MaxUsers = 50
		binary.BigEndian.PutUint32(resp[12:16], 50)
		// Bandwidth = 72000
		binary.BigEndian.PutUint32(resp[16:20], 72000)

		conn.WriteToUDP(resp[:20], addr)
	})

	mod, ok := Get("mumble")
	if !ok {
		t.Fatal("mumble not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*MumbleResult)
	if !result.Ping {
		t.Error("Ping = false")
	}
	if result.VersionMajor != 1 || result.VersionMinor != 5 || result.VersionPatch != 0 {
		t.Errorf("Version = %d.%d.%d, want 1.5.0", result.VersionMajor, result.VersionMinor, result.VersionPatch)
	}
	if result.Users != 10 {
		t.Errorf("Users = %d, want 10", result.Users)
	}
	if result.MaxUsers != 50 {
		t.Errorf("MaxUsers = %d, want 50", result.MaxUsers)
	}
}

func TestMumble_ModuleRegistered(t *testing.T) {
	_, ok := Get("mumble")
	if !ok {
		t.Fatal("mumble not registered")
	}
}

// --- CoAP (UDP) ---

func TestScanCoAP_ValidResponse(t *testing.T) {
	host, port := startTestUDPServer(t, func(conn *net.UDPConn) {
		buf := make([]byte, 256)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil || n < 4 {
			return
		}

		// Build CoAP response: ACK, 2.05 Content
		resp := []byte{
			0x60,       // Ver=1, Type=ACK, TKL=0
			0x45,       // Code: 2.05 (Content)
			0x00, 0x01, // Message ID
			0xFF, // Payload marker
		}
		resp = append(resp, []byte("</sensor>;rt=temperature,</light>;rt=light")...)
		conn.WriteToUDP(resp, addr)
	})

	mod, ok := Get("coap")
	if !ok {
		t.Fatal("coap not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*CoAPResult)
	if !result.Response {
		t.Error("Response = false")
	}
	if result.ResponseCode != "2.05" {
		t.Errorf("ResponseCode = %q, want %q", result.ResponseCode, "2.05")
	}
	if len(result.Resources) == 0 {
		t.Error("Resources empty")
	}
}

func TestCoAP_ModuleRegistered(t *testing.T) {
	_, ok := Get("coap")
	if !ok {
		t.Fatal("coap not registered")
	}
}
