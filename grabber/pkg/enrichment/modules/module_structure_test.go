package modules

import (
	"encoding/json"
	"reflect"
	"testing"
)

// allResultStructs returns zero-value instances of every known *Result struct.
// When adding a new module, add its Result type here.
var allResultStructs = []interface{}{
	// Web
	&HTTPResult{},
	&IPPResult{},
	&IcecastResult{},
	&CouchDBResult{},
	&ElasticsearchResult{},
	&InfluxDBResult{},
	// Email
	&SMTPResult{},
	&POP3Result{},
	&IMAPResult{},
	// DB
	&MySQLResult{},
	&PostgresResult{},
	&MongoDBResult{},
	&RedisResult{},
	&OracleResult{},
	&MSSQLResult{},
	&CassandraResult{},
	&MemcachedResult{},
	// Directory
	&LDAPResult{},
	&DNSResult{},
	&NetBIOSResult{},
	&X11Result{},
	// Remote
	&SSHResult{},
	&TelnetResult{},
	&VNCResult{},
	&RDPResult{},
	// File
	&FTPResult{},
	&RsyncResult{},
	&TFTPResult{},
	&NFSResult{},
	&GitResult{},
	&AFPResult{},
	// Messaging
	&MQTTResult{},
	&AMQPResult{},
	&XMPPResult{},
	&IRCResult{},
	&MumbleResult{},
	&TeamSpeakResult{},
	&SIPResult{},
	// Network
	&SMBResult{},
	&SNMPResult{},
	&NTPResult{},
	&ModbusResult{},
	&CoAPResult{},
	&OpenVPNResult{},
	&PPTPResult{},
	&UPnPResult{},
	// Other
	&RPCResult{},
	&RTSPResult{},
	&MinecraftResult{},
	&AJP13Result{},
	&LPDResult{},
	&MPDResult{},
	&NNTPResult{},
	&SyslogResult{},
	&LDPResult{},
	&BannerResult{},
}

func TestAllResultStructsHaveProtocolJSONTag(t *testing.T) {
	for _, s := range allResultStructs {
		typeName := reflect.TypeOf(s).Elem().Name()
		rt := reflect.TypeOf(s).Elem()

		found := false
		for i := 0; i < rt.NumField(); i++ {
			field := rt.Field(i)
			jsonTag := field.Tag.Get("json")
			if jsonTag == "protocol" || jsonTag == "protocol,omitempty" {
				if field.Type.Kind() != reflect.String {
					t.Errorf("%s: 'protocol' field is %v, want string", typeName, field.Type)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: missing json tag 'protocol'", typeName)
		}
	}
}

func TestAllResultStructsHaveErrorJSONTag(t *testing.T) {
	for _, s := range allResultStructs {
		typeName := reflect.TypeOf(s).Elem().Name()
		rt := reflect.TypeOf(s).Elem()

		for i := 0; i < rt.NumField(); i++ {
			field := rt.Field(i)
			jsonTag := field.Tag.Get("json")
			if jsonTag == "error" || jsonTag == "error,omitempty" {
				if field.Type.Kind() != reflect.String {
					t.Errorf("%s: 'error' field is %v, want string", typeName, field.Type)
				}
				if jsonTag != "error,omitempty" {
					t.Errorf("%s: 'error' field should use 'error,omitempty' tag, got %q", typeName, jsonTag)
				}
			}
		}
	}
}

func TestAllResultStructsSerializeProtocol(t *testing.T) {
	for _, s := range allResultStructs {
		typeName := reflect.TypeOf(s).Elem().Name()

		v := reflect.New(reflect.TypeOf(s).Elem())
		protoField := v.Elem().FieldByName("Protocol")
		if !protoField.IsValid() {
			t.Errorf("%s: no Protocol field", typeName)
			continue
		}
		protoField.SetString("test_proto")

		raw, err := json.Marshal(v.Interface())
		if err != nil {
			t.Errorf("%s: json.Marshal failed: %v", typeName, err)
			continue
		}

		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("%s: json.Unmarshal failed: %v", typeName, err)
			continue
		}

		proto, ok := m["protocol"]
		if !ok {
			t.Errorf("%s: 'protocol' not present in JSON output", typeName)
		} else if proto != "test_proto" {
			t.Errorf("%s: protocol = %v, want 'test_proto'", typeName, proto)
		}
	}
}
