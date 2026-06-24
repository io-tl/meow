package modules

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MongoDBModule implements the MongoDB enrichment module
type MongoDBModule struct {
	BaseModule
}

// MongoDBResult represents the enriched MongoDB data
type MongoDBResult struct {
	Protocol       string            `json:"protocol"`
	Version        string            `json:"version,omitempty"`
	GitVersion     string            `json:"git_version,omitempty"`
	Modules        []string          `json:"modules,omitempty"`
	Allocator      string            `json:"allocator,omitempty"`
	JSEngine       string            `json:"javascript_engine,omitempty"`
	Bits           int               `json:"bits,omitempty"`
	MaxBsonSize    int               `json:"max_bson_object_size,omitempty"`
	StorageEngines []string          `json:"storage_engines,omitempty"`
	OpenSSL        string            `json:"openssl,omitempty"`
	IsMaster       bool              `json:"is_master,omitempty"`
	MaxWireVersion int               `json:"max_wire_version,omitempty"`
	ReadOnly       bool              `json:"is_read_only,omitempty"`
	ReplicaSet     string            `json:"replica_set,omitempty"`
	ReplicaHosts   []string          `json:"replica_hosts,omitempty"`
	Passives       []string          `json:"passive_hosts,omitempty"`
	Arbiters       []string          `json:"arbiters,omitempty"`
	Primary        string            `json:"primary,omitempty"`
	Me             string            `json:"me,omitempty"`
	Compression    []string          `json:"compression,omitempty"`
	SessionTimeout int               `json:"session_timeout_minutes,omitempty"`
	Hostname       string            `json:"hostname,omitempty"`
	OSType         string            `json:"os_type,omitempty"`
	OSName         string            `json:"os_name,omitempty"`
	CPUArch        string            `json:"cpu_arch,omitempty"`
	CPUCores       int               `json:"cpu_cores,omitempty"`
	MemoryMB       int               `json:"memory_mb,omitempty"`
	Databases      []MongoDatabase   `json:"databases,omitempty"`
	Collections    []MongoCollection `json:"collections,omitempty"`
	Buckets        []MongoBucket     `json:"buckets,omitempty"`
	TotalDBSize    int64             `json:"total_db_size,omitempty"`
	AuthStatus     string            `json:"auth_status,omitempty"`
	AuthMessage    string            `json:"auth_message,omitempty"`
	AuthRequired   bool              `json:"auth_required,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// MongoDatabase represents a database entry from listDatabases
type MongoDatabase struct {
	Name       string `json:"name"`
	SizeOnDisk int64  `json:"size_on_disk"`
	Empty      bool   `json:"empty,omitempty"`
}

type MongoBucket struct {
	Database   string `json:"database"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Collection string `json:"collection,omitempty"`
}

type MongoCollection struct {
	Database string `json:"database"`
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
}

func init() {
	Register(&MongoDBModule{
		BaseModule: NewBaseModule(
			"mongodb",
			[]string{"mongo"},
			true,
			10*time.Second,
		),
	})
}

func (m *MongoDBModule) Scan(ip string, port int) (interface{}, error) {
	return scanMongoDB(ip, port, m.DefaultTimeout())
}

func scanMongoDB(ip string, port int, timeout time.Duration) (*MongoDBResult, error) {
	result := &MongoDBResult{
		Protocol: "mongodb",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Try OP_MSG commands (MongoDB 3.6+)
	if err := mongoProbeAll(conn, result); err != nil {
		result.Error = err.Error()

		// OP_MSG protocol failed, try OP_QUERY fallback for buildInfo
		conn.Close()
		conn, err = helpers.DialTCP(ip, port, timeout)
		if err != nil {
			if result.Version == "" {
				result.Error = err.Error()
			}
			return result, nil
		}
		defer conn.Close()

		if fallbackErr := mongoFallbackOpQuery(conn, result); fallbackErr != nil {
			if !errors.Is(fallbackErr, io.EOF) {
				result.Error = fallbackErr.Error()
			}
			return result, nil
		}

		result.Error = ""
		return result, nil
	}

	conn.Close()
	return result, nil
}

// mongoProbeAll sends multiple commands via OP_MSG on a single connection
func mongoProbeAll(conn net.Conn, result *MongoDBResult) error {
	reqID := uint32(1)

	// 1. buildInfo — version, modules, openssl, storage engines
	doc, err := mongoRunCommand(conn, "buildInfo", "admin", reqID)
	if err != nil {
		return err // protocol failure, will fallback to OP_QUERY
	}
	reqID++
	mongoExtractBuildInfo(doc, result)
	if result.Version == "" && !result.AuthRequired {
		result.Version = "detected"
	}

	// 2. isMaster — topology, wire version, replica set, compression
	doc, err = mongoRunCommand(conn, "isMaster", "admin", reqID)
	if err != nil {
		result.Error = fmt.Sprintf("isMaster command failed: %v", err)
	} else {
		mongoExtractIsMaster(doc, result)
	}
	reqID++

	// 3. hostInfo — OS, hostname, CPU, memory
	doc, err = mongoRunCommand(conn, "hostInfo", "admin", reqID)
	if err == nil {
		mongoExtractHostInfo(doc, result)
	}
	reqID++

	// 4. listDatabases — database names and sizes (requires auth on most instances)
	doc, err = mongoRunCommand(conn, "listDatabases", "admin", reqID)
	if err == nil {
		mongoExtractDatabases(doc, result)
		if len(result.Databases) > 0 && result.AuthStatus == "" {
			result.AuthStatus = "not_required"
		}
	}
	if mongoIsUnauthorized(doc) {
		result.AuthRequired = true
		result.AuthStatus = "required"
		result.AuthMessage = mongoExtractErrorMessage(doc)
		return nil
	}
	reqID++

	if len(result.Databases) > 0 {
		for _, db := range result.Databases {
			doc, err = mongoRunCommandElements(conn, "listCollections", db.Name, reqID,
				mongoBoolElement("nameOnly", true),
				mongoBoolElement("authorizedCollections", true),
			)
			if err == nil {
				mongoExtractBuckets(db.Name, doc, result)
			} else if result.AuthStatus == "" {
				result.AuthStatus = "unknown"
			}
			if mongoIsUnauthorized(doc) && result.AuthStatus == "" {
				result.AuthRequired = true
				result.AuthStatus = "required"
				result.AuthMessage = mongoExtractErrorMessage(doc)
			}
			reqID++
		}
	}

	if result.AuthStatus == "" {
		if result.AuthRequired {
			result.AuthStatus = "required"
		} else {
			result.AuthStatus = "unknown"
		}
	}

	return nil
}

// --- Wire protocol builders ---

// mongoBuildCommandBSON builds a BSON document for {cmd: 1, $db: db}
func mongoBuildCommandBSON(cmd, db string) []byte {
	return mongoBuildCommandBSONWithElements(cmd, db)
}

type mongoElement struct {
	name string
	kind byte
	i32  int32
	str  string
	b    bool
}

func mongoBoolElement(name string, value bool) mongoElement {
	return mongoElement{name: name, kind: 0x08, b: value}
}

func mongoBuildCommandBSONWithElements(cmd, db string, elems ...mongoElement) []byte {
	// Element 1: type(1) + cmd\0 + int32(4)
	// Element 2: type(1) + "$db\0"(4) + strLen(4) + db\0
	// Document: size(4) + elem1 + elem2 + extras + terminator(1)
	elem1 := 1 + len(cmd) + 1 + 4
	elem2 := 1 + 4 + 4 + len(db) + 1
	extraSize := 0
	for _, elem := range elems {
		extraSize += 1 + len(elem.name) + 1
		switch elem.kind {
		case 0x10:
			extraSize += 4
		case 0x02:
			extraSize += 4 + len(elem.str) + 1
		case 0x08:
			extraSize++
		}
	}
	docSize := 4 + elem1 + elem2 + extraSize + 1

	doc := make([]byte, docSize)
	pos := 0

	binary.LittleEndian.PutUint32(doc[pos:], uint32(docSize))
	pos += 4

	doc[pos] = 0x10 // int32 type
	pos++
	copy(doc[pos:], cmd)
	pos += len(cmd)
	doc[pos] = 0x00
	pos++
	binary.LittleEndian.PutUint32(doc[pos:], 1)
	pos += 4

	doc[pos] = 0x02 // string type
	pos++
	copy(doc[pos:], "$db\x00")
	pos += 4
	binary.LittleEndian.PutUint32(doc[pos:], uint32(len(db)+1))
	pos += 4
	copy(doc[pos:], db)
	pos += len(db)
	doc[pos] = 0x00
	pos++

	for _, elem := range elems {
		doc[pos] = elem.kind
		pos++
		copy(doc[pos:], elem.name)
		pos += len(elem.name)
		doc[pos] = 0x00
		pos++

		switch elem.kind {
		case 0x10:
			binary.LittleEndian.PutUint32(doc[pos:], uint32(elem.i32))
			pos += 4
		case 0x02:
			binary.LittleEndian.PutUint32(doc[pos:], uint32(len(elem.str)+1))
			pos += 4
			copy(doc[pos:], elem.str)
			pos += len(elem.str)
			doc[pos] = 0x00
			pos++
		case 0x08:
			if elem.b {
				doc[pos] = 0x01
			} else {
				doc[pos] = 0x00
			}
			pos++
		}
	}

	doc[pos] = 0x00 // terminator
	return doc
}

// mongoBuildOpMsg wraps BSON in an OP_MSG wire protocol message
func mongoBuildOpMsg(bson []byte, requestID uint32) []byte {
	msgLen := uint32(16 + 4 + 1 + len(bson))
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:], msgLen)
	binary.LittleEndian.PutUint32(msg[4:], requestID)
	binary.LittleEndian.PutUint32(msg[8:], 0)     // responseTo
	binary.LittleEndian.PutUint32(msg[12:], 2013) // OP_MSG
	binary.LittleEndian.PutUint32(msg[16:], 0)    // flagBits
	msg[20] = 0x00                                // section kind: body
	copy(msg[21:], bson)
	return msg
}

// mongoBuildOpQuery builds an OP_QUERY for {buildInfo: 1} (fallback for MongoDB < 3.6)
func mongoBuildOpQuery() []byte {
	// BSON: {buildInfo: 1} = 20 bytes
	// OP_QUERY: header(16) + flags(4) + coll(11) + skip(4) + return(4) + bson(20) = 59
	return []byte{
		0x3b, 0x00, 0x00, 0x00, // messageLength: 59
		0x01, 0x00, 0x00, 0x00, // requestID: 1
		0x00, 0x00, 0x00, 0x00, // responseTo: 0
		0xd4, 0x07, 0x00, 0x00, // opCode: OP_QUERY (2004)
		0x00, 0x00, 0x00, 0x00, // flags: 0
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd\0"
		0x00, 0x00, 0x00, 0x00, // numberToSkip: 0
		0x01, 0x00, 0x00, 0x00, // numberToReturn: 1
		// BSON: {buildInfo: 1} (20 bytes)
		0x14, 0x00, 0x00, 0x00, // doc size: 20
		0x10,                                                       // type: int32
		0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00, // "buildInfo\0"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // end
	}
}

// --- Command execution ---

// mongoRunCommand sends a command via OP_MSG and returns parsed BSON response
func mongoRunCommand(conn net.Conn, cmd, db string, requestID uint32) (map[string]interface{}, error) {
	return mongoRunCommandElements(conn, cmd, db, requestID)
}

func mongoRunCommandElements(conn net.Conn, cmd, db string, requestID uint32, elems ...mongoElement) (map[string]interface{}, error) {
	bson := mongoBuildCommandBSONWithElements(cmd, db, elems...)
	msg := mongoBuildOpMsg(bson, requestID)

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	return mongoReadResponse(conn)
}

func mongoReadResponse(conn net.Conn) (map[string]interface{}, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	msgLen := int(binary.LittleEndian.Uint32(header[0:4]))
	opCode := binary.LittleEndian.Uint32(header[12:16])

	if msgLen < 21 || msgLen > 1<<20 {
		return nil, fmt.Errorf("invalid message length %d", msgLen)
	}

	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	var bsonData []byte
	switch opCode {
	case 2013: // OP_MSG: flagBits(4) + sectionKind(1) + BSON
		if len(body) < 5 {
			return nil, fmt.Errorf("OP_MSG too short")
		}
		bsonData = body[5:]
	case 1: // OP_REPLY: responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + BSON
		if len(body) < 20 {
			return nil, fmt.Errorf("OP_REPLY too short")
		}
		bsonData = body[20:]
	default:
		return nil, fmt.Errorf("unexpected opcode %d", opCode)
	}

	return mongoParseBSON(bsonData), nil
}

func mongoFallbackOpQuery(conn net.Conn, result *MongoDBResult) error {
	if _, err := conn.Write(mongoBuildOpQuery()); err != nil {
		return err
	}
	doc, err := mongoReadResponse(conn)
	if err != nil {
		return err
	}
	mongoExtractBuildInfo(doc, result)
	if result.Version == "" {
		result.Version = "detected"
	}
	return nil
}

// --- Data extraction ---

func mongoExtractBuildInfo(doc map[string]interface{}, result *MongoDBResult) {
	if len(doc) == 0 {
		return
	}

	if !mongoIsOK(doc) {
		if mongoIsUnauthorized(doc) {
			result.AuthStatus = "required"
			result.AuthMessage = mongoExtractErrorMessage(doc)
		}
		result.AuthRequired = true
		return
	}

	if v, ok := doc["version"].(string); ok {
		result.Version = v
	}
	if v, ok := doc["gitVersion"].(string); ok {
		result.GitVersion = v
	}
	if v, ok := doc["allocator"].(string); ok {
		result.Allocator = v
	}
	if v, ok := doc["javascriptEngine"].(string); ok {
		result.JSEngine = v
	}
	if v := mongoGetInt(doc, "bits"); v > 0 {
		result.Bits = v
	}
	if v := mongoGetInt(doc, "maxBsonObjectSize"); v > 0 {
		result.MaxBsonSize = v
	}
	result.Modules = mongoGetStringArray(doc, "modules")
	result.StorageEngines = mongoGetStringArray(doc, "storageEngines")

	// OpenSSL info
	if ssl, ok := doc["openssl"].(map[string]interface{}); ok {
		if running, ok := ssl["running"].(string); ok {
			result.OpenSSL = running
		}
	}
}

func mongoExtractIsMaster(doc map[string]interface{}, result *MongoDBResult) {
	if !mongoIsOK(doc) {
		return
	}

	if v, ok := doc["ismaster"].(bool); ok && v {
		result.IsMaster = true
	}
	if v := mongoGetInt(doc, "maxWireVersion"); v > 0 {
		result.MaxWireVersion = v
	}
	if v, ok := doc["readOnly"].(bool); ok && v {
		result.ReadOnly = true
	}
	if v, ok := doc["setName"].(string); ok {
		result.ReplicaSet = v
	}
	if v, ok := doc["primary"].(string); ok {
		result.Primary = v
	}
	if v, ok := doc["me"].(string); ok {
		result.Me = v
	}
	if v := mongoGetInt(doc, "logicalSessionTimeoutMinutes"); v > 0 {
		result.SessionTimeout = v
	}

	result.ReplicaHosts = mongoGetStringArray(doc, "hosts")
	result.Passives = mongoGetStringArray(doc, "passives")
	result.Arbiters = mongoGetStringArray(doc, "arbiters")
	result.Compression = mongoGetStringArray(doc, "compression")

	// If we didn't get version from buildInfo, estimate from maxWireVersion
	if result.Version == "" && result.MaxWireVersion > 0 {
		result.Version = mongoVersionFromWire(result.MaxWireVersion)
	}
}

func mongoExtractHostInfo(doc map[string]interface{}, result *MongoDBResult) {
	if !mongoIsOK(doc) {
		return
	}

	if sys, ok := doc["system"].(map[string]interface{}); ok {
		if v, ok := sys["hostname"].(string); ok {
			result.Hostname = v
		}
		if v, ok := sys["cpuArch"].(string); ok {
			result.CPUArch = v
		}
		if v := mongoGetInt(sys, "numCores"); v > 0 {
			result.CPUCores = v
		}
		if v := mongoGetInt(sys, "memSizeMB"); v > 0 {
			result.MemoryMB = v
		}
	}

	if osInfo, ok := doc["os"].(map[string]interface{}); ok {
		if v, ok := osInfo["type"].(string); ok {
			result.OSType = v
		}
		if v, ok := osInfo["name"].(string); ok {
			result.OSName = v
		}
		if v, ok := osInfo["version"].(string); ok {
			if result.OSName != "" {
				result.OSName += " " + v
			} else {
				result.OSName = v
			}
		}
	}
}

func mongoExtractDatabases(doc map[string]interface{}, result *MongoDBResult) {
	if !mongoIsOK(doc) {
		if mongoIsUnauthorized(doc) {
			result.AuthRequired = true
			result.AuthStatus = "required"
			result.AuthMessage = mongoExtractErrorMessage(doc)
		}
		return
	}

	if v := mongoGetInt64(doc, "totalSize"); v > 0 {
		result.TotalDBSize = v
	}

	dbs, ok := doc["databases"].([]interface{})
	if !ok {
		return
	}

	for _, item := range dbs {
		dbDoc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := dbDoc["name"].(string)
		if !ok {
			continue
		}
		db := MongoDatabase{
			Name:       name,
			SizeOnDisk: mongoGetInt64(dbDoc, "sizeOnDisk"),
		}
		if v, ok := dbDoc["empty"].(bool); ok {
			db.Empty = v
		}
		result.Databases = append(result.Databases, db)
	}
}

func mongoExtractBuckets(dbName string, doc map[string]interface{}, result *MongoDBResult) {
	if !mongoIsOK(doc) {
		return
	}

	cursor, ok := doc["cursor"].(map[string]interface{})
	if !ok {
		return
	}
	firstBatch, ok := cursor["firstBatch"].([]interface{})
	if !ok {
		return
	}

	gridfs := make(map[string]map[string]bool)
	for _, item := range firstBatch {
		colDoc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := colDoc["name"].(string)
		if !ok || name == "" {
			continue
		}
		collType, _ := colDoc["type"].(string)

		result.Collections = append(result.Collections, MongoCollection{
			Database: dbName,
			Name:     name,
			Type:     collType,
		})

		if strings.HasPrefix(name, "system.buckets.") {
			bucketName := strings.TrimPrefix(name, "system.buckets.")
			result.Buckets = append(result.Buckets, MongoBucket{
				Database:   dbName,
				Name:       bucketName,
				Type:       "timeseries",
				Collection: name,
			})
			continue
		}

		if strings.HasSuffix(name, ".files") || strings.HasSuffix(name, ".chunks") {
			base := strings.TrimSuffix(strings.TrimSuffix(name, ".files"), ".chunks")
			entry := gridfs[base]
			if entry == nil {
				entry = make(map[string]bool)
				gridfs[base] = entry
			}
			entry[name] = true
		}
	}

	for bucketName, collections := range gridfs {
		if collections[bucketName+".files"] && collections[bucketName+".chunks"] {
			result.Buckets = append(result.Buckets, MongoBucket{
				Database: dbName,
				Name:     bucketName,
				Type:     "gridfs",
			})
		}
	}
}

// --- Helpers ---

func mongoIsOK(doc map[string]interface{}) bool {
	v, exists := doc["ok"]
	if !exists {
		return len(doc) > 0 // if no "ok" field but has data, treat as success
	}
	switch val := v.(type) {
	case float64:
		return val != 0
	case int:
		return val != 0
	case int64:
		return val != 0
	}
	return false
}

func mongoIsUnauthorized(doc map[string]interface{}) bool {
	if len(doc) == 0 || mongoIsOK(doc) {
		return false
	}
	if code := mongoGetInt(doc, "code"); code == 13 || code == 18 {
		return true
	}
	message := strings.ToLower(mongoExtractErrorMessage(doc))
	return strings.Contains(message, "not authorized") || strings.Contains(message, "requires authentication") || strings.Contains(message, "unauthorized")
}

func mongoExtractErrorMessage(doc map[string]interface{}) string {
	if msg, ok := doc["errmsg"].(string); ok && msg != "" {
		return msg
	}
	if msg, ok := doc["codeName"].(string); ok && msg != "" {
		return msg
	}
	return ""
}

func mongoGetInt(doc map[string]interface{}, key string) int {
	switch v := doc[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func mongoGetInt64(doc map[string]interface{}, key string) int64 {
	switch v := doc[key].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case int:
		return int64(v)
	}
	return 0
}

func mongoGetStringArray(doc map[string]interface{}, key string) []string {
	arr, ok := doc[key].([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// mongoVersionFromWire estimates MongoDB version from maxWireVersion
func mongoVersionFromWire(wire int) string {
	switch {
	case wire >= 27:
		return "~8.1"
	case wire >= 25:
		return "~8.0"
	case wire >= 21:
		return "~7.0"
	case wire >= 17:
		return "~6.0"
	case wire >= 13:
		return "~5.0"
	case wire >= 9:
		return "~4.4"
	case wire >= 8:
		return "~4.2"
	case wire >= 7:
		return "~4.0"
	case wire >= 6:
		return "~3.6"
	case wire >= 5:
		return "~3.4"
	case wire >= 4:
		return "~3.2"
	case wire >= 3:
		return "~3.0"
	default:
		return "~2.6"
	}
}

// --- Minimal BSON parser ---

func mongoParseBSON(data []byte) map[string]interface{} {
	result := make(map[string]interface{})
	if len(data) < 5 {
		return result
	}

	docSize := int(binary.LittleEndian.Uint32(data[0:4]))
	if docSize < 5 || docSize > len(data) {
		return result
	}

	pos := 4
	for pos < docSize-1 {
		if pos >= len(data) {
			break
		}
		typ := data[pos]
		pos++

		// Read cstring element name
		nameEnd := pos
		for nameEnd < len(data) && data[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= len(data) {
			break
		}
		name := string(data[pos:nameEnd])
		pos = nameEnd + 1

		switch typ {
		case 0x01: // double (8 bytes)
			if pos+8 > len(data) {
				return result
			}
			bits := binary.LittleEndian.Uint64(data[pos : pos+8])
			result[name] = math.Float64frombits(bits)
			pos += 8
		case 0x02: // UTF-8 string
			if pos+4 > len(data) {
				return result
			}
			strLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
			if strLen < 1 || pos+strLen > len(data) {
				return result
			}
			result[name] = string(data[pos : pos+strLen-1])
			pos += strLen
		case 0x03: // embedded document
			if pos+4 > len(data) {
				return result
			}
			subSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if subSize < 5 || pos+subSize > len(data) {
				return result
			}
			result[name] = mongoParseBSON(data[pos : pos+subSize])
			pos += subSize
		case 0x04: // array
			if pos+4 > len(data) {
				return result
			}
			subSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if subSize < 5 || pos+subSize > len(data) {
				return result
			}
			result[name] = mongoParseBSONArray(data[pos : pos+subSize])
			pos += subSize
		case 0x05: // binary
			if pos+4 > len(data) {
				return result
			}
			binLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if pos+4+1+binLen > len(data) {
				return result
			}
			pos += 4 + 1 + binLen
		case 0x07: // ObjectId (12 bytes)
			if pos+12 > len(data) {
				return result
			}
			pos += 12
		case 0x08: // boolean (1 byte)
			if pos >= len(data) {
				return result
			}
			result[name] = data[pos] != 0
			pos++
		case 0x09: // UTC datetime (8 bytes)
			if pos+8 > len(data) {
				return result
			}
			pos += 8
		case 0x0A: // null
			// no data
		case 0x10: // int32
			if pos+4 > len(data) {
				return result
			}
			result[name] = int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
		case 0x11: // MongoDB timestamp (8 bytes)
			if pos+8 > len(data) {
				return result
			}
			pos += 8
		case 0x12: // int64
			if pos+8 > len(data) {
				return result
			}
			result[name] = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
			pos += 8
		case 0x13: // decimal128 (16 bytes)
			if pos+16 > len(data) {
				return result
			}
			pos += 16
		default:
			// Skip unknown type but continue parsing
			switch typ {
			case 0x05: // binary
				if pos+4 > len(data) {
					return result
				}
				binLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
				pos += 4 + 1 + binLen
			case 0x07: // ObjectId (12 bytes)
				pos += 12
			case 0x11: // MongoDB timestamp (8 bytes)
				pos += 8
			case 0x13: // decimal128 (16 bytes)
				pos += 16
			default:
				// Skip 1 byte for unknown types to avoid infinite loop
				pos++
			}
		}
	}

	return result
}

func mongoParseBSONArray(data []byte) []interface{} {
	doc := mongoParseBSON(data)
	arr := make([]interface{}, 0, len(doc))
	for i := 0; ; i++ {
		v, ok := doc[fmt.Sprintf("%d", i)]
		if !ok {
			break
		}
		arr = append(arr, v)
	}
	return arr
}
