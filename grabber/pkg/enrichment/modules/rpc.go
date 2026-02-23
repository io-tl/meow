package modules

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// RPCModule implements the RPC enrichment module
type RPCModule struct {
	BaseModule
}

// RPCService represents a single RPC service
type RPCService struct {
	Program uint32 `json:"program"`
	Version uint32 `json:"version"`
	Netid   string `json:"netid"`
	Address string `json:"address"`
	Service string `json:"service"`
	Owner   string `json:"owner"`
}

// NFSExport represents a single NFS export
type NFSExport struct {
	Directory string   `json:"directory"`
	Groups    []string `json:"groups"`
}

// RPCResult contains the results of an RPC scan
type RPCResult struct {
	Protocol string       `json:"protocol"`
	IsRPC    bool         `json:"is_rpc"`
	Services []RPCService `json:"services,omitempty"`
	NFSFound bool         `json:"nfs_found"`
	Exports  []NFSExport  `json:"exports,omitempty"`
	Error    string       `json:"error,omitempty"`
}

// RPC constants
const (
	RPCVersion = 2
	RPCCall    = 0
	RPCReply   = 1
)

// RPC message types
const (
	MsgAccepted = 0
	MsgDenied   = 1
)

// Accept status
const (
	Success      = 0
	ProgMismatch = 1
	ProgUnavail  = 2
	ProcUnavail  = 3
	GarbageArgs  = 4
)

// Auth flavor
const (
	AuthNone  = 0
	AuthUnix  = 1
	AuthShort = 2
	AuthDes   = 3
)

// Rpcbind constants
const (
	PortmapProgram  = 100000
	PortmapVersion2 = 2
	PortmapVersion3 = 3
	PortmapVersion4 = 4
	PortmapProc4    = 4 // RPCBPROC_DUMP (v4)
)

// Mount protocol constants
const (
	MountProgram    = 100005
	MountVersion1   = 1
	MountVersion3   = 3
	MountProcExport = 5 // MOUNTPROC_EXPORT
)

// NFS program constant
const (
	NFSProgram = 100003
)

// RPC program names (common ones)
var programNames = map[uint32]string{
	100000: "portmapper",
	100001: "rstatd",
	100002: "rusersd",
	100003: "nfs",
	100004: "ypserv",
	100005: "mountd",
	100007: "ypbind",
	100008: "walld",
	100009: "yppasswdd",
	100011: "rquotad",
	100012: "sprayd",
	100021: "nlockmgr",
	100024: "status",
	100227: "nfs_acl",
	150001: "pcnfsd",
}

// pmapMapping represents a single portmap entry
type pmapMapping struct {
	Program uint32
	Version uint32
	Netid   string
	Addr    string
	Owner   string
}

// XDRWriter helps build XDR encoded messages
type xdrWriter struct {
	data []byte
}

func newXDRWriter() *xdrWriter {
	return &xdrWriter{data: make([]byte, 0, 1024)}
}

func (w *xdrWriter) writeUint32(v uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	w.data = append(w.data, buf...)
}

func (w *xdrWriter) writeBytes(b []byte) {
	w.writeUint32(uint32(len(b)))
	w.data = append(w.data, b...)
	padding := (4 - (len(b) % 4)) % 4
	for i := 0; i < padding; i++ {
		w.data = append(w.data, 0)
	}
}

func (w *xdrWriter) bytes() []byte {
	return w.data
}

// XDRReader helps parse XDR encoded messages
type xdrReader struct {
	data []byte
	pos  int
}

func newXDRReader(data []byte) *xdrReader {
	return &xdrReader{data: data, pos: 0}
}

func (r *xdrReader) readUint32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, fmt.Errorf("unexpected end of data")
	}
	v := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *xdrReader) readBytes() ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	if r.pos+int(length) > len(r.data) {
		return nil, fmt.Errorf("unexpected end of data")
	}

	result := make([]byte, length)
	copy(result, r.data[r.pos:r.pos+int(length)])
	r.pos += int(length)

	padding := (4 - (int(length) % 4)) % 4
	r.pos += padding

	return result, nil
}

func (r *xdrReader) readString() (string, error) {
	b, err := r.readBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *xdrReader) skip(n int) {
	r.pos += n
}

func init() {
	Register(&RPCModule{
		BaseModule: NewBaseModule(
			"rpcbind",
			[]string{"rpc", "portmapper"},
			true, // Should enrich
			15*time.Second,
		),
	})
}

func (m *RPCModule) Scan(ip string, port int) (interface{}, error) {
	return scanRPC(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - RPC doesn't use SNI
func (m *RPCModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// scanRPC scans a host for RPC services and NFS exports
func scanRPC(host string, port int, timeout time.Duration) (*RPCResult, error) {
	result := &RPCResult{
		Protocol: "rpc",
		IsRPC:    false,
		Services: []RPCService{},
		NFSFound: false,
	}

	// Query rpcbind
	mappings, err := queryRpcbind(host, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// RPC service detected successfully
	result.IsRPC = true

	// Convert mappings to services
	nfsFound := false
	for _, m := range mappings {
		service := RPCService{
			Program: m.Program,
			Version: m.Version,
			Netid:   m.Netid,
			Address: m.Addr,
			Service: getProgramName(m.Program),
			Owner:   m.Owner,
		}
		if service.Owner == "" {
			service.Owner = "superuser"
		}
		result.Services = append(result.Services, service)

		// Check if NFS is available
		if m.Program == NFSProgram {
			nfsFound = true
		}
	}

	result.NFSFound = nfsFound

	// If NFS found, query mountd for exports
	if nfsFound {
		mountPort, netid := getMountInfo(mappings)
		if mountPort > 0 {
			exports, err := queryMountd(host, mountPort, netid, timeout)
			if err == nil {
				result.Exports = exports
			}
		}
	}

	return result, nil
}

// buildRpcbindCall creates an RPC call message for RPCBPROC_DUMP (v4)
func buildRpcbindCall(xid uint32, version uint32) []byte {
	w := newXDRWriter()

	w.writeUint32(xid)
	w.writeUint32(RPCCall)
	w.writeUint32(RPCVersion)
	w.writeUint32(PortmapProgram)
	w.writeUint32(version)
	w.writeUint32(PortmapProc4)

	w.writeUint32(AuthNone)
	w.writeUint32(0)

	w.writeUint32(AuthNone)
	w.writeUint32(0)

	return w.bytes()
}

// parseRpcbindReply parses the RPC reply and extracts rpcbind v4 entries
func parseRpcbindReply(data []byte) ([]pmapMapping, error) {
	r := newXDRReader(data)

	xid, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read XID: %w", err)
	}
	_ = xid

	msgType, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}

	if msgType != RPCReply {
		return nil, fmt.Errorf("expected REPLY message, got %d", msgType)
	}

	replyState, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read reply state: %w", err)
	}

	if replyState != MsgAccepted {
		return nil, fmt.Errorf("RPC call was denied")
	}

	verifierFlavor, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier flavor: %w", err)
	}
	_ = verifierFlavor

	verifierLength, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier length: %w", err)
	}
	r.skip(int(verifierLength))

	acceptStatus, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read accept status: %w", err)
	}

	if acceptStatus != Success {
		return nil, fmt.Errorf("RPC call failed with status %d", acceptStatus)
	}

	var mappings []pmapMapping

	for {
		hasMore, err := r.readUint32()
		if err != nil {
			break
		}

		if hasMore == 0 {
			break
		}

		program, err := r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("failed to read program: %w", err)
		}

		version, err := r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("failed to read version: %w", err)
		}

		netid, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("failed to read netid: %w", err)
		}

		addr, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("failed to read addr: %w", err)
		}

		owner, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("failed to read owner: %w", err)
		}

		mappings = append(mappings, pmapMapping{
			Program: program,
			Version: version,
			Netid:   netid,
			Addr:    addr,
			Owner:   owner,
		})
	}

	return mappings, nil
}

// queryRpcbind queries rpcbind (v4) on the given host
func queryRpcbind(host string, port int, timeout time.Duration) ([]pmapMapping, error) {
	conn, err := helpers.DialTCP(host, port, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rpcbind: %w", err)
	}
	defer conn.Close()

	xid := uint32(time.Now().Unix())
	request := buildRpcbindCall(xid, PortmapVersion4)

	recordMark := make([]byte, 4)
	binary.BigEndian.PutUint32(recordMark, uint32(len(request))|0x80000000)

	if _, err := conn.Write(append(recordMark, request...)); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	replyMark := make([]byte, 4)
	if _, err := conn.Read(replyMark); err != nil {
		return nil, fmt.Errorf("failed to read reply mark: %w", err)
	}

	replyLen := binary.BigEndian.Uint32(replyMark) & 0x7fffffff

	reply := make([]byte, replyLen)
	totalRead := 0
	for totalRead < int(replyLen) {
		n, err := conn.Read(reply[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read reply: %w", err)
		}
		totalRead += n
	}

	return parseRpcbindReply(reply)
}

// buildMountExportCall creates an RPC call for MOUNTPROC_EXPORT
func buildMountExportCall(xid uint32, version uint32) []byte {
	w := newXDRWriter()

	w.writeUint32(xid)
	w.writeUint32(RPCCall)
	w.writeUint32(RPCVersion)
	w.writeUint32(MountProgram)
	w.writeUint32(version)
	w.writeUint32(MountProcExport)

	w.writeUint32(AuthNone)
	w.writeUint32(0)

	w.writeUint32(AuthNone)
	w.writeUint32(0)

	return w.bytes()
}

// parseExportList parses the MOUNTPROC_EXPORT reply
func parseExportList(data []byte) ([]NFSExport, error) {
	r := newXDRReader(data)

	xid, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read XID: %w", err)
	}
	_ = xid

	msgType, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}

	if msgType != RPCReply {
		return nil, fmt.Errorf("expected REPLY message, got %d", msgType)
	}

	replyState, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read reply state: %w", err)
	}

	if replyState != MsgAccepted {
		return nil, fmt.Errorf("RPC call was denied")
	}

	verifierFlavor, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier flavor: %w", err)
	}
	_ = verifierFlavor

	verifierLength, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier length: %w", err)
	}
	r.skip(int(verifierLength))

	acceptStatus, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read accept status: %w", err)
	}

	if acceptStatus != Success {
		return nil, fmt.Errorf("RPC call failed with status %d", acceptStatus)
	}

	var exports []NFSExport

	for {
		hasMore, err := r.readUint32()
		if err != nil {
			break
		}

		if hasMore == 0 {
			break
		}

		directory, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		var groups []string
		for {
			hasMoreGroups, err := r.readUint32()
			if err != nil {
				break
			}

			if hasMoreGroups == 0 {
				break
			}

			group, err := r.readString()
			if err != nil {
				return nil, fmt.Errorf("failed to read group: %w", err)
			}

			groups = append(groups, group)
		}

		exports = append(exports, NFSExport{
			Directory: directory,
			Groups:    groups,
		})
	}

	return exports, nil
}

// parsePortFromUaddr extracts port from universal address
func parsePortFromUaddr(uaddr string, netid string) uint16 {
	if netid == "local" {
		return 0
	}

	parts := strings.Split(uaddr, ".")
	if len(parts) < 2 {
		return 0
	}

	var p1, p2 int
	fmt.Sscanf(parts[len(parts)-2], "%d", &p1)
	fmt.Sscanf(parts[len(parts)-1], "%d", &p2)

	return uint16(p1*256 + p2)
}

// getMountInfo queries rpcbind to get the mount daemon port and protocol
func getMountInfo(mappings []pmapMapping) (uint16, string) {
	var udpPort uint16
	var udpNetid string

	for _, m := range mappings {
		if m.Program == MountProgram && (m.Version == MountVersion3 || m.Version == MountVersion1) {
			port := parsePortFromUaddr(m.Addr, m.Netid)
			if port > 0 {
				if m.Netid == "tcp" || m.Netid == "tcp6" {
					return port, m.Netid
				}
				if m.Netid == "udp" || m.Netid == "udp6" {
					udpPort = port
					udpNetid = m.Netid
				}
			}
		}
	}

	if udpPort > 0 {
		return udpPort, udpNetid
	}

	return 0, ""
}

// queryMountdTCP queries mountd over TCP
func queryMountdTCP(host string, port uint16, version uint32, timeout time.Duration) ([]NFSExport, error) {
	conn, err := helpers.DialTCP(host, int(port), timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mountd: %w", err)
	}
	defer conn.Close()

	xid := uint32(time.Now().Unix())
	request := buildMountExportCall(xid, version)

	recordMark := make([]byte, 4)
	binary.BigEndian.PutUint32(recordMark, uint32(len(request))|0x80000000)

	if _, err := conn.Write(append(recordMark, request...)); err != nil {
		return nil, err
	}

	replyMark := make([]byte, 4)
	if _, err := conn.Read(replyMark); err != nil {
		return nil, err
	}

	replyLen := binary.BigEndian.Uint32(replyMark) & 0x7fffffff

	reply := make([]byte, replyLen)
	totalRead := 0
	for totalRead < int(replyLen) {
		n, err := conn.Read(reply[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read reply: %w", err)
		}
		totalRead += n
	}

	return parseExportList(reply)
}

// queryMountdUDP queries mountd over UDP
func queryMountdUDP(host string, port uint16, version uint32, timeout time.Duration) ([]NFSExport, error) {
	conn, err := helpers.DialUDP(host, int(port), timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mountd: %w", err)
	}
	defer conn.Close()

	xid := uint32(time.Now().Unix())
	request := buildMountExportCall(xid, version)

	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	reply := make([]byte, 8192)
	n, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}

	return parseExportList(reply[:n])
}

// queryMountd queries mountd for export list
func queryMountd(host string, port uint16, netid string, timeout time.Duration) ([]NFSExport, error) {
	versions := []uint32{MountVersion3, MountVersion1}

	for _, version := range versions {
		var exports []NFSExport
		var err error

		if netid == "udp" || netid == "udp6" {
			exports, err = queryMountdUDP(host, port, version, timeout)
		} else {
			exports, err = queryMountdTCP(host, port, version, timeout)
		}

		if err == nil {
			return exports, nil
		}
	}

	return nil, fmt.Errorf("failed to get export list from mountd")
}

// getProgramName returns the name of a known RPC program
func getProgramName(program uint32) string {
	if name, ok := programNames[program]; ok {
		return name
	}
	return "unknown"
}
