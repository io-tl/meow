package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// init pre-loads wpcap.dll from the Npcap install directory using LoadLibraryExW
// with LOAD_WITH_ALTERED_SEARCH_PATH. This flag makes Windows resolve Packet.dll
// (wpcap's dependency) from the same directory — critical because Npcap v1.0+
// installs to System32\Npcap\ which is NOT in the standard DLL search path.
// Once pre-loaded, the LazyDLL("wpcap.dll") finds it already in memory.
func init() {
	sysRoot := os.Getenv("SYSTEMROOT")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	wpcapPath := sysRoot + `\System32\Npcap\wpcap.dll`
	pathPtr, _ := syscall.UTF16PtrFromString(wpcapPath)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibEx := kernel32.NewProc("LoadLibraryExW")
	loadLibEx.Call(uintptr(unsafe.Pointer(pathPtr)), 0, 0x00000008) // LOAD_WITH_ALTERED_SEARCH_PATH
}

// Npcap DLL lazy loading — fails gracefully if Npcap is not installed.
// Using NewLazyDLL keeps the binary static (no CGO) and allows runtime fallback.
var (
	npcapDLL = syscall.NewLazyDLL("wpcap.dll")
	iphlpDLL = syscall.NewLazyDLL("iphlpapi.dll")

	procPcapFindAllDevs = npcapDLL.NewProc("pcap_findalldevs")
	procPcapFreeAllDevs = npcapDLL.NewProc("pcap_freealldevs")
	procPcapOpenLive    = npcapDLL.NewProc("pcap_open_live")
	procPcapClose       = npcapDLL.NewProc("pcap_close")
	procPcapSendPacket  = npcapDLL.NewProc("pcap_sendpacket")
	procPcapNextEx      = npcapDLL.NewProc("pcap_next_ex")
	procPcapCompile     = npcapDLL.NewProc("pcap_compile")
	procPcapSetFilter   = npcapDLL.NewProc("pcap_setfilter")
	procPcapSetNonblock = npcapDLL.NewProc("pcap_setnonblock")

	procSendARP           = iphlpDLL.NewProc("SendARP")
	procGetBestRoute      = iphlpDLL.NewProc("GetBestRoute")
	procGetIpForwardTable = iphlpDLL.NewProc("GetIpForwardTable")
)

// C struct replicas using unsafe.Pointer for fields that hold C pointers.
// Go applies the same alignment rules as the platform C ABI, so layout matches
// on both 32-bit and 64-bit Windows.

type pcapIf struct {
	next  unsafe.Pointer // *pcapIf
	name  unsafe.Pointer // *byte (C string)
	desc  unsafe.Pointer // *byte (C string)
	addrs unsafe.Pointer // *pcapAddr
	flags uint32
}

type pcapAddr struct {
	next      unsafe.Pointer // *pcapAddr
	addr      unsafe.Pointer // *sockaddr
	netmask   unsafe.Pointer
	broadaddr unsafe.Pointer
	dstaddr   unsafe.Pointer
}

type pcapPkthdr struct {
	tsSec  int32 // Windows long is always 32-bit
	tsUsec int32
	capLen uint32
	pktLen uint32
}

type bpfProgram struct {
	bfLen   uint32
	bfInsns unsafe.Pointer
}

type mibIPForwardRow struct {
	dest, mask, policy, nextHop, ifIndex uint32
	typ, proto, age, nextHopAS           uint32
	metric1, metric2, metric3            uint32
	metric4, metric5                     uint32
}

// NpcapTransport implements Transport using Npcap for raw packet injection on Windows.
// Requires Npcap installed and Administrator privileges.
// Resolves destination MAC per-packet: local targets are ARP'd directly,
// remote targets go through the gateway MAC.
type NpcapTransport struct {
	handle  uintptr
	sendBuf []byte // reusable buffer (Send is single-goroutine from scanner)

	srcMAC      [6]byte
	gatewayMAC  [6]byte
	hasGateway  bool
	srcIPNative uint32
	localNet    uint32 // srcIP & mask
	localMask   uint32
	macCache    map[uint32][6]byte // IP → MAC cache for local targets
}

// NewNpcapTransport creates a transport using Npcap for true SYN scanning on Windows.
// Returns error if Npcap is not installed or privileges are insufficient → detector falls back to Connect.
func NewNpcapTransport(config *TransportConfig) (t Transport, err error) {
	if loadErr := npcapDLL.Load(); loadErr != nil {
		return nil, fmt.Errorf("npcap not available: %w", loadErr)
	}

	// DLL loaded — if init still fails, warn so the user knows why we fall back to Connect
	defer func() {
		if err != nil {
			log.Printf("WARNING: Npcap installed but unusable: %v", err)
		}
	}()

	devName, err := findPcapDevice(config.SourceIP)
	if err != nil {
		return nil, err
	}

	srcMAC, err := getInterfaceMAC(config.SourceIP)
	if err != nil {
		return nil, fmt.Errorf("cannot determine source MAC: %w", err)
	}

	localNet, localMask := getSubnetInfo(config.SourceIP)

	// Gateway is optional — local-only networks work via per-target ARP
	var gatewayMAC [6]byte
	hasGateway := false
	if gwMAC, gwErr := resolveGatewayMAC(config.SourceIP); gwErr == nil {
		copy(gatewayMAC[:], gwMAC)
		hasGateway = true
	}

	errbuf := make([]byte, 256)
	devNameC := append([]byte(devName), 0)
	handle, _, _ := procPcapOpenLive.Call(
		uintptr(unsafe.Pointer(&devNameC[0])),
		65535, // snaplen
		1,     // promisc
		1,     // timeout_ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		return nil, fmt.Errorf("pcap_open_live: %s", cstring(errbuf))
	}

	filter := fmt.Sprintf("tcp and dst host %s", config.SourceIP)
	if err := setBPFFilter(handle, filter); err != nil {
		procPcapClose.Call(handle)
		return nil, err
	}

	procPcapSetNonblock.Call(handle, 1, uintptr(unsafe.Pointer(&errbuf[0])))

	nt := &NpcapTransport{
		handle:      handle,
		sendBuf:     make([]byte, 0, 128),
		hasGateway:  hasGateway,
		gatewayMAC:  gatewayMAC,
		srcIPNative: ipToNative(config.SourceIP.To4()),
		localNet:    localNet,
		localMask:   localMask,
		macCache:    make(map[uint32][6]byte),
	}
	copy(nt.srcMAC[:], srcMAC)

	return nt, nil
}

func (n *NpcapTransport) Method() TransportMethod { return TransportNpcap }

func (n *NpcapTransport) Send(packets []*Packet) (int, error) {
	sent := 0
	for _, pkt := range packets {
		dstMAC := n.resolveDstMAC(pkt.DstIP)

		frameLen := 14 + len(pkt.Data)
		if cap(n.sendBuf) < frameLen {
			n.sendBuf = make([]byte, frameLen)
		}
		n.sendBuf = n.sendBuf[:frameLen]
		copy(n.sendBuf[0:6], dstMAC[:])
		copy(n.sendBuf[6:12], n.srcMAC[:])
		n.sendBuf[12] = 0x08 // EtherType IPv4
		n.sendBuf[13] = 0x00
		copy(n.sendBuf[14:], pkt.Data)

		ret, _, _ := procPcapSendPacket.Call(
			n.handle,
			uintptr(unsafe.Pointer(&n.sendBuf[0])),
			uintptr(frameLen),
		)
		if ret == 0 {
			sent++
		}
	}
	return sent, nil
}

// resolveDstMAC returns the destination MAC for a target IP.
// When a gateway is available, always use it (handles both local and remote targets via routing).
// Only falls back to per-target ARP on gateway-less networks.
func (n *NpcapTransport) resolveDstMAC(dstIP net.IP) [6]byte {
	if n.hasGateway {
		return n.gatewayMAC
	}

	// No gateway — must ARP each target directly (local-only network)
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return [6]byte{}
	}
	dstNative := ipToNative(dstIP4)
	if mac, ok := n.macCache[dstNative]; ok {
		return mac
	}
	if mac, err := arpResolve(dstNative, n.srcIPNative); err == nil {
		n.macCache[dstNative] = mac
		return mac
	}
	return [6]byte{}
}

// arpResolve resolves an IP to a MAC address via SendARP.
func arpResolve(dstIP, srcIP uint32) ([6]byte, error) {
	var mac [6]byte
	macBuf := make([]byte, 8)
	macLen := uint32(8)
	ret, _, _ := procSendARP.Call(
		uintptr(dstIP),
		uintptr(srcIP),
		uintptr(unsafe.Pointer(&macBuf[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 {
		// Retry with srcIP=0 (let Windows pick interface)
		macLen = 8
		ret, _, _ = procSendARP.Call(
			uintptr(dstIP),
			0,
			uintptr(unsafe.Pointer(&macBuf[0])),
			uintptr(unsafe.Pointer(&macLen)),
		)
	}
	if ret != 0 {
		return mac, fmt.Errorf("SendARP failed: %d", ret)
	}
	copy(mac[:], macBuf[:6])
	return mac, nil
}

// getSubnetInfo returns the network address and mask for the interface owning sourceIP.
func getSubnetInfo(sourceIP net.IP) (localNet, localMask uint32) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, 0
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || !ipnet.IP.Equal(sourceIP) {
				continue
			}
			ip4 := ipnet.IP.To4()
			mask4 := net.IP(ipnet.Mask).To4()
			if ip4 == nil || mask4 == nil {
				continue
			}
			m := ipToNative(mask4)
			n := ipToNative(ip4) & m
			return n, m
		}
	}
	return 0, 0
}

func (n *NpcapTransport) Receive(ctx context.Context) ([]*ReceivedPacket, error) {
	var results []*ReceivedPacket
	var hdrPtr, dataPtr unsafe.Pointer

	for range 100 {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		ret, _, _ := procPcapNextEx.Call(
			n.handle,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)),
		)
		if ret != 1 {
			break // 0=timeout, -1=error
		}
		if hdrPtr == nil || dataPtr == nil {
			continue
		}

		hdr := (*pcapPkthdr)(hdrPtr)
		if hdr.capLen < 54 { // 14 (eth) + 20 (ip) + 20 (tcp) minimum
			continue
		}

		raw := unsafe.Slice((*byte)(dataPtr), hdr.capLen)
		if pkt := parseEthernetPacket(raw); pkt != nil {
			results = append(results, pkt)
		}
	}
	return results, nil
}

func (n *NpcapTransport) Close() error {
	if n.handle != 0 {
		procPcapClose.Call(n.handle)
		n.handle = 0
	}
	return nil
}

func (n *NpcapTransport) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsSYNScan:          true,
		SupportsCustomSourcePort: true,
		SupportsRawPackets:       true,
		RequiresRoot:             true, // Administrator required
		MaxPacketsPerSecond:      500000,
	}
}

// --- Packet parsing ---

// parseEthernetPacket extracts IP/TCP fields from a raw Ethernet frame.
func parseEthernetPacket(data []byte) *ReceivedPacket {
	if len(data) < 54 {
		return nil
	}
	// EtherType must be IPv4 (0x0800)
	if data[12] != 0x08 || data[13] != 0x00 {
		return nil
	}

	ipHdrLen := int(data[14]&0x0F) * 4
	if ipHdrLen < 20 || 14+ipHdrLen+20 > len(data) {
		return nil
	}
	// Protocol must be TCP (6)
	if data[14+9] != 6 {
		return nil
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, data[14+12:14+16])

	tcpOff := 14 + ipHdrLen
	return &ReceivedPacket{
		SrcIP:     srcIP,
		SrcPort:   binary.BigEndian.Uint16(data[tcpOff : tcpOff+2]),
		DstPort:   binary.BigEndian.Uint16(data[tcpOff+2 : tcpOff+4]),
		Flags:     data[tcpOff+13],
		Timestamp: time.Now(),
	}
}

// --- Device and MAC resolution ---

// findPcapDevice enumerates Npcap devices and returns the one matching sourceIP.
func findPcapDevice(sourceIP net.IP) (string, error) {
	var allDevs unsafe.Pointer
	errbuf := make([]byte, 256)
	ret, _, _ := procPcapFindAllDevs.Call(
		uintptr(unsafe.Pointer(&allDevs)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret != 0 {
		return "", fmt.Errorf("pcap_findalldevs: %s", cstring(errbuf))
	}
	defer procPcapFreeAllDevs.Call(uintptr(allDevs))

	srcIP4 := sourceIP.To4()
	if srcIP4 == nil {
		return "", fmt.Errorf("source IP is not IPv4")
	}

	for dev := allDevs; dev != nil; {
		d := (*pcapIf)(dev)
		for a := d.addrs; a != nil; {
			addr := (*pcapAddr)(a)
			if addr.addr != nil {
				family := *(*uint16)(addr.addr)
				if family == syscall.AF_INET {
					// sockaddr_in: family(2) + port(2) + addr(4)
					ip := make(net.IP, 4)
					copy(ip, (*[4]byte)(unsafe.Add(addr.addr, 4))[:])
					if ip.Equal(srcIP4) {
						return cstringPtr(d.name), nil
					}
				}
			}
			a = addr.next
		}
		dev = d.next
	}

	return "", fmt.Errorf("no pcap device found for IP %s", sourceIP)
}

// getInterfaceMAC returns the hardware address of the interface owning sourceIP.
func getInterfaceMAC(sourceIP net.IP) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(sourceIP) && len(iface.HardwareAddr) >= 6 {
				return iface.HardwareAddr, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found with IP %s", sourceIP)
}

// resolveGatewayMAC finds a gateway and resolves its MAC via SendARP.
// Tries GetBestRoute(8.8.8.8) first, then scans the routing table for any default route.
func resolveGatewayMAC(sourceIP net.IP) (net.HardwareAddr, error) {
	srcIPNative := ipToNative(sourceIP.To4())

	gwIP := findGateway(srcIPNative)
	if gwIP == 0 {
		return nil, fmt.Errorf("no gateway found in routing table")
	}

	macBuf := make([]byte, 8)
	macLen := uint32(8)

	// Try with explicit source IP first, then with 0 (let Windows pick the best interface)
	ret, _, _ := procSendARP.Call(
		uintptr(gwIP),
		uintptr(srcIPNative),
		uintptr(unsafe.Pointer(&macBuf[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 {
		macLen = 8
		ret, _, _ = procSendARP.Call(
			uintptr(gwIP),
			0,
			uintptr(unsafe.Pointer(&macBuf[0])),
			uintptr(unsafe.Pointer(&macLen)),
		)
	}
	if ret != 0 {
		return nil, fmt.Errorf("SendARP for gateway %d.%d.%d.%d failed: %d",
			byte(gwIP), byte(gwIP>>8), byte(gwIP>>16), byte(gwIP>>24), ret)
	}

	return net.HardwareAddr(macBuf[:6]), nil
}

// findGateway returns the gateway IP (native byte order) using two methods:
// 1. GetBestRoute to 8.8.8.8 (fast, works when internet route exists)
// 2. Scan routing table for any default route 0.0.0.0 (works on local-only networks)
func findGateway(srcIPNative uint32) uint32 {
	// Method 1: GetBestRoute to internet
	var route mibIPForwardRow
	remoteIP := ipToNative(net.IPv4(8, 8, 8, 8).To4())
	ret, _, _ := procGetBestRoute.Call(
		uintptr(remoteIP),
		uintptr(srcIPNative),
		uintptr(unsafe.Pointer(&route)),
	)
	if ret == 0 && route.nextHop != 0 {
		return route.nextHop
	}

	// Method 2: scan full routing table for default gateway (dest=0.0.0.0, nextHop!=0)
	var size uint32
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	ret, _, _ = procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if ret != 0 {
		return 0
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	const rowSize = unsafe.Sizeof(mibIPForwardRow{})
	for i := uint32(0); i < numEntries; i++ {
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[4+uintptr(i)*rowSize]))
		if row.dest == 0 && row.nextHop != 0 {
			return row.nextHop
		}
	}
	return 0
}

// --- BPF filter ---

func setBPFFilter(handle uintptr, filter string) error {
	var fp bpfProgram
	filterC := append([]byte(filter), 0)

	ret, _, _ := procPcapCompile.Call(
		handle,
		uintptr(unsafe.Pointer(&fp)),
		uintptr(unsafe.Pointer(&filterC[0])),
		1, // optimize
		0, // netmask (0 = any)
	)
	if ret != 0 {
		return fmt.Errorf("pcap_compile failed for filter: %s", filter)
	}
	// Note: compiled bpf_program is leaked (pcap_freecode not called).
	// Single allocation per scan lifetime, negligible.

	ret, _, _ = procPcapSetFilter.Call(handle, uintptr(unsafe.Pointer(&fp)))
	if ret != 0 {
		return fmt.Errorf("pcap_setfilter failed")
	}
	return nil
}

// --- String helpers ---

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func cstringPtr(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var buf []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Add(ptr, i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// ipToNative converts a 4-byte IP to uint32 for Windows API calls (network byte order as native uint32).
func ipToNative(ip net.IP) uint32 {
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}
