package transport

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	// Socket options
	PACKET_RX_RING      = 5
	PACKET_TX_RING      = 13
	PACKET_VERSION      = 10
	PACKET_LOSS         = 14
	PACKET_QDISC_BYPASS = 20

	// Packet versions
	TPACKET_V3 = 3

	// Frame status
	TP_STATUS_KERNEL       = 0
	TP_STATUS_USER         = 1 << 0
	TP_STATUS_SEND_REQUEST = 1 << 1
	TP_STATUS_SENDING      = 1 << 2
	TP_STATUS_WRONG_FORMAT = 1 << 3
	TP_STATUS_AVAILABLE    = 0

	// Default frame size and counts
	DefaultFrameSize = 2048
	DefaultBlockSize = 4096
)

// tpacket_req3 is the request structure for TPACKET_V3
type tpacket_req3 struct {
	block_size       uint32
	block_nr         uint32
	frame_size       uint32
	frame_nr         uint32
	retire_blk_tov   uint32
	sizeof_priv      uint32
	feature_req_word uint32
}

// tpacket3_hdr is the header for TPACKET_V3 frames
type tpacket3_hdr struct {
	tp_next_offset uint32
	tp_sec         uint32
	tp_nsec        uint32
	tp_snaplen     uint32
	tp_len         uint32
	tp_status      uint32
	tp_mac         uint16
	tp_net         uint16
	hv1_union      [24]byte // Union with hardware-specific fields
}

// AFPacketTransport implements Transport using AF_PACKET with mmap
type AFPacketTransport struct {
	config  *TransportConfig
	fd      int
	ifIndex int

	// TX ring
	txRing     []byte
	txReq      tpacket_req3
	txFrameNum int

	// RX ring
	rxRing     []byte
	rxReq      tpacket_req3
	rxFrameNum int

	// Interface info for crafting Ethernet frames
	ifaceMAC   net.HardwareAddr
	gatewayMAC net.HardwareAddr
}

// NewAFPacketTransport creates a new AF_PACKET transport with mmap rings
func NewAFPacketTransport(config *TransportConfig) (Transport, error) {
	// Create AF_PACKET socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET socket (need CAP_NET_RAW): %w", err)
	}

	// Set TPACKET_V3
	version := TPACKET_V3
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_VERSION, version); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set PACKET_VERSION (kernel 2.6.27+ required): %w", err)
	}

	// Enable QDISC bypass for better performance
	bypass := 1
	syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_QDISC_BYPASS, bypass)

	// Allow packet loss instead of blocking
	loss := 1
	syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_LOSS, loss)

	// Get interface index
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("interface %s not found: %w", config.Interface, err)
	}

	// Bind to interface
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &sll); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface: %w", err)
	}

	t := &AFPacketTransport{
		config:   config,
		fd:       fd,
		ifIndex:  iface.Index,
		ifaceMAC: iface.HardwareAddr,
	}

	// Get gateway MAC address
	if err := t.resolveGatewayMAC(); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to resolve gateway MAC: %w", err)
	}

	// Setup TX and RX rings
	if err := t.setupTXRing(); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to setup TX ring: %w", err)
	}

	if err := t.setupRXRing(); err != nil {
		syscall.Munmap(t.txRing)
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to setup RX ring: %w", err)
	}

	return t, nil
}

func (a *AFPacketTransport) setupTXRing() error {
	// Calculate ring parameters
	frameSize := uint32(DefaultFrameSize)
	blockSize := uint32(DefaultBlockSize)
	if blockSize < frameSize {
		blockSize = frameSize
	}

	// Use ringSize from config if available
	ringSize := a.config.RingSize
	if ringSize <= 0 {
		ringSize = 256 // Default number of frames
	}

	blockNr := uint32(ringSize) * frameSize / blockSize
	if blockNr == 0 {
		blockNr = 1
	}
	frameNr := blockNr * blockSize / frameSize

	a.txReq = tpacket_req3{
		block_size: blockSize,
		block_nr:   blockNr,
		frame_size: frameSize,
		frame_nr:   frameNr,
	}

	// Setup TX ring
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(a.fd),
		uintptr(syscall.SOL_PACKET),
		uintptr(PACKET_TX_RING),
		uintptr(unsafe.Pointer(&a.txReq)),
		unsafe.Sizeof(a.txReq),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt PACKET_TX_RING: %v", errno)
	}

	// mmap TX ring
	size := int(a.txReq.block_size * a.txReq.block_nr)
	txRing, err := syscall.Mmap(
		a.fd,
		0,
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("mmap TX ring: %w", err)
	}

	a.txRing = txRing
	a.txFrameNum = 0

	return nil
}

func (a *AFPacketTransport) setupRXRing() error {
	// Calculate ring parameters
	frameSize := uint32(DefaultFrameSize)
	blockSize := uint32(DefaultBlockSize)
	if blockSize < frameSize {
		blockSize = frameSize
	}

	// Use ringSize from config if available
	ringSize := a.config.RingSize
	if ringSize <= 0 {
		ringSize = 512 // Default number of frames (more for RX)
	}

	blockNr := uint32(ringSize) * frameSize / blockSize
	if blockNr == 0 {
		blockNr = 1
	}
	frameNr := blockNr * blockSize / frameSize

	a.rxReq = tpacket_req3{
		block_size:     blockSize,
		block_nr:       blockNr,
		frame_size:     frameSize,
		frame_nr:       frameNr,
		retire_blk_tov: 100, // 100ms timeout
	}

	// Setup RX ring
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(a.fd),
		uintptr(syscall.SOL_PACKET),
		uintptr(PACKET_RX_RING),
		uintptr(unsafe.Pointer(&a.rxReq)),
		unsafe.Sizeof(a.rxReq),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt PACKET_RX_RING: %v", errno)
	}

	// mmap RX ring (must be mapped after TX ring if both exist)
	size := int(a.rxReq.block_size * a.rxReq.block_nr)
	offset := int(a.txReq.block_size * a.txReq.block_nr)

	rxRing, err := syscall.Mmap(
		a.fd,
		int64(offset),
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("mmap RX ring: %w", err)
	}

	a.rxRing = rxRing
	a.rxFrameNum = 0

	return nil
}

func (a *AFPacketTransport) resolveGatewayMAC() error {
	// For simplicity, we'll use broadcast MAC
	// In production, you'd want to do ARP resolution
	a.gatewayMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// TODO: Implement proper ARP resolution or gateway MAC discovery
	// For now, try to get first route's gateway

	return nil
}

func (a *AFPacketTransport) Method() TransportMethod {
	return TransportAFPacket
}

func (a *AFPacketTransport) Send(packets []*Packet) (int, error) {
	sent := 0

	for _, pkt := range packets {
		// Get next TX frame
		frameOffset := (a.txFrameNum % int(a.txReq.frame_nr)) * int(a.txReq.frame_size)
		frame := a.txRing[frameOffset:]

		// Check if frame is available
		status := (*uint32)(unsafe.Pointer(&frame[offsetof_tp_status()]))
		if *status != TP_STATUS_AVAILABLE {
			// Frame not available, try to flush
			break
		}

		// Build Ethernet + IP + TCP packet
		ethFrame := a.buildEthFrame(pkt)
		if len(ethFrame) > int(a.txReq.frame_size)-256 {
			continue // Packet too large
		}

		// Copy packet to frame
		headerSize := 256 // TPACKET3 header size estimate
		copy(frame[headerSize:], ethFrame)

		// Set packet length
		tpLen := (*uint32)(unsafe.Pointer(&frame[offsetof_tp_len()]))
		*tpLen = uint32(len(ethFrame))

		// Mark frame for sending
		*status = TP_STATUS_SEND_REQUEST

		a.txFrameNum++
		sent++
	}

	if sent > 0 {
		// Trigger send
		syscall.Sendto(a.fd, []byte{}, 0, nil)
	}

	return sent, nil
}

func (a *AFPacketTransport) buildEthFrame(pkt *Packet) []byte {
	// Ethernet header (14 bytes) + IP + TCP data
	frame := make([]byte, 14+len(pkt.Data))

	// Ethernet header
	copy(frame[0:6], a.gatewayMAC) // Destination MAC
	copy(frame[6:12], a.ifaceMAC)  // Source MAC
	frame[12] = 0x08               // EtherType: IPv4
	frame[13] = 0x00

	// IP + TCP packet
	copy(frame[14:], pkt.Data)

	return frame
}

func (a *AFPacketTransport) Receive(ctx context.Context) ([]*ReceivedPacket, error) {
	received := make([]*ReceivedPacket, 0, 32)

	// Poll RX ring for packets
	maxFrames := 64
	for i := 0; i < maxFrames; i++ {
		frameOffset := (a.rxFrameNum % int(a.rxReq.frame_nr)) * int(a.rxReq.frame_size)
		frame := a.rxRing[frameOffset:]

		// Check if frame has data
		status := (*uint32)(unsafe.Pointer(&frame[offsetof_tp_status()]))
		if *status&TP_STATUS_USER == 0 {
			break // No more packets
		}

		// Get packet data
		tpLen := (*uint32)(unsafe.Pointer(&frame[offsetof_tp_len()]))
		tpNet := (*uint16)(unsafe.Pointer(&frame[offsetof_tp_net()]))

		headerSize := int(*tpNet)
		packetSize := int(*tpLen)

		if packetSize > 0 && headerSize+packetSize <= int(a.rxReq.frame_size) {
			// Skip Ethernet header, get IP packet
			ipPacket := frame[headerSize : headerSize+packetSize]

			// Parse packet
			if pkt := a.parsePacket(ipPacket); pkt != nil {
				received = append(received, pkt)
			}
		}

		// Release frame back to kernel
		*status = TP_STATUS_KERNEL

		a.rxFrameNum++
	}

	if len(received) == 0 {
		return nil, nil
	}

	return received, nil
}

func (a *AFPacketTransport) parsePacket(buf []byte) *ReceivedPacket {
	if len(buf) < 40 {
		return nil
	}

	// Parse IP header
	ipHeaderLen := int(buf[0]&0x0F) * 4
	if len(buf) < ipHeaderLen+20 {
		return nil
	}

	// Extract source IP
	srcIP := make([]byte, 4)
	copy(srcIP, buf[12:16])

	// Parse TCP header
	tcpHeader := buf[ipHeaderLen:]
	srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
	dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])
	flags := tcpHeader[13]

	return &ReceivedPacket{
		Data:      append([]byte(nil), buf...),
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Flags:     flags,
		Timestamp: time.Now(),
	}
}

func (a *AFPacketTransport) Close() error {
	if a.txRing != nil {
		syscall.Munmap(a.txRing)
	}
	if a.rxRing != nil {
		syscall.Munmap(a.rxRing)
	}
	if a.fd >= 0 {
		syscall.Close(a.fd)
	}
	return nil
}

func (a *AFPacketTransport) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsSYNScan:          true,
		SupportsCustomSourcePort: true,
		SupportsRawPackets:       true,
		RequiresRoot:             true,
		MaxPacketsPerSecond:      2000000, // Estimate: ~2M PPS with mmap
	}
}

// Helper functions to get field offsets in tpacket3_hdr
func offsetof_tp_status() uintptr {
	return 20 // Offset of tp_status in tpacket3_hdr
}

func offsetof_tp_len() uintptr {
	return 16 // Offset of tp_len in tpacket3_hdr
}

func offsetof_tp_net() uintptr {
	return 26 // Offset of tp_net in tpacket3_hdr
}
