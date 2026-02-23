package transport

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const (
	// SYS_SENDMMSG and SYS_RECVMMSG syscall numbers
	SYS_SENDMMSG = 307
	SYS_RECVMMSG = 299
)

// Structures for sendmmsg/recvmmsg
type mmsghdr struct {
	msghdr syscall.Msghdr
	msglen uint32
	_      [4]byte // padding for 64-bit alignment
}

type iovec struct {
	base *byte
	len  uint64
}

// RawSocketTransport implements Transport using raw sockets with sendmmsg/recvmmsg
type RawSocketTransport struct {
	config     *TransportConfig
	sendSocket int
	recvSocket int
	sendBatch  *rawSendBatch
	recvBatch  *rawRecvBatch
}

// rawSendBatch handles batched sending
type rawSendBatch struct {
	msgs    []mmsghdr
	iovecs  []iovec
	addrs   []syscall.RawSockaddrInet4
	packets [][]byte
	size    int
}

// rawRecvBatch handles batched receiving
type rawRecvBatch struct {
	msgs    []mmsghdr
	iovecs  []iovec
	buffers [][]byte
	size    int
}

// NewRawSocketTransport creates a new raw socket transport
func NewRawSocketTransport(config *TransportConfig) (Transport, error) {
	// Create send socket
	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create send socket (need CAP_NET_RAW): %w", err)
	}

	// Enable IP_HDRINCL to control IP header
	if err := syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendSocket)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Create receive socket
	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendSocket)
		return nil, fmt.Errorf("failed to create receive socket: %w", err)
	}

	// Set receive timeout
	tv := syscall.Timeval{
		Sec:  0,
		Usec: 100000, // 100ms
	}
	if err := syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(sendSocket)
		syscall.Close(recvSocket)
		return nil, fmt.Errorf("failed to set receive timeout: %w", err)
	}

	// Set batch sizes with defaults if not specified
	sendBatchSize := config.SendBatchSize
	if sendBatchSize <= 0 {
		sendBatchSize = 64
	}
	recvBatchSize := config.RecvBatchSize
	if recvBatchSize <= 0 {
		recvBatchSize = 128
	}

	return &RawSocketTransport{
		config:     config,
		sendSocket: sendSocket,
		recvSocket: recvSocket,
		sendBatch:  newRawSendBatch(sendBatchSize),
		recvBatch:  newRawRecvBatch(recvBatchSize, 4096),
	}, nil
}

func newRawSendBatch(size int) *rawSendBatch {
	sb := &rawSendBatch{
		msgs:    make([]mmsghdr, size),
		iovecs:  make([]iovec, size),
		addrs:   make([]syscall.RawSockaddrInet4, size),
		packets: make([][]byte, size),
		size:    size,
	}

	// Pre-allocate packet buffers (max size for IP+TCP)
	for i := 0; i < size; i++ {
		sb.packets[i] = make([]byte, 1500)
		sb.iovecs[i].base = &sb.packets[i][0]

		sb.msgs[i].msghdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&sb.iovecs[i]))
		sb.msgs[i].msghdr.Iovlen = 1
		sb.msgs[i].msghdr.Name = (*byte)(unsafe.Pointer(&sb.addrs[i]))
		sb.msgs[i].msghdr.Namelen = uint32(syscall.SizeofSockaddrInet4)
	}

	return sb
}

func newRawRecvBatch(size, bufferSize int) *rawRecvBatch {
	rb := &rawRecvBatch{
		msgs:    make([]mmsghdr, size),
		iovecs:  make([]iovec, size),
		buffers: make([][]byte, size),
		size:    size,
	}

	for i := 0; i < size; i++ {
		rb.buffers[i] = make([]byte, bufferSize)
		rb.iovecs[i].base = &rb.buffers[i][0]
		rb.iovecs[i].len = uint64(bufferSize)
		rb.msgs[i].msghdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&rb.iovecs[i]))
		rb.msgs[i].msghdr.Iovlen = 1
	}

	return rb
}

func (r *RawSocketTransport) Method() TransportMethod {
	return TransportRawSocket
}

func (r *RawSocketTransport) Send(packets []*Packet) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}

	// Prepare batch
	batchSize := len(packets)
	if batchSize > r.sendBatch.size {
		batchSize = r.sendBatch.size
	}

	for i := 0; i < batchSize; i++ {
		pkt := packets[i]

		// Copy packet data
		copy(r.sendBatch.packets[i], pkt.Data)
		r.sendBatch.iovecs[i].len = uint64(len(pkt.Data))

		// Set destination address
		r.sendBatch.addrs[i].Family = syscall.AF_INET
		copy(r.sendBatch.addrs[i].Addr[:], pkt.DstIP.To4())
	}

	// Send batch using sendmmsg
	n, _, errno := syscall.Syscall6(
		SYS_SENDMMSG,
		uintptr(r.sendSocket),
		uintptr(unsafe.Pointer(&r.sendBatch.msgs[0])),
		uintptr(batchSize),
		0, // flags
		0, 0,
	)

	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func (r *RawSocketTransport) Receive(ctx context.Context) ([]*ReceivedPacket, error) {
	// Receive packets using recvmmsg
	n, _, errno := syscall.Syscall6(
		SYS_RECVMMSG,
		uintptr(r.recvSocket),
		uintptr(unsafe.Pointer(&r.recvBatch.msgs[0])),
		uintptr(r.recvBatch.size),
		0, // flags
		0, // timeout (NULL)
		0,
	)

	if errno != 0 {
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.EINTR {
			return nil, nil // No packets available
		}
		return nil, errno
	}

	if n == 0 {
		return nil, nil
	}

	// Parse received packets
	received := make([]*ReceivedPacket, 0, n)
	now := time.Now()

	for i := 0; i < int(n); i++ {
		length := r.recvBatch.msgs[i].msglen
		buf := r.recvBatch.buffers[i][:length]

		if len(buf) < 40 { // Minimum IP + TCP header size
			continue
		}

		// Parse IP header
		ipHeaderLen := int(buf[0]&0x0F) * 4
		if len(buf) < ipHeaderLen+20 {
			continue
		}

		// Extract source IP
		srcIP := make([]byte, 4)
		copy(srcIP, buf[12:16])

		// Parse TCP header
		tcpHeader := buf[ipHeaderLen:]
		srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
		dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])
		flags := tcpHeader[13]

		received = append(received, &ReceivedPacket{
			Data:      append([]byte(nil), buf...), // Copy buffer
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Flags:     flags,
			Timestamp: now,
		})
	}

	return received, nil
}

func (r *RawSocketTransport) Close() error {
	syscall.Close(r.sendSocket)
	syscall.Close(r.recvSocket)
	return nil
}

func (r *RawSocketTransport) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsSYNScan:          true,
		SupportsCustomSourcePort: true,
		SupportsRawPackets:       true,
		RequiresRoot:             true,
		MaxPacketsPerSecond:      500000, // Estimate: ~500K PPS with sendmmsg
	}
}
