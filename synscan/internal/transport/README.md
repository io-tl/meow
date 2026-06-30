# Transport Layer Architecture

synscan's transport system is modular and cross-platform. It automatically detects the best available method based on the platform and privileges.

## Architecture

```
internal/transport/
├── transport.go              # Common interface (cross-platform)
├── connect.go                # Connect mode (cross-platform)
│
├── detector_linux.go         # Linux detection
├── afpacket_linux.go         # AF_PACKET + mmap (Linux only)
├── rawsocket_linux.go        # Raw sockets + sendmmsg (Linux)
│
├── detector_windows.go       # Windows detection
└── rawsocket_windows.go      # Windows raw sockets (limited)
```

## Transport Methods

### Linux

#### 1. AF_PACKET + mmap (PACKET_TX_RING/RX_RING)
- **Performance**: ~2M PPS
- **Required**: Root/CAP_NET_RAW + kernel 2.6.27+
- **Advantages**: Zero-copy I/O, minimal latency
- **File**: `afpacket_linux.go`

#### 2. Raw Socket + sendmmsg/recvmmsg
- **Performance**: ~500K PPS
- **Required**: Root/CAP_NET_RAW
- **Advantages**: Compatible with old 2.6.x, efficient batching
- **File**: `rawsocket_linux.go`

#### 3. Connect() Mode
- **Performance**: ~10K PPS
- **Required**: No privileges
- **Advantages**: Works everywhere
- **File**: `connect.go`

### Windows

#### 1. Raw Socket (NOT SUPPORTED)
- **Status**: Disabled
- **Reason**: Windows XP SP2+ does not support IP_HDRINCL for TCP
- **File**: `rawsocket_windows.go`

#### 2. Connect() Mode
- **Performance**: ~10K PPS
- **Required**: No privileges
- **Advantages**: Only reliable method on Windows
- **File**: `connect.go`

## Automatic Detection

The system tries the transports in order of performance:

**Linux**:
```
AF_PACKET+mmap → Raw Socket → Connect
```

**Windows**:
```
Raw Socket (failure) → Connect
```

## Transport Interface

Each transport implements the interface:

```go
type Transport interface {
    Method() TransportMethod
    Send(packets []*Packet) (int, error)
    Receive(ctx context.Context) ([]*ReceivedPacket, error)
    Close() error
    GetCapabilities() Capabilities
}
```

## Capabilities

Each transport exposes its capabilities:

```go
type Capabilities struct {
    SupportsSYNScan          bool  // True SYN scan
    SupportsCustomSourcePort bool  // Custom source port
    SupportsRawPackets       bool  // Packet forging
    RequiresRoot             bool  // Privileges required
    MaxPacketsPerSecond      int   // Estimated PPS
}
```

## Build Tags

Go automatically uses the file suffixes:
- `*_linux.go` → compiled only on Linux
- `*_windows.go` → compiled only on Windows
- `*.go` (no suffix) → cross-platform

No need for explicit `// +build` tags!

## Cross-Platform Compilation

```bash
# Linux
make build

# Windows (from Linux)
GOOS=windows GOARCH=amd64 go build -o synscan.exe ./cmd/synscan

# Standalone binary (no dependencies)
CGO_ENABLED=0 go build -o synscan ./cmd/synscan
```

## Why Not WinPcap/Npcap?

- **External dependency**: Requires separate installation
- **Complexity**: CGO bindings, drivers
- **Portability**: The binary would no longer be standalone

Connect mode is largely sufficient for most use cases on Windows.

## Future Extensions

To add a new transport:

1. Create `newmethod_<platform>.go`
2. Implement the `Transport` interface
3. Add it to `detector_<platform>.go`
4. No scanner modification needed!

## Windows Limitations

Windows raw sockets do **not** allow:
- ❌ Forging the IP header (IP_HDRINCL)
- ❌ SYN scan stealthy
- ❌ Custom source port

Only Connect mode works (full TCP connection).
