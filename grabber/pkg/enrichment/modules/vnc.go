package modules

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// VNCModule implements the VNC enrichment module
type VNCModule struct {
	BaseModule
}

type VNCResult struct {
	Protocol         string   `json:"protocol"`
	Version          string   `json:"version,omitempty"`
	SecurityTypes    []string `json:"security_types,omitempty"`
	Authentication   bool     `json:"authentication_required"`
	Width            uint16   `json:"width,omitempty"`
	Height           uint16   `json:"height,omitempty"`
	DesktopName      string   `json:"desktop_name,omitempty"`
	Screenshot       string   `json:"screenshot,omitempty"` // Base64 PNG
	ScreenshotFormat string   `json:"screenshot_format,omitempty"`
	Error            string   `json:"error,omitempty"`
}

func init() {
	Register(&VNCModule{
		BaseModule: NewBaseModule("vnc", []string{"rfb"}, true, 15*time.Second),
	})
}

func (m *VNCModule) Scan(ip string, port int) (interface{}, error) {
	result := &VNCResult{Protocol: "vnc"}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read server version
	version, _ := reader.ReadString('\n')
	if !strings.HasPrefix(version, "RFB ") {
		result.Error = "Invalid VNC handshake"
		return result, fmt.Errorf("invalid VNC handshake")
	}

	result.Version = strings.TrimSpace(version)

	// Send client version
	conn.Write([]byte(version))

	// Read security types
	secByte := make([]byte, 1)
	_, err = reader.Read(secByte)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	numSec := int(secByte[0])
	hasNoAuth := false

	if numSec > 0 && numSec < 20 {
		secTypes := make([]byte, numSec)
		n, err := reader.Read(secTypes)
		if err != nil || n != numSec {
			result.Error = "failed to read security types"
			return result, nil
		}
		for _, st := range secTypes {
			secName := getSecurityTypeName(st)
			result.SecurityTypes = append(result.SecurityTypes, secName)
			if st == 1 {
				hasNoAuth = true
			} else if st != 1 {
				result.Authentication = true
			}
		}
	}

	// Try to capture screenshot if no authentication required
	if hasNoAuth {
		captureVNCScreenshot(conn, reader, result)
	}

	return result, nil
}

// getSecurityTypeName returns the name for a VNC security type
func getSecurityTypeName(secType byte) string {
	switch secType {
	case 0:
		return "Invalid"
	case 1:
		return "None"
	case 2:
		return "VNC Authentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 17:
		return "Ultra"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 20:
		return "GTK-VNC SASL"
	case 21:
		return "MD5 hash authentication"
	case 22:
		return "Colin Dean xvp"
	case 30:
		return "Apple Remote Desktop"
	default:
		return fmt.Sprintf("Unknown (%d)", secType)
	}
}

// captureVNCScreenshot attempts to capture a screenshot from an unauthenticated VNC server
func captureVNCScreenshot(conn net.Conn, reader *bufio.Reader, result *VNCResult) {
	// Select security type 1 (None)
	conn.Write([]byte{1})

	// Read security result (RFB 3.8+)
	secResult := make([]byte, 4)
	n, err := reader.Read(secResult)
	if err != nil || (n == 4 && binary.BigEndian.Uint32(secResult) != 0) {
		return
	}

	// Send ClientInit (shared flag = 1)
	conn.Write([]byte{1})

	// Read ServerInit
	serverInit := make([]byte, 24)
	n, err = reader.Read(serverInit)
	if err != nil || n < 24 {
		return
	}

	result.Width = binary.BigEndian.Uint16(serverInit[0:2])
	result.Height = binary.BigEndian.Uint16(serverInit[2:4])

	// Read desktop name
	nameLength := binary.BigEndian.Uint32(serverInit[20:24])
	if nameLength > 0 && nameLength < 256 {
		nameBytes := make([]byte, nameLength)
		reader.Read(nameBytes)
		result.DesktopName = string(nameBytes)
	}

	// Request framebuffer update (only a small portion to save bandwidth)
	width := result.Width
	height := result.Height
	if width > 320 {
		width = 320
	}
	if height > 240 {
		height = 240
	}

	// FramebufferUpdateRequest: incremental=0, x=0, y=0, w=width, h=height
	fbUpdateReq := make([]byte, 10)
	fbUpdateReq[0] = 3 // Message type: FramebufferUpdateRequest
	fbUpdateReq[1] = 0 // Incremental: false
	binary.BigEndian.PutUint16(fbUpdateReq[2:4], 0)      // X position
	binary.BigEndian.PutUint16(fbUpdateReq[4:6], 0)      // Y position
	binary.BigEndian.PutUint16(fbUpdateReq[6:8], width)  // Width
	binary.BigEndian.PutUint16(fbUpdateReq[8:10], height) // Height

	conn.Write(fbUpdateReq)

	// Read FramebufferUpdate header
	fbHeader := make([]byte, 4)
	n, err = reader.Read(fbHeader)
	if err != nil || n < 4 || fbHeader[0] != 0 {
		return
	}

	numRects := binary.BigEndian.Uint16(fbHeader[2:4])
	if numRects == 0 || numRects > 100 {
		return
	}

	// Try to read first rectangle and create a thumbnail
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))

	for i := uint16(0); i < numRects && i < 10; i++ {
		rectHeader := make([]byte, 12)
		n, err = reader.Read(rectHeader)
		if err != nil || n < 12 {
			break
		}

		encoding := binary.BigEndian.Uint32(rectHeader[8:12])

		// Only handle Raw encoding (0) for simplicity
		if encoding != 0 {
			break
		}

		rectWidth := binary.BigEndian.Uint16(rectHeader[4:6])
		rectHeight := binary.BigEndian.Uint16(rectHeader[6:8])

		// Read pixel data (assuming 32-bit RGBA)
		pixelDataSize := int(rectWidth) * int(rectHeight) * 4
		if pixelDataSize > 1024*1024 {
			break
		}

		pixelData := make([]byte, pixelDataSize)
		_, err = reader.Read(pixelData)
		if err != nil {
			break
		}

		// Simple conversion to image (this is simplified)
		if i == 0 {
			for y := 0; y < int(rectHeight) && y < int(height); y++ {
				for x := 0; x < int(rectWidth) && x < int(width); x++ {
					idx := (y*int(rectWidth) + x) * 4
					if idx+2 < len(pixelData) {
						img.Set(x, y, color.RGBA{
							R: pixelData[idx+2],
							G: pixelData[idx+1],
							B: pixelData[idx],
							A: 255,
						})
					}
				}
			}
		}
	}

	// Encode to PNG
	var buf bytes.Buffer
	err = png.Encode(&buf, img)
	if err == nil && buf.Len() > 0 {
		result.Screenshot = fmt.Sprintf("data:image/png;base64,%s",
			bytesToBase64(buf.Bytes()))
		result.ScreenshotFormat = "png"
	}
}

// bytesToBase64 converts bytes to base64 string
func bytesToBase64(data []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder

	for i := 0; i < len(data); i += 3 {
		b := (uint32(data[i]) << 16)
		if i+1 < len(data) {
			b |= uint32(data[i+1]) << 8
		}
		if i+2 < len(data) {
			b |= uint32(data[i+2])
		}

		result.WriteByte(base64Table[(b>>18)&0x3F])
		result.WriteByte(base64Table[(b>>12)&0x3F])
		if i+1 < len(data) {
			result.WriteByte(base64Table[(b>>6)&0x3F])
		} else {
			result.WriteByte('=')
		}
		if i+2 < len(data) {
			result.WriteByte(base64Table[b&0x3F])
		} else {
			result.WriteByte('=')
		}
	}

	return result.String()
}
