package modules

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
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

type vncPixelFormat struct {
	BitsPerPixel uint8
	Depth        uint8
	BigEndian    bool
	TrueColor    bool
	RedMax       uint16
	GreenMax     uint16
	BlueMax      uint16
	RedShift     uint8
	GreenShift   uint8
	BlueShift    uint8
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
	if _, err := conn.Write([]byte(version)); err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read security types
	secByte := make([]byte, 1)
	if _, err := io.ReadFull(reader, secByte); err != nil {
		result.Error = err.Error()
		return result, err
	}

	numSec := int(secByte[0])
	hasNoAuth := false

	if numSec > 0 && numSec < 20 {
		secTypes := make([]byte, numSec)
		if _, err := io.ReadFull(reader, secTypes); err != nil {
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
	if _, err := conn.Write([]byte{1}); err != nil {
		return
	}

	// Read security result (RFB 3.8+)
	secResult := make([]byte, 4)
	if _, err := io.ReadFull(reader, secResult); err != nil || binary.BigEndian.Uint32(secResult) != 0 {
		return
	}

	// Send ClientInit (shared flag = 1)
	if _, err := conn.Write([]byte{1}); err != nil {
		return
	}

	// Read ServerInit
	serverInit := make([]byte, 24)
	if _, err := io.ReadFull(reader, serverInit); err != nil {
		return
	}

	result.Width = binary.BigEndian.Uint16(serverInit[0:2])
	result.Height = binary.BigEndian.Uint16(serverInit[2:4])
	pixelFormat := parseVNCPixelFormat(serverInit[4:20])

	// Read desktop name
	nameLength := binary.BigEndian.Uint32(serverInit[20:24])
	if nameLength > 0 && nameLength < 256 {
		nameBytes := make([]byte, nameLength)
		if _, err := io.ReadFull(reader, nameBytes); err != nil {
			return
		}
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
	fbUpdateReq[0] = 3                                    // Message type: FramebufferUpdateRequest
	fbUpdateReq[1] = 0                                    // Incremental: false
	binary.BigEndian.PutUint16(fbUpdateReq[2:4], 0)       // X position
	binary.BigEndian.PutUint16(fbUpdateReq[4:6], 0)       // Y position
	binary.BigEndian.PutUint16(fbUpdateReq[6:8], width)   // Width
	binary.BigEndian.PutUint16(fbUpdateReq[8:10], height) // Height

	if _, err := conn.Write(fbUpdateReq); err != nil {
		return
	}

	// Read FramebufferUpdate header
	fbHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, fbHeader); err != nil || fbHeader[0] != 0 {
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
		if _, err := io.ReadFull(reader, rectHeader); err != nil {
			break
		}

		rectX := binary.BigEndian.Uint16(rectHeader[0:2])
		rectY := binary.BigEndian.Uint16(rectHeader[2:4])
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
		if _, err := io.ReadFull(reader, pixelData); err != nil {
			break
		}

		bytesPerPixel := int(pixelFormat.BitsPerPixel) / 8
		if bytesPerPixel == 0 {
			break
		}

		for y := 0; y < int(rectHeight) && int(rectY)+y < int(height); y++ {
			for x := 0; x < int(rectWidth) && int(rectX)+x < int(width); x++ {
				idx := (y*int(rectWidth) + x) * bytesPerPixel
				if idx+bytesPerPixel > len(pixelData) {
					break
				}
				img.Set(int(rectX)+x, int(rectY)+y, decodeVNCPixel(pixelData[idx:idx+bytesPerPixel], pixelFormat))
			}
		}
	}

	// Encode to PNG
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	if err == nil && buf.Len() > 0 {
		result.Screenshot = fmt.Sprintf("data:image/png;base64,%s",
			base64.StdEncoding.EncodeToString(buf.Bytes()))
		result.ScreenshotFormat = "png"
	}
}

func parseVNCPixelFormat(data []byte) vncPixelFormat {
	if len(data) < 16 {
		return vncPixelFormat{BitsPerPixel: 32, Depth: 24, TrueColor: true, RedMax: 255, GreenMax: 255, BlueMax: 255, RedShift: 16, GreenShift: 8, BlueShift: 0}
	}

	return vncPixelFormat{
		BitsPerPixel: data[0],
		Depth:        data[1],
		BigEndian:    data[2] != 0,
		TrueColor:    data[3] != 0,
		RedMax:       binary.BigEndian.Uint16(data[4:6]),
		GreenMax:     binary.BigEndian.Uint16(data[6:8]),
		BlueMax:      binary.BigEndian.Uint16(data[8:10]),
		RedShift:     data[10],
		GreenShift:   data[11],
		BlueShift:    data[12],
	}
}

func decodeVNCPixel(data []byte, format vncPixelFormat) color.RGBA {
	if !format.TrueColor || len(data) == 0 {
		return color.RGBA{A: 255}
	}

	var raw uint32
	switch len(data) {
	case 1:
		raw = uint32(data[0])
	case 2:
		if format.BigEndian {
			raw = uint32(binary.BigEndian.Uint16(data))
		} else {
			raw = uint32(binary.LittleEndian.Uint16(data))
		}
	case 4:
		if format.BigEndian {
			raw = binary.BigEndian.Uint32(data)
		} else {
			raw = binary.LittleEndian.Uint32(data)
		}
	default:
		for i := 0; i < len(data); i++ {
			if format.BigEndian {
				raw = (raw << 8) | uint32(data[i])
			} else {
				raw |= uint32(data[i]) << (8 * i)
			}
		}
	}

	return color.RGBA{
		R: scaleVNCColor((raw>>format.RedShift)&uint32(format.RedMax), format.RedMax),
		G: scaleVNCColor((raw>>format.GreenShift)&uint32(format.GreenMax), format.GreenMax),
		B: scaleVNCColor((raw>>format.BlueShift)&uint32(format.BlueMax), format.BlueMax),
		A: 255,
	}
}

func scaleVNCColor(value uint32, max uint16) uint8 {
	if max == 0 {
		return 0
	}
	return uint8((value * 255) / uint32(max))
}
