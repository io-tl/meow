package modules

import (
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

// X11Module implements the X11 enrichment module
type X11Module struct {
	BaseModule
}

type X11Result struct {
	Protocol         string   `json:"protocol"`
	Version          string   `json:"version,omitempty"`
	Vendor           string   `json:"vendor,omitempty"`
	Release          uint32   `json:"release,omitempty"`
	MaxRequestLength uint16   `json:"max_request_length,omitempty"`
	Screens          int      `json:"screens,omitempty"`
	PixmapFormats    int      `json:"pixmap_formats,omitempty"`
	Width            uint16   `json:"width,omitempty"`
	Height           uint16   `json:"height,omitempty"`
	RootWindow       uint32   `json:"root_window,omitempty"`
	AuthRequired     bool     `json:"auth_required"`
	AuthMethods      []string `json:"auth_methods,omitempty"`
	Banner           string   `json:"banner,omitempty"`
	Screenshot       string   `json:"screenshot,omitempty"`
	ScreenshotFormat string   `json:"screenshot_format,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type x11PixmapFormat struct {
	Depth        byte
	BitsPerPixel byte
	ScanlinePad  byte
}

type x11Visual struct {
	VisualID  uint32
	RedMask   uint32
	GreenMask uint32
	BlueMask  uint32
}

type x11Screen struct {
	Root       uint32
	RootVisual uint32
	RootDepth  byte
	Width      uint16
	Height     uint16
}

type x11SetupInfo struct {
	ByteOrder      binary.ByteOrder
	ImageByteOrder byte
	Formats        map[byte]x11PixmapFormat
	Screen         x11Screen
	Visual         x11Visual
}

func init() {
	Register(&X11Module{
		BaseModule: NewBaseModule("x11", []string{"x-window", "xorg"}, true, 10*time.Second),
	})
}

func (m *X11Module) Scan(ip string, port int) (interface{}, error) {
	return scanX11(ip, port, m.DefaultTimeout())
}

func scanX11(ip string, port int, timeout time.Duration) (*X11Result, error) {
	result := &X11Result{Protocol: "x11"}
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	if _, err := conn.Write(buildX11SetupRequest()); err != nil {
		result.Error = err.Error()
		return result, err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		result.Error = "failed to read X11 response"
		return result, err
	}

	switch header[0] {
	case 0:
		parseX11Failure(conn, header, result)
		return result, nil
	case 1:
		info, err := parseX11Success(conn, header, result)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		if screenshot, err := captureX11Screenshot(conn, info, result); err == nil && screenshot != "" {
			result.Screenshot = screenshot
			result.ScreenshotFormat = "png"
		}
		return result, nil
	case 2:
		parseX11Authenticate(conn, header, result)
		return result, nil
	default:
		banner := append([]byte{}, header...)
		if extra, _ := helpers.ReadAvailable(conn, 256); len(extra) > 0 {
			banner = append(banner, extra...)
		}
		result.Banner = strings.TrimSpace(helpers.CleanString(string(banner)))
		if result.Banner != "" {
			result.Error = "non-X11 service responded"
		} else {
			result.Error = fmt.Sprintf("unknown X11 response status: %d", header[0])
		}
		return result, nil
	}
}

func buildX11SetupRequest() []byte {
	req := new(bytes.Buffer)
	req.WriteByte('l')
	req.WriteByte(0)
	_ = binary.Write(req, binary.LittleEndian, uint16(11))
	_ = binary.Write(req, binary.LittleEndian, uint16(0))
	_ = binary.Write(req, binary.LittleEndian, uint16(0))
	_ = binary.Write(req, binary.LittleEndian, uint16(0))
	req.Write([]byte{0, 0})
	return req.Bytes()
}

func parseX11Failure(conn net.Conn, header []byte, result *X11Result) {
	order := binary.LittleEndian
	result.AuthRequired = true
	result.AuthMethods = []string{"required"}
	result.Version = fmt.Sprintf("%d.%d", order.Uint16(header[2:4]), order.Uint16(header[4:6]))

	reasonLen := int(header[1])
	additionalLen := int(order.Uint16(header[6:8])) * 4
	if additionalLen <= 0 {
		return
	}

	reason := make([]byte, additionalLen)
	if _, err := io.ReadFull(conn, reason); err != nil {
		return
	}
	if reasonLen > len(reason) {
		reasonLen = len(reason)
	}
	result.Error = strings.TrimSpace(helpers.CleanString(string(reason[:reasonLen])))
}

func parseX11Authenticate(conn net.Conn, header []byte, result *X11Result) {
	order := binary.LittleEndian
	result.AuthRequired = true
	result.AuthMethods = []string{"authenticate"}
	additionalLen := int(order.Uint16(header[6:8])) * 4
	if additionalLen > 0 {
		payload := make([]byte, additionalLen)
		_, _ = io.ReadFull(conn, payload)
	}
	result.Error = "authentication required"
}

func parseX11Success(conn net.Conn, header []byte, result *X11Result) (*x11SetupInfo, error) {
	order := binary.LittleEndian
	result.AuthRequired = false
	result.Version = fmt.Sprintf("%d.%d", order.Uint16(header[2:4]), order.Uint16(header[4:6]))

	additionalLen := int(order.Uint16(header[6:8])) * 4
	if additionalLen < 24 {
		return nil, fmt.Errorf("short X11 setup reply")
	}

	body := make([]byte, additionalLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	result.Release = order.Uint32(body[0:4])
	result.MaxRequestLength = order.Uint16(body[12:14])
	vendorLen := int(order.Uint16(body[16:18]))
	numScreens := int(body[20])
	numFormats := int(body[21])
	imageByteOrder := body[22]

	result.Screens = numScreens
	result.PixmapFormats = numFormats

	offset := 24
	if offset+vendorLen > len(body) {
		return nil, fmt.Errorf("truncated X11 vendor")
	}
	result.Vendor = strings.TrimSpace(helpers.CleanString(string(body[offset : offset+vendorLen])))
	offset += pad4(vendorLen)

	formats := make(map[byte]x11PixmapFormat, numFormats)
	for i := 0; i < numFormats; i++ {
		if offset+8 > len(body) {
			return nil, fmt.Errorf("truncated X11 pixmap formats")
		}
		format := x11PixmapFormat{
			Depth:        body[offset],
			BitsPerPixel: body[offset+1],
			ScanlinePad:  body[offset+2],
		}
		formats[format.Depth] = format
		offset += 8
	}

	if numScreens == 0 || offset+40 > len(body) {
		return nil, fmt.Errorf("missing X11 screen data")
	}

	screen := x11Screen{
		Root:       order.Uint32(body[offset : offset+4]),
		Width:      order.Uint16(body[offset+20 : offset+22]),
		Height:     order.Uint16(body[offset+22 : offset+24]),
		RootVisual: order.Uint32(body[offset+32 : offset+36]),
		RootDepth:  body[offset+38],
	}
	numDepths := int(body[offset+39])
	result.RootWindow = screen.Root
	result.Width = screen.Width
	result.Height = screen.Height
	offset += 40

	visual := x11Visual{VisualID: screen.RootVisual}
	for depthIndex := 0; depthIndex < numDepths; depthIndex++ {
		if offset+8 > len(body) {
			return nil, fmt.Errorf("truncated X11 depth info")
		}
		depthValue := body[offset]
		numVisuals := int(order.Uint16(body[offset+2 : offset+4]))
		offset += 8

		for visualIndex := 0; visualIndex < numVisuals; visualIndex++ {
			if offset+24 > len(body) {
				return nil, fmt.Errorf("truncated X11 visual info")
			}
			current := x11Visual{
				VisualID:  order.Uint32(body[offset : offset+4]),
				RedMask:   order.Uint32(body[offset+8 : offset+12]),
				GreenMask: order.Uint32(body[offset+12 : offset+16]),
				BlueMask:  order.Uint32(body[offset+16 : offset+20]),
			}
			if current.VisualID == screen.RootVisual {
				visual = current
				screen.RootDepth = depthValue
			}
			offset += 24
		}
	}

	return &x11SetupInfo{
		ByteOrder:      order,
		ImageByteOrder: imageByteOrder,
		Formats:        formats,
		Screen:         screen,
		Visual:         visual,
	}, nil
}

func captureX11Screenshot(conn net.Conn, info *x11SetupInfo, result *X11Result) (string, error) {
	if info == nil || info.Screen.Root == 0 || info.Screen.Width == 0 || info.Screen.Height == 0 {
		return "", fmt.Errorf("missing X11 root window info")
	}

	width := info.Screen.Width
	height := info.Screen.Height
	if width > 320 {
		width = 320
	}
	if height > 240 {
		height = 240
	}

	req := make([]byte, 20)
	req[0] = 73 // GetImage
	req[1] = 2  // ZPixmap
	info.ByteOrder.PutUint16(req[2:4], 5)
	info.ByteOrder.PutUint32(req[4:8], info.Screen.Root)
	info.ByteOrder.PutUint16(req[8:10], 0)
	info.ByteOrder.PutUint16(req[10:12], 0)
	info.ByteOrder.PutUint16(req[12:14], width)
	info.ByteOrder.PutUint16(req[14:16], height)
	info.ByteOrder.PutUint32(req[16:20], 0xffffffff)

	if _, err := conn.Write(req); err != nil {
		return "", err
	}

	replyHeader := make([]byte, 32)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		return "", err
	}
	if replyHeader[0] != 1 {
		return "", fmt.Errorf("unexpected X11 GetImage reply")
	}

	replyDepth := replyHeader[1]
	replyLen := info.ByteOrder.Uint32(replyHeader[4:8])
	if replyLen == 0 || replyLen > 16*1024*1024 {
		return "", fmt.Errorf("invalid X11 image reply length")
	}

	pixelData := make([]byte, int(replyLen)*4)
	if _, err := io.ReadFull(conn, pixelData); err != nil {
		return "", err
	}

	format, ok := info.Formats[replyDepth]
	if !ok {
		format = x11PixmapFormat{Depth: replyDepth, BitsPerPixel: 32, ScanlinePad: 32}
	}

	img, err := decodeX11Image(pixelData, width, height, format, info.ImageByteOrder, info.Visual)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func decodeX11Image(data []byte, width, height uint16, format x11PixmapFormat, imageByteOrder byte, visual x11Visual) (*image.RGBA, error) {
	if format.BitsPerPixel == 0 {
		return nil, fmt.Errorf("unsupported X11 bits_per_pixel")
	}

	bytesPerPixel := int(format.BitsPerPixel) / 8
	if bytesPerPixel == 0 {
		return nil, fmt.Errorf("unsupported X11 bytes_per_pixel")
	}

	scanlinePad := int(format.ScanlinePad)
	if scanlinePad == 0 {
		scanlinePad = 32
	}
	bytesPerLine := (((int(width) * int(format.BitsPerPixel)) + scanlinePad - 1) / scanlinePad) * (scanlinePad / 8)
	if bytesPerLine <= 0 || bytesPerLine*int(height) > len(data) {
		return nil, fmt.Errorf("truncated X11 pixel data")
	}

	if visual.RedMask == 0 && visual.GreenMask == 0 && visual.BlueMask == 0 {
		visual.RedMask = 0x00ff0000
		visual.GreenMask = 0x0000ff00
		visual.BlueMask = 0x000000ff
	}

	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	for y := 0; y < int(height); y++ {
		rowStart := y * bytesPerLine
		for x := 0; x < int(width); x++ {
			pixelStart := rowStart + x*bytesPerPixel
			pixelEnd := pixelStart + bytesPerPixel
			if pixelEnd > len(data) {
				break
			}
			raw := readX11Pixel(data[pixelStart:pixelEnd], imageByteOrder)
			img.SetRGBA(x, y, decodeX11Pixel(raw, visual))
		}
	}
	return img, nil
}

func readX11Pixel(data []byte, imageByteOrder byte) uint32 {
	if imageByteOrder == 0 {
		imageByteOrder = 'l'
	}

	var raw uint32
	switch len(data) {
	case 1:
		raw = uint32(data[0])
	case 2:
		if imageByteOrder == 'B' {
			raw = uint32(binary.BigEndian.Uint16(data))
		} else {
			raw = uint32(binary.LittleEndian.Uint16(data))
		}
	case 3:
		if imageByteOrder == 'B' {
			raw = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		} else {
			raw = uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
		}
	default:
		if imageByteOrder == 'B' {
			raw = binary.BigEndian.Uint32(data[:4])
		} else {
			raw = binary.LittleEndian.Uint32(data[:4])
		}
	}
	return raw
}

func decodeX11Pixel(raw uint32, visual x11Visual) color.RGBA {
	return color.RGBA{
		R: scaleMaskComponent(raw, visual.RedMask),
		G: scaleMaskComponent(raw, visual.GreenMask),
		B: scaleMaskComponent(raw, visual.BlueMask),
		A: 255,
	}
}

func scaleMaskComponent(raw, mask uint32) uint8 {
	if mask == 0 {
		return 0
	}
	shift := uint32(0)
	for ((mask >> shift) & 1) == 0 {
		shift++
	}
	value := (raw & mask) >> shift
	max := mask >> shift
	if max == 0 {
		return 0
	}
	return uint8((value * 255) / max)
}

func pad4(n int) int {
	return (n + 3) &^ 3
}
