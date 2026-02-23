package modules

import (
	"encoding/binary"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// LDPModule implements the Label Distribution Protocol enrichment module
type LDPModule struct {
	BaseModule
}

// LDPResult represents the enriched LDP data
type LDPResult struct {
	Protocol     string   `json:"protocol"`
	Version      string   `json:"version,omitempty"`
	LSRID        string   `json:"lsr_id,omitempty"`
	LabelSpace   int      `json:"label_space,omitempty"`
	PDULength    int      `json:"pdu_length,omitempty"`
	MessageTypes []string `json:"message_types,omitempty"`
	Error        string   `json:"error,omitempty"`
}

func init() {
	Register(&LDPModule{
		BaseModule: NewBaseModule(
			"ldp",
			[]string{},
			false, // Should not enrich (specialized protocol)
			10*time.Second,
		),
	})
}

func (m *LDPModule) Scan(ip string, port int) (interface{}, error) {
	return scanLDP(ip, port, m.DefaultTimeout())
}

// scanLDP performs LDP enrichment
func scanLDP(ip string, port int, timeout time.Duration) (*LDPResult, error) {
	result := &LDPResult{
		Protocol: "ldp",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build LDP Hello message (simplified probe)
	// LDP uses TLV (Type-Length-Value) encoding
	// This is a very basic probe
	helloMsg := []byte{
		0x00, 0x01, // Version: 1
		0x00, 0x0c, // Length: 12
		0x00, 0x00, 0x00, 0x00, // LSR ID
		0x00, 0x00, // Label Space
		// Hello message TLV
		0x01, 0x00, // Type: Hello
		0x00, 0x04, // Length: 4
		0x00, 0x00, 0x00, 0x0f, // Hold time: 15
	}

	_, err = conn.Write(helloMsg)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Try to read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n > 4 {
		// Parse LDP header
		version := binary.BigEndian.Uint16(response[0:2])
		if version == 1 {
			result.Version = "1"

			// Parse PDU length
			if n >= 4 {
				pduLen := binary.BigEndian.Uint16(response[2:4])
				result.PDULength = int(pduLen)
			}

			// Parse LSR ID and Label Space
			if n >= 10 {
				lsrID := binary.BigEndian.Uint32(response[4:8])
				labelSpace := binary.BigEndian.Uint16(response[8:10])
				result.LSRID = fmt.Sprintf("%d.%d.%d.%d",
					(lsrID>>24)&0xFF, (lsrID>>16)&0xFF,
					(lsrID>>8)&0xFF, lsrID&0xFF)
				result.LabelSpace = int(labelSpace)
			}

			// Try to parse TLVs
			offset := 10
			for offset+4 <= n {
				tlvType := binary.BigEndian.Uint16(response[offset : offset+2])
				tlvLen := binary.BigEndian.Uint16(response[offset+2 : offset+4])
				offset += 4

				if offset+int(tlvLen) > n {
					break
				}

				switch tlvType {
				case 0x0100: // Hello TLV
					result.MessageTypes = append(result.MessageTypes, "Hello")
				case 0x0001: // FEC TLV
					result.MessageTypes = append(result.MessageTypes, "FEC")
				case 0x0200: // Address List TLV
					result.MessageTypes = append(result.MessageTypes, "Address List")
				}

				offset += int(tlvLen)
			}
		}
	}

	return result, nil
}
