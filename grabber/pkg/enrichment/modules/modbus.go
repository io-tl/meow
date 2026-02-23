package modules

import (
	"encoding/binary"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// ModbusModule implements the Modbus enrichment module
type ModbusModule struct {
	BaseModule
}

type ModbusResult struct {
	Protocol           string `json:"protocol"`
	DeviceID           string `json:"device_id,omitempty"`
	FunctionCode       int    `json:"function_code,omitempty"`
	Detected           bool   `json:"detected"`
	VendorName         string `json:"vendor_name,omitempty"`
	ProductCode        string `json:"product_code,omitempty"`
	MajorMinorRevision string `json:"revision,omitempty"`
	VendorURL          string `json:"vendor_url,omitempty"`
	ProductName        string `json:"product_name,omitempty"`
	ModelName          string `json:"model_name,omitempty"`
	Error              string `json:"error,omitempty"`
}

func init() {
	Register(&ModbusModule{
		BaseModule: NewBaseModule("modbus", []string{}, false, 10*time.Second),
	})
}

func (m *ModbusModule) Scan(ip string, port int) (interface{}, error) {
	result := &ModbusResult{Protocol: "modbus"}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Modbus TCP read device identification
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request[0:2], 1)     // Transaction ID
	binary.BigEndian.PutUint16(request[2:4], 0)     // Protocol ID
	binary.BigEndian.PutUint16(request[4:6], 6)     // Length
	request[6] = 1                                   // Unit ID
	request[7] = 0x2B                                // Function code: Read Device ID
	request[8] = 0x0E                                // MEI type
	request[9] = 0x01                                // Read Device ID code
	request[10] = 0x00                               // Object ID

	if _, err := conn.Write(request); err != nil {
		result.Error = err.Error()
		return result, err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n > 8 {
		// Parse Modbus TCP header
		protocolID := binary.BigEndian.Uint16(response[2:4])
		unitID := response[6]
		funcCode := response[7]

		result.DeviceID = fmt.Sprintf("Unit %d", unitID)
		result.FunctionCode = int(funcCode)

		// Check if response is valid
		if protocolID == 0 && funcCode == 0x2B && n > 9 {
			// Parse Read Device ID response
			meiType := response[8]
			readDevCode := response[9]

			if meiType == 0x0E && readDevCode == 0x01 {
				result.Detected = true

				// Parse objects
				offset := 12 // Skip header
				for offset+2 <= n {
					objID := response[offset]
					objLen := int(response[offset+1])
					offset += 2

					if objLen < 0 || offset+objLen > n {
						break
					}

					objValue := string(response[offset : offset+objLen])
					offset += objLen

					switch objID {
					case 0x00:
						result.VendorName = objValue
					case 0x01:
						result.ProductCode = objValue
					case 0x02:
						result.MajorMinorRevision = objValue
					case 0x03:
						result.VendorURL = objValue
					case 0x04:
						result.ProductName = objValue
					case 0x05:
						result.ModelName = objValue
					}

					// Limit parsing
					if offset >= 256 {
						break
					}
				}
			}
		}
	}

	return result, nil
}
