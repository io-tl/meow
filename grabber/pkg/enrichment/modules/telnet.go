package modules

import (
	"bufio"
	"bytes"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// TelnetModule implements the Telnet enrichment module
type TelnetModule struct {
	BaseModule
}

// TelnetResult represents the enriched Telnet data
type TelnetResult struct {
	Protocol string   `json:"protocol"`
	Banner   string   `json:"banner,omitempty"`
	Options  []string `json:"options,omitempty"` // Telnet negotiation options
	Error    string   `json:"error,omitempty"`
}

func init() {
	Register(&TelnetModule{
		BaseModule: NewBaseModule(
			"telnet",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *TelnetModule) Scan(ip string, port int) (interface{}, error) {
	return scanTelnet(ip, port, m.DefaultTimeout())
}

// Telnet protocol constants
const (
	telnetIAC  = 255 // Interpret As Command
	telnetDONT = 254
	telnetDO   = 253
	telnetWONT = 252
	telnetWILL = 251
	telnetSB   = 250 // Subnegotiation
	telnetSE   = 240 // End of subnegotiation
)

var telnetOptionNames = map[byte]string{
	0:  "Binary Transmission",
	1:  "Echo",
	3:  "Suppress Go Ahead",
	5:  "Status",
	6:  "Timing Mark",
	24: "Terminal Type",
	31: "Window Size",
	32: "Terminal Speed",
	33: "Remote Flow Control",
	34: "Linemode",
	36: "Environment Variables",
}

// scanTelnet performs Telnet enrichment
func scanTelnet(ip string, port int, timeout time.Duration) (*TelnetResult, error) {
	result := &TelnetResult{
		Protocol: "telnet",
	}

	// Connect using helper — DialTCP sets a deadline so reads timeout automatically
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	var banner bytes.Buffer
	var options []string

	// Synchronous read loop — exits on deadline error or connection close
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}

		if b == telnetIAC {
			// Telnet command follows
			cmd, err := reader.ReadByte()
			if err != nil {
				break
			}

			if cmd == telnetDO || cmd == telnetDONT || cmd == telnetWILL || cmd == telnetWONT {
				// Read option
				opt, err := reader.ReadByte()
				if err != nil {
					break
				}

				// Record the option
				cmdName := ""
				switch cmd {
				case telnetDO:
					cmdName = "DO"
				case telnetDONT:
					cmdName = "DONT"
				case telnetWILL:
					cmdName = "WILL"
				case telnetWONT:
					cmdName = "WONT"
				}

				optName := telnetOptionNames[opt]
				if optName == "" {
					optName = fmt.Sprintf("Option %d", opt)
				}
				options = append(options, fmt.Sprintf("%s %s", cmdName, optName))

				// Respond with WONT/DONT to all requests
				var response []byte
				if cmd == telnetDO {
					response = []byte{telnetIAC, telnetWONT, opt}
				} else if cmd == telnetWILL {
					response = []byte{telnetIAC, telnetDONT, opt}
				}
				if response != nil {
					if _, err := conn.Write(response); err != nil {
						break
					}
				}
			} else if cmd == telnetSB {
				// Skip subnegotiation
				for {
					sb, err := reader.ReadByte()
					if err != nil || sb == telnetSE {
						break
					}
				}
			}
		} else {
			// Regular character - part of banner
			banner.WriteByte(b)
		}
	}

	result.Banner = banner.String()
	result.Options = options

	return result, nil
}
