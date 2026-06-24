package modules

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// NTLM parsing code adapted from go-smb2 (MIT license)
// This properly handles modern Windows servers

const (
	MsvAvEOL = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDnsComputerName
	MsvAvDnsDomainName
	MsvAvDnsTreeName
	MsvAvFlags
	MsvAvTimestamp
	MsvAvSingleHost
	MsvAvTargetName
	MsvAvChannelBindings
)

// OSVersion contains OS version information from NTLM
type OSVersion struct {
	Major        uint8
	Minor        uint8
	Build        uint16
	NTLMRevision uint8
}

// parseNTLMChallengeMessage parses an NTLM CHALLENGE message and extracts TargetInfo
func parseNTLMChallengeMessage(challengeData []byte) (targetName, nbComputerName, nbDomainName, dnsComputerName, dnsDomainName string, osVer *OSVersion, err error) {
	if len(challengeData) < 48 {
		return "", "", "", "", "", nil, nil
	}

	// Verify signature
	if string(challengeData[0:8]) != "NTLMSSP\x00" {
		return "", "", "", "", "", nil, nil
	}

	// Verify message type (should be 2 for CHALLENGE)
	msgType := binary.LittleEndian.Uint32(challengeData[8:12])
	if msgType != 2 {
		return "", "", "", "", "", nil, nil
	}

	// Extract TargetName
	targetNameLen := binary.LittleEndian.Uint16(challengeData[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(challengeData[16:20])
	if targetNameLen > 0 && int(targetNameOffset) < len(challengeData) && int(targetNameOffset)+int(targetNameLen) <= len(challengeData) {
		targetNameBytes := challengeData[targetNameOffset : targetNameOffset+uint32(targetNameLen)]
		targetName = decodeUTF16LEToString(targetNameBytes)
	}

	// Extract NegotiateFlags to check for VERSION flag
	negotiateFlags := binary.LittleEndian.Uint32(challengeData[20:24])
	const NTLMSSP_NEGOTIATE_VERSION = 0x02000000

	// Extract Version field if present (offset 48, 8 bytes)
	if (negotiateFlags&NTLMSSP_NEGOTIATE_VERSION) != 0 && len(challengeData) >= 56 {
		osVer = &OSVersion{
			Major:        challengeData[48],
			Minor:        challengeData[49],
			Build:        binary.LittleEndian.Uint16(challengeData[50:52]),
			NTLMRevision: challengeData[55],
		}
	}

	// Extract TargetInfo
	if len(challengeData) < 48 {
		return targetName, "", "", "", "", osVer, nil
	}

	targetInfoLen := binary.LittleEndian.Uint16(challengeData[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(challengeData[44:48])

	if targetInfoLen == 0 || targetInfoOffset == 0 {
		return targetName, "", "", "", "", osVer, nil
	}

	if int(targetInfoOffset) >= len(challengeData) || int(targetInfoOffset)+int(targetInfoLen) > len(challengeData) {
		return targetName, "", "", "", "", osVer, nil
	}

	targetInfo := challengeData[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]

	// Parse TargetInfo AV_PAIRs
	infoMap := parseTargetInfo(targetInfo)

	nbComputerName = decodeUTF16LEToString(infoMap[MsvAvNbComputerName])
	nbDomainName = decodeUTF16LEToString(infoMap[MsvAvNbDomainName])
	dnsComputerName = decodeUTF16LEToString(infoMap[MsvAvDnsComputerName])
	dnsDomainName = decodeUTF16LEToString(infoMap[MsvAvDnsDomainName])

	return targetName, nbComputerName, nbDomainName, dnsComputerName, dnsDomainName, osVer, nil
}

// parseTargetInfo parses NTLM TargetInfo into a map
func parseTargetInfo(data []byte) map[uint16][]byte {
	infoMap := make(map[uint16][]byte)
	r := bytes.NewReader(data)

	for {
		var id uint16
		var length uint16

		if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
			break
		}

		if id == MsvAvEOL {
			break
		}

		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			break
		}

		value := make([]byte, length)
		if n, err := r.Read(value); err != nil || n != int(length) {
			break
		}

		infoMap[id] = value
	}

	return infoMap
}

// decodeUTF16LEToString decodes UTF-16LE bytes to string
func decodeUTF16LEToString(b []byte) string {
	if len(b) == 0 || len(b)%2 != 0 {
		return ""
	}

	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
	}

	runes := utf16.Decode(u16)
	return string(runes)
}
