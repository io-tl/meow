package grab

import (
	"bytes"
	"testing"
)

// salesforceMung reimplements EXACTLY cipher_mung from salesforce/jarm (jarm.py).
// Serves as a reference oracle to lock down reorderCiphers.
func salesforceMung(ciphers [][]byte, request string) [][]byte {
	n := len(ciphers)
	switch request {
	case "REVERSE":
		out := make([][]byte, n)
		for i := 0; i < n; i++ {
			out[i] = ciphers[n-1-i]
		}
		return out
	case "BOTTOM_HALF":
		if n%2 == 1 {
			return ciphers[n/2+1:]
		}
		return ciphers[n/2:]
	case "TOP_HALF":
		var out [][]byte
		if n%2 == 1 {
			out = append(out, ciphers[n/2])
		}
		out = append(out, salesforceMung(salesforceMung(ciphers, "REVERSE"), "BOTTOM_HALF")...)
		return out
	case "MIDDLE_OUT":
		mid := n / 2
		var out [][]byte
		if n%2 == 1 {
			out = append(out, ciphers[mid])
			for i := 1; i <= mid; i++ {
				out = append(out, ciphers[mid+i], ciphers[mid-i])
			}
		} else {
			for i := 1; i <= mid; i++ {
				out = append(out, ciphers[mid-1+i], ciphers[mid-i])
			}
		}
		return out
	}
	return ciphers
}

func equalCipherLists(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// reorderCiphers must be identical to cipher_mung for all strategies,
// on even AND odd lists. The JARM "ALL" list has 69 entries (odd), which
// exercises the critical TOP_HALF/MIDDLE_OUT case.
func TestReorderCiphersMatchesSalesforce(t *testing.T) {
	strategies := []string{"FORWARD", "REVERSE", "TOP_HALF", "BOTTOM_HALF", "MIDDLE_OUT"}
	for _, size := range []int{8, 9, 64, 69} {
		list := make([][]byte, size)
		for i := range list {
			list[i] = []byte{byte(i)}
		}
		for _, strat := range strategies {
			got := reorderCiphers(list, strat)
			want := salesforceMung(list, strat)
			if !equalCipherLists(got, want) {
				t.Errorf("reorderCiphers(size=%d, %q) diverges from salesforce cipher mung\n got=%v\nwant=%v",
					size, strat, flattenFirst(got, 6), flattenFirst(want, 6))
			}
		}
	}
}

func flattenFirst(s [][]byte, n int) []int {
	out := []int{}
	for i := 0; i < n && i < len(s); i++ {
		out = append(out, int(s[i][0]))
	}
	return out
}

// findExtension walks an extensions block (type(2)+len(2)+data) and returns
// the data of the first extension of the requested type.
func findExtension(body []byte, extType uint16) []byte {
	for i := 0; i+4 <= len(body); {
		t := uint16(body[i])<<8 | uint16(body[i+1])
		l := int(body[i+2])<<8 | int(body[i+3])
		if i+4+l > len(body) {
			break
		}
		if t == extType {
			return body[i+4 : i+4+l]
		}
		i += 4 + l
	}
	return nil
}

// The rare ALPN must be reordered like the normal ALPN according to extOrder.
// Probe #5 = RARE_ALPN + REVERSE: the 1st offered protocol must be "hq".
func TestRareALPNIsReordered(t *testing.T) {
	var probe5 probeConfig
	found := false
	for _, p := range getProbes() {
		if p.alpn == "RARE_ALPN" && p.extOrder == "REVERSE" {
			probe5 = p
			found = true
		}
	}
	if !found {
		t.Fatal("no RARE_ALPN+REVERSE probe found (probe #5 expected)")
	}
	ext := getExtensions("example.com", probe5)
	// ext[0:2] = total length of the block, then the extensions.
	alpn := findExtension(ext[2:], 0x0010)
	if alpn == nil {
		t.Fatal("ALPN extension missing from the RARE_ALPN probe")
	}
	// alpn = alpnListLen(2) + protocols; 1st protocol = len(1) + name.
	first := alpn[2:]
	name := string(first[1 : 1+int(first[0])])
	if name != "hq" {
		t.Errorf("RARE_ALPN+REVERSE: 1st ALPN protocol = %q, expected \"hq\"", name)
	}
}
