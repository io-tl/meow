package grab

import (
	"bytes"
	"testing"
)

// salesforceMung réimplémente EXACTEMENT cipher_mung de salesforce/jarm (jarm.py).
// Sert d'oracle de référence pour verrouiller reorderCiphers.
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

// reorderCiphers doit être identique à cipher_mung pour toutes les stratégies,
// sur des listes paires ET impaires. La liste JARM "ALL" fait 69 (impaire), ce
// qui exerce le cas TOP_HALF/MIDDLE_OUT critique.
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
				t.Errorf("reorderCiphers(size=%d, %q) diverge de cipher_mush salesforce\n got=%v\nwant=%v",
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

// findExtension parcourt un bloc d'extensions (type(2)+len(2)+data) et renvoie
// les données de la première extension du type demandé.
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

// L'ALPN rare doit être réordonné comme l'ALPN normal selon extOrder.
// Probe #5 = RARE_ALPN + REVERSE : le 1er protocole offert doit être "hq".
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
		t.Fatal("aucun probe RARE_ALPN+REVERSE trouvé (probe #5 attendu)")
	}
	ext := getExtensions("example.com", probe5)
	// ext[0:2] = longueur totale du bloc, puis les extensions.
	alpn := findExtension(ext[2:], 0x0010)
	if alpn == nil {
		t.Fatal("extension ALPN absente du probe RARE_ALPN")
	}
	// alpn = alpnListLen(2) + protocoles; 1er protocole = len(1) + nom.
	first := alpn[2:]
	name := string(first[1 : 1+int(first[0])])
	if name != "hq" {
		t.Errorf("RARE_ALPN+REVERSE: 1er protocole ALPN = %q, attendu \"hq\"", name)
	}
}
