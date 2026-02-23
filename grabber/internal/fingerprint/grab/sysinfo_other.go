//go:build !linux

package grab

// getTotalSystemRAM retourne la RAM totale du système en MB (fallback)
func getTotalSystemRAM() uint64 {
	return 8192 // 8GB par defaut sur les plateformes non-Linux
}
