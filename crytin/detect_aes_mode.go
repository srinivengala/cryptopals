package crytin

// DetectECB : detect ECB mode
// returns the block size
func DetectECB(cb []byte) (bool, uint) {
	//16, 24, or 32 key or block sizes

	cbLen := len(cb)
	for _, bs := range []int{16, 24, 32} {
		if cbLen%bs == 0 {
			blocks := map[string]bool{}
			for i := 0; i < cbLen; i += bs {
				block := string(cb[i : i+bs])
				_, exists := blocks[block]
				if exists {
					return true, uint(bs)
				}
				blocks[block] = true
			}
		}
	}
	return false, uint(0)
}
