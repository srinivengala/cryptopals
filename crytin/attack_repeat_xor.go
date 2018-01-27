package crytin

import "fmt"

// AttackRepeatXOR : Attack repeating byte XOR cipher text
//
//
func AttackRepeatXOR(cb []byte, verbose bool) (pt []byte, key []byte) {
	pt = []byte{}
	key = []byte{}

	// estimate the size of the key
	keySize, _ := BestKeySize(cb, 2, 40)

	// split cipher text into keySize blocks
	//  arrange them top to bottom
	//  get columns
	tr := Transpose(cb, keySize)

	// for each colum do AttackSingleXOR
	for _, col := range tr {
		pt, b, _ := AttackSingleByteXOR(col, ASCIIScore, false)
		if verbose {
			fmt.Printf("\ncol (%s) : %s", string(b), ToSafeString(pt))
		}
		key = append(key, b)
	}

	pt = XOR(cb, key)
	if verbose {
		fmt.Printf("\n Key : \"%s\"", string(key))
		fmt.Printf("\n Plain text : %s\n", ToSafeString(pt))
		//fmt.Print(string(pt)+"\n")
	}
	return XOR(cb, key), key
}
