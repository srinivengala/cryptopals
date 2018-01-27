package crytin

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"fmt"
)

// FromString : Convert string to bytes
func FromString(s string) []byte {
	return []byte(s)
}

// FromHex : Get bytes from hex encoded string
func FromHex(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

// ToHex : Get hex encoded string from bytes
func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// FromBase64String : Get bytes from base64 encoded data
func FromBase64(bb []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(bb))
}

// FromBase64String : Get bytes from base64 encoded data
func FromBase64String(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ToBase64 : Get base64 encoded string from bytes
func ToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// HexToBase64 : Change hex encoding to Base64 encoding
func HexToBase64(hh string) (string, error) {
	bytes, err := FromHex(hh)
	if err != nil {
		return "", err
	}
	b64 := ToBase64(bytes)
	return b64, nil
}

// XOR : XOR b1 with b2.
// b2 is repeated to match b1 length
func XOR(b1, b2 []byte) []byte {
	b := make([]byte, len(b1))
	b2len := len(b2)
	for i := range b1 {
		b[i] = b1[i] ^ b2[i%b2len]
	}
	return b
}

// ToSafeString : Convert to safe printable string
func ToSafeString(b []byte) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9 ]")
	return reg.ReplaceAllString(string(b), ".")
}

// HammingDistance : Count number of differing bits between two byte arrays
func HammingDistance(b1, b2 []byte) uint {
	dist := uint(0)
	for _, b := range XOR(b1, b2) {
		for i := uint(0); i < 8; i++ {
			dist += uint((b >> i) & 1)
		}
	}
	return dist
}

// EditDistance : is the HammingDistance
func EditDistance(b1, b2 []byte) uint {
	return HammingDistance(b1, b2)
}

// NormalizedEditDistance : EditDistance / KeySize
// The keySize with smallest normalized edit distance is the best key size
//   to bruteforce
func NormalizedEditDistance(b1, b2 []byte) uint {
	keySize := uint(len(b1))
	return EditDistance(b1, b2) / keySize
}

// BestKeySize : Find the best keysize for the cipher text
//   to use for attacking repeated XOR cipher
// returns choosen key size and its edit distance
//
// How it works:
// for a keySize split the cipher text into keySize blocks and arrange them top to bottom
//   find edit distance of some other blocks with first block
//
// the keySize with minimum average edit distance is possible keySize
//   to start bruteforcing
func BestKeySize(cb []byte, minKeySize, maxKeySize uint) (bestKeySize, bestEditDistance uint) {
	bestEditDistance = 0
	bestKeySize = 0
	
	if uint(len(cb)/2) < maxKeySize {
		maxKeySize = uint(len(cb)/2)
	}

	maxBlocks := uint(len(cb)) / maxKeySize

	for keySize := minKeySize; keySize <= maxKeySize; keySize++ {
		editDistance := uint(0)
		firstBlock := cb[:keySize]

		// edit distance over several blocks for accuracy
		for i := uint(1); i < maxBlocks; i++ {
			nextBlock := cb[keySize*i : keySize*(i+1)]
			editDistance += NormalizedEditDistance(firstBlock, nextBlock)
		}
		// if we try average over blocks it fails
		// as it looses precision with integer division :)
		// editDistance should be floating point.
		// but here we can get away without averaging
		//
		//editDistance /= uint(maxBlocks)

		fmt.Printf("\n keysize: %d, editdist: %d", keySize, editDistance)
		if bestEditDistance == 0 || editDistance < bestEditDistance {
			bestEditDistance = editDistance
			bestKeySize = keySize
		}
	}
	fmt.Printf("\n best keySize: %d, editdist: %d\n", bestKeySize, bestEditDistance)
	return bestKeySize, bestEditDistance
}

// Transpose : divide into blocks, arrange blocks top down, grab columns as rows
func Transpose(cb []byte, blockSize uint) (tr [][]byte) {
	tr = make([][]byte, blockSize)
	for i, b := range cb {
		tr[i%int(blockSize)] = append(tr[i%int(blockSize)], b)
	}
	return tr
}
