package crytin

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
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
func XOR(b1 []byte, b2 []byte) []byte {
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
