package main

import (
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

//Convert hex to base64

//The string:
//49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

//Should produce:
//SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

//So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

//Cryptopals Rule
//Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

//C:\Go\bin\go.exe test -coverprofile=C:\Users\scott\AppData\Local\Temp\go-code-cover -timeout 30s github.com\srinivengala\cryptopals\set1
// C:\Go\bin\go.exe test -timeout 30s github.com\srinivengala\cryptopals\set1 -run ^TestHexToBase64$
// go test -v
// go test

func TestHexToBase64(t *testing.T) {
	expectedBase64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	t.Logf("Hex String: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d ")
	t.Logf("Expected: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
	b64, err := crytin.HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil || b64 != expectedBase64 {
		t.Error("Expected " + expectedBase64 + ",\n got " + b64)
	}
}
