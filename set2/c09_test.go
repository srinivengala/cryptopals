package main

import (
	"bytes"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

// go test
// go test -v

func TestPKCS7Pad(t *testing.T) {
	pb := []byte("YELLOW SUBMARINE")
	crytin.PKCS7Padding(&pb, 20)
	if !bytes.Equal(pb, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) {
		t.Error("PKCS7 padding failed")
	}
}
