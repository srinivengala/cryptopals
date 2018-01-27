package main

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

func TestDecryptAESECBMode(t *testing.T) {
	// key size 16, 24, or 32 bytes to select
	//     AES-128, AES-192, or AES-256
	key := []byte("YELLOW SUBMARINE") //16 bytes, 16*8=128bits

	dat, err := ioutil.ReadFile("../data/7.txt")
	if err != nil {
		t.Fatal(err)
	}
	cb, err := crytin.FromBase64(dat)
	if err != nil {
		t.Error(err)
	}

	pb, err := crytin.DecryptAesEcb(cb, key)
	if err != nil {
		t.Error(err)
	}

	cb2, err := crytin.EncryptAesEcb(pb, key)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(cb[:], cb2[:]) != 0 {
		t.Error("Re encrypted text did not match original encrypted text")
	}

	t.Logf("Plain text: %s\n", string(pb))
}
