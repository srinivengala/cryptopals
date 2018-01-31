package main

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

// ../data/10.txt decrypt it with AES-CBC with key "YELLOW SUBMARINE" and IV of all ASCII 0 (\x00\x00)

// go test
// go test -v

func TestCBCMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, len(key))

	pb := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	cb, err := crytin.EncryptAesCbc(pb, key, iv)
	if err != nil {
		t.Error(err)
	}

	pb2, err := crytin.DecryptAesCbc(cb, key, iv)
	if err != nil {
		t.Error(err)
	}

	t.Logf("Plain text: %s\n", crytin.ToSafeString(pb2))

	if !bytes.Equal(pb[:], pb2[:]) {
		//t.Errorf("padding : %s and %s", crytin.ToHex(cb[len(cb)-8:]), crytin.ToHex(cb2[len(cb2)-8:]))
		t.Errorf("not equal")
	}
}

func TestCBCModeFile(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, len(key))

	dat, err := ioutil.ReadFile("../data/10.txt")
	if err != nil {
		t.Fatal(err)
	}
	cb, err := crytin.FromBase64(dat)
	if err != nil {
		t.Error(err)
	}

	pb, err := crytin.DecryptAesCbc(cb, key, iv)
	if err != nil {
		t.Error(err)
	}

	cb2, err := crytin.EncryptAesCbc(pb, key, iv)
	if err != nil {
		t.Error(err)
	}

	t.Logf("Plain text: %s\n", crytin.ToSafeString(pb))

	if !bytes.Equal(cb[:], cb2[:]) {
		t.Errorf("not equal")
	}
}
