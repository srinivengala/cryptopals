package main

import (
	"github.com/srinivengala/cryptopals/crytin"

	"math/rand"
	"testing"
	"time"
)

var c14UnknownKey []byte

func init() {
	const ks = 16
	c14UnknownKey = make([]byte, ks)
	rand.Seed(time.Now().Unix())
	rand.Read(c14UnknownKey[:])
}

type _oracle struct{}

// Encrypt : AES-ECB-Encrypt(unknownText|yourText|unknownText)
func (o _oracle) Encrypt(pb []byte, insertPoint int) ([]byte, error) {
	unknownBytes, _ := crytin.FromBase64String(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	opb := make([]byte, 0)
	opb = append(opb, unknownBytes[0:insertPoint]...)
	opb = append(opb, pb...)
	opb = append(opb, unknownBytes[insertPoint:]...)

	return crytin.DecryptAesEcb(opb, c14UnknownKey[:])
}

func TestAttackECBByteAtATimeDecryptEasyway(t *testing.T) {
	const ks = 16
	insertPoint := ks*2 + 2
	if err := crytin.AttackECBByteAtATime(_oracle{}, insertPoint, ks, true); err != nil {
		t.Error(err)
	}
}
