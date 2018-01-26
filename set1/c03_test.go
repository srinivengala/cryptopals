package main

import (
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

// break : single byte XOR cipher
// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// Answer: "Cooking MC's like a pound of bacon"

// go test -v
// go test

func TestAttackSingleXOR(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	t.Logf("Breaking:" + input)
	cb, err := crytin.FromHex(input)
	if err != nil {
		t.Error("FromHex failed")
		return
	}

	// using ASCIIScore1
	pb1, secret1, _ := crytin.AttackSingleByteXOR(cb, crytin.ASCIIScore1, false)

	if len(pb1) == 0 {
		t.Error("Could not find XOR byte")
	}

	t.Log("Plain text is : ", string(pb1))
	t.Log("Secret byte is : ", string(secret1))

	// using ASCIIScore2
	pb2, secret2, _ := crytin.AttackSingleByteXOR(cb, crytin.ASCIIScore2, false)

	if len(pb2) == 0 {
		t.Error("Could not find the XOR byte")
	}

	t.Log("Plain text is : ", string(pb2))
	t.Log("Secret byte is : ", string(secret2))

	// using ASCIIScore3
	pb3, secret3, _ := crytin.AttackSingleByteXOR(cb, crytin.ASCIIScore3, false)

	if len(pb3) == 0 {
		t.Error("Could not find the XOR byte")
	}

	t.Log("Plain text is : ", string(pb3))
	t.Log("Secret byte is : ", string(secret3))
}
