package main

import (
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

//Encrypt with repeating XOR key "ICE":
// "Burning 'em, if you ain't quick and nimble
// I go crazy when I hear a cymbal"
// Should get:
// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

// go test -v
// go test

func TestRepeatXORKey(t *testing.T) {
	res := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	pt := []byte("Burning 'em, if you ain't quick and nimble\n" +
		"I go crazy when I hear a cymbal")
	t.Log("plain text: " + string(pt))
	cht := crytin.ToHex(crytin.XOR(pt, []byte("ICE")))
	t.Log("cipher text: " + cht)
	if res != cht {
		t.Error("Failed to perform : repeat XOR")
	}
}
