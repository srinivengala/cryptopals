package main

import (
	"github.com/srinivengala/cryptopals/crytin"

	"bytes"
	"math/rand"
	"testing"
	"time"
)

//Byte-at-a-time ECB decryption (Simple)
//
//AES-128-ECB(your-string || unknown-string, random-key)
//
//It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
//
//Here's roughly how:
//
//    1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
//    2. Detect that the function is using ECB. You already know, but do this step anyways.
//    3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
//    4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
//    5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
//    6. Repeat for the next byte.

// NOTES: Insert ks-1 A's at the currBlock you want to decrypt
//
// AAAAAAAX => for each X: 0-256 do oracle => map[cb]=X
// AAAAAAA cb[currBlock+0] => oracle => pt => map[pt] => say "s"
//
// AAAAAAsX => for each X: 0-256 do oracle => map[cb]=X
// AAAAAAs cb[currBlock+1] => oracle => pt => map[pt] => say "e"
//
// AAAAAseX => for each X: 0-256 do oracle => map[cb]=X
// AAAAAAse cb[currBlock+2] => oracle => pt => map[pt] => say "c"
//

const ks = 16

var unknownKey = [ks]byte{}

func init() {
	rand.Seed(time.Now().Unix())
	rand.Read(unknownKey[:])
}

func oracle(cb []byte) ([]byte, error) {
	return crytin.DecryptAesEcb(cb, unknownKey[:])
}

// bruteForceX : appends X and creates map[ToHex(cb)]X
// returns: lookup map
// note: converting to string so I don't need to create hash function
//  for map compare keys
func bruteForceX(prefix []byte) map[string]byte {
	m := make(map[string]byte)
	for i := byte(0); i <= 128; i++ {
		cb := append(prefix, i)
		resultBytes, _ := oracle(cb)
		m[string(resultBytes)] = i
	}
	return m
}

func TestECBByteAtATimeDecrypt(t *testing.T) {
	cb, _ := crytin.FromBase64String(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
		aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
		dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
		YnkK`)
	// for each block
	currBlock := 0
	ptb := make([]byte, 0)

	// for each byte in currBlock
	for bn := 0; bn < ks; bn++ {
		ab := bytes.Repeat([]byte("A"), ks-len(ptb)-1)
		ab = append(ab, ptb...)
		m := bruteForceX(ab)
		t.Log("\n Bruteforce complete for block", string(ab))

		ab = append(ab, cb[bn:]...)
		//t.Log("\n", crytin.ToHex(ab)[currBlock:currBlock+(ks*2)])
		pb, err := oracle(ab)
		if err != nil {
			t.Error(err)
		}
		//t.Log("\n ", crytin.ToHex(pb[currBlock:currBlock+ks]))
		if v, ok := m[string(pb[currBlock:currBlock+ks])]; ok {
			ptb = append(ptb, v)
			//t.Log("\n The letter is : ", string(ptb))
		} else {
			ptb = append(ptb, 46) //"."
			//t.Error("\n Not found in bruteforce lookup map")
		}
	}
}
