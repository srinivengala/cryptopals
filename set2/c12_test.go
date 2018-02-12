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
	// cheat: 126 optimized for english.
	//  for binary use 256
	for i := byte(0); i < 126; i++ {
		cb := append(prefix, i)
		resultBytes, _ := oracle(cb)
		m[crytin.ToHex(resultBytes)] = i
	}
	return m
}

func TestAttackECBByteAtATimeDecrypt(t *testing.T) {
	cb, _ := crytin.FromBase64String(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	//Rollin' in my 5.0
	//With my rag-top down so my hair can blow
	//The girlies on standby waving just to say hi
	//Did you stop? No, I just drove by

	//append some padding to be able to decrypt last block
	pad := ((len(cb)+ks-1)/ks)*ks - len(cb)
	cb = append(cb, make([]byte, pad)...)

	decrypted := make([]byte, 0, len(cb))
	// for each block
	currBlock := 0
	for ; currBlock < len(cb); currBlock += ks {
		ptb := make([]byte, 0)

		// for each byte in currBlock
		for bn := 0; bn < ks; bn++ {
			ab := bytes.Repeat([]byte("A"), ks-len(ptb)-1)
			ab = append(ab, ptb...)
			m := bruteForceX(ab)
			t.Log("\n Lookup table complete for block :", crytin.ToSafeString(ab))

			oab := make([]byte, 0)
			oab = append(oab, cb[0:currBlock]...)
			oab = append(oab, ab...)
			oab = append(oab, cb[currBlock+bn:]...)
			// append shifted len to keep oab constant length
			oab = append(oab, make([]byte, bn+1)...)

			//t.Log("\n=>", crytin.ToHex(oab[currBlock:currBlock+ks]))
			//t.Log("\n=>",crytin.ToHex(oab))
			opb, err := oracle(oab)
			if err != nil {
				t.Error(err)
			}
			lookup := crytin.ToHex(opb[currBlock : currBlock+ks])
			if v, ok := m[lookup]; ok {
				ptb = append(ptb, v)
				//t.Log("\n The letter is : ", string(ptb))
			} else {
				ptb = append(ptb, 46) //"."
				//t.Error("\n Not found in bruteforce lookup map")
			}
			if bn == ks-1 {
				decrypted = append(decrypted, ptb...)
				t.Log("\nptb=>", crytin.ToSafeString(ptb), "\n")
			}
		}
	}
	decrypted = decrypted[0 : len(decrypted)-pad]
	t.Log("\nDecrypted: ", string(decrypted))
}
