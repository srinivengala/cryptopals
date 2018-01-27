package main

import (
	"io/ioutil"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

// 6.txt is repeat-XOR encrypted and then base64 encoded.
// Decrypt it
//
//Here's how:
//
//1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
//2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
//
//this is a test
//
//and
//
//wokka wokka!!!
//
//is 37. Make sure your code agrees before you proceed.
//3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
//4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
//5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
//6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
//7. Solve each block as if it was single-character XOR. You already have code to do this.
//8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

//This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

// go test -v
// go test

func TestHammingDistance(t *testing.T) {
	hd := crytin.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if hd != 37 {
		t.Errorf("Error calculating HammingDistance %d", hd)
	}
	t.Logf("Hamming distance \"%s\" and \"%s\" is %d", "this is a test", "wokka wokka!!!", hd)
}

func TestAttackRepeatXORKey(t *testing.T) {
	dat, err := ioutil.ReadFile("../data/6.txt")
	if err != nil {
		t.Error("Could not load 6.txt file")
	}
	cb, err := crytin.FromBase64(dat)
	if err != nil {
		t.Error("Failed decoding base64")
	}

	pt, key := crytin.AttackRepeatXOR(cb, false)
	t.Logf("\n Key : \"%s\"\n plain text : \"%s\"\n", key, pt)
}
