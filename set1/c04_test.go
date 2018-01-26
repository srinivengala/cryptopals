package main

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

//One of the 60-character strings in 4.txt file has been encrypted by single-character XOR.

// go test -v
// go test

func TestAttackSingleXORFile(t *testing.T) {
	dat, err := ioutil.ReadFile("../data/4.txt")
	if err != nil {
		t.Error("Could not read ../data/4.txt file")
	}
	lines := strings.Split(string(dat), "\n")

	winScore := 0
	winLine := []byte{}
	winByte := byte(0)
	for _, line := range lines {
		input := line

		cb, err := crytin.FromHex(input)
		if err != nil {
			t.Error("FromHex failed")
			return
		}

		// Only ASCIIScore4 worked :)
		pb1, secret, score := crytin.AttackSingleByteXOR(cb, crytin.ASCIIScore4, false)

		if score > winScore {
			winScore = score
			winByte = secret
			winLine = make([]byte, len(pb1))
			copy(winLine, pb1)
		}

		if len(pb1) == 0 {
			t.Error("Could not find XOR byte")
		}

		//t.Logf(" %s (%d) : %s", string(secret), score, crytin.ToSafeString(pb1))
	}

	t.Logf(" %s : %s", string(winByte), crytin.ToSafeString(winLine))
}
