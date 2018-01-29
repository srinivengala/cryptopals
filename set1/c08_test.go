package main

import (
	"bufio"
	"os"
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

func TestDetectECBMode(t *testing.T) {
	file, err := os.Open("../data/8.txt")
	defer file.Close()

	if err != nil {
		t.Error(err)
	}

	found := false

	//The Scanner solution does not handle long lines.
	//The ReadLine solution is complex to implement.
	//The ReadString solution is the simplest and works for long lines.
	reader := bufio.NewReader(file)
	for i := 1; ; i++ {
		line, err := reader.ReadString('\n') //check err after processing line

		cb, _ := crytin.FromBase64String(line)
		isECB, bs := crytin.DetectECB(cb)
		if isECB {
			found = true
			t.Logf("line %d : ECB-%d detected", i, bs)
		}

		if err != nil {
			break
		}
	}

	if !found {
		t.Error("ECB not detected in ../data/8.txt")
	}
}
