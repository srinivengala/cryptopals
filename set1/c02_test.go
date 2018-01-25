package main

import (
	"testing"

	"github.com/srinivengala/cryptopals/crytin"
)

//Fixed XOR

//Write a function that takes two equal-length buffers and produces their XOR combination.
//If your function works properly, then when you feed it the string:
//1c0111001f010100061a024b53535009181c
//... after hex decoding, and when XOR'd against:
//686974207468652062756c6c277320657965
//... should produce:
//746865206b696420646f6e277420706c6179

// C:\Go\bin\go.exe test -timeout 30s github.com\srinivengala\cryptopals\set1 -run ^TestHexToBase64$
// go test -v
// go test

func TestXOR(t *testing.T) {
	expectedHex := "746865206b696420646f6e277420706c6179"
	t.Logf("Operation: 1c0111001f010100061a024b53535009181c XOR 686974207468652062756c6c277320657965")
	t.Logf("Expected: 746865206b696420646f6e277420706c6179")
	a, err := crytin.FromHex("1c0111001f010100061a024b53535009181c")
	b, err := crytin.FromHex("686974207468652062756c6c277320657965")
	x, err := crytin.XOR(a, b)
	xx := crytin.ToHex(x)
	if err != nil || xx != expectedHex {
		t.Error("Expected " + expectedHex + ",\n got " + xx)
	}
}
