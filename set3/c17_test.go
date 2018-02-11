package main

import (
	"testing"
)

// cb(i-1) XOR dec(key,cb(i)) = pb(i)
//
// (cb(i-1) XOR kpb(i)) XOR dec(key,cb(i)) = tb
//
// (..00 R  XOR ..00) XOR dec(key, cb(i)) = tb ; R where tb[ks-1] = 0x01 a valid padding
// then kpt1 = kpb(i)[ks-1] = R XOR 0x01
//
// (..R 02  XOR ..00 kpt1) XOR dec(key, cb(i)) = tb ; R where tb[ks-2],tb[ks-1] = 0x02 a valid padding
// then kpt2 = kpb(i)[ks-2] = R XOR 0x02
//
// (..R 03 03 XOR ..00 kpt2 kpt1) XOR dec(key, cb(i)) = tb ; R where tb[ks-3],tb[ks-2],tb[ks-1] = 0x03 a valid padding
// then kpt3 = kpb(i)[ks-2] = R XOR 0x03

func testCBCPaddingOracle(t testing.T) {

}
