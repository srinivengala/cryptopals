package crytin

import (
	"bytes"
	"fmt"
)

//AES-ECB-Encrypt(random-prefix || attacker-controlled || target-bytes, random-key)

//Byte-at-a-time ECB decryption (Simple)
//
//AES-ECB-Encrypt(your-string || unknown-string, random-key)
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

// Funda:
//
// Brute force last byte of block by using known prefix.
//    Known prefix is : (1.) at Insertion point or first block known text
//                                   (Known text can be anything, we used A's).
//                      (ii) Next blocks: decrypted text till the byte X).
// By decreasing the prefix length, effectively slides the block right.
//                                  or in other words
//                                  shifts the bytes left into the block.
// Brute force last byte of the slided block.
//
// Correlate the bruteforce cipher blocks with brute force bytes
// Compare actual result with bruteforce result to get the brute force byte
//      for current block shift
// to do block shift we just inserted A's while getting acutal result

// AAAAAAAAAAAAAAAX
// AAAAAAAAAAAAAARX
// AAAAAAAAAAAAARoX
// AAAAAAAAAAAARolX
// AAAAAAAAAAARollX
// AAAAAAAAAARolliX
// AAAAAAAAARollinX
// AAAAAAAARollin.X
// AAAAAAARollin. X
// AAAAAARollin. iX
// AAAAARollin. inX
// AAAARollin. in X
// AAARollin. in mX
// AARollin. in myX
// ARollin. in my X
// Rollin. in my 5X
// AAAAAAAAAAAAAAARollin. in my 5.X   <= we know text till X "the oracle will place"
//                                          with given A's inserted
// AAAAAAAAAAAAAARollin. in my 5.0X
// AAAAAAAAAAAAARollin. in my 5.0.X
// AAAAAAAAAAAARollin. in my 5.0.WX
// AAAAAAAAAAARollin. in my 5.0.WiX
// AAAAAAAAAARollin. in my 5.0.WitX
// AAAAAAAAARollin. in my 5.0.WithX
// AAAAAAAARollin. in my 5.0.With X
// AAAAAAARollin. in my 5.0.With mX
// AAAAAARollin. in my 5.0.With myX
// AAAAARollin. in my 5.0.With my X
// AAAARollin. in my 5.0.With my rX
// AAARollin. in my 5.0.With my raX
// AARollin. in my 5.0.With my ragX
// ARollin. in my 5.0.With my rag.X
// Rollin. in my 5.0.With my rag.tX
//                ^
//                |

// Moral : if you let me insert text that will use ECB mode,
//         all unknown bytes to the right of insertion point
//         I will know them

// Remedy : Pad inputs to fixed length

// OracleECB : AES-ECB-Encrypt(random-prefix || attacker-controlled || target-bytes, random-key)
type OracleECB interface {
	// Encrypt : AES-ECB-Encrypt(random-prefix || attacker-controlled || target-bytes, random-key)
	Encrypt(pb []byte, insertPoint int) (cb []byte, err error)
}

// bruteForceX : appends X and creates map[ToHex(cb)]X
// returns: lookup map
// note: converting to string so I don't need to create hash function
//  for map compare keys
func bruteForceX(oracle OracleECB, prefix []byte, insertPoint int, currentBlock int, ks int) map[string]byte {
	m := make(map[string]byte)
	// cheat: 126 optimized for english.
	//  for binary use 256
	for i := byte(0); i < 126; i++ {
		pb := append(prefix, i)
		cb, _ := oracle.Encrypt(pb, insertPoint)
		m[ToHex(cb[currentBlock:currentBlock+ks])] = i
	}
	return m
}

// AttackECBByteAtATime : Attacks ECB mode by brute forcing byte at a time
// AES-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
func AttackECBByteAtATime(oracle OracleECB, insertPoint int, ks int, verbose bool) (err error) {
	cb, _ := oracle.Encrypt([]byte{}, insertPoint)
	decrypted := make([]byte, 0)

	currBlock := 0
	for ; currBlock < insertPoint; currBlock += ks {
	}
	alignBlock := currBlock - insertPoint

	for ; currBlock < len(cb)+alignBlock; currBlock += ks {
		ptb := make([]byte, 0)

		// for each byte in currBlock
		for bn := 0; bn < ks; bn++ {
			ab := bytes.Repeat([]byte("A"), alignBlock+ks-1-len(ptb))
			abptb := append(ab, decrypted...)
			abptb = append(abptb, ptb...)
			m := bruteForceX(oracle, abptb, insertPoint, currBlock, ks)
			if verbose {
				fmt.Print("\n Bruteforced block :", ToSafeString(abptb))
			}

			//t.Log("\n=>", crytin.ToHex(oab[currBlock:currBlock+ks]))
			//t.Log("\n=>",crytin.ToHex(oab))
			ocb, err := oracle.Encrypt(ab, insertPoint)
			if err != nil {
				return err
			}

			// append shifted len to keep ocb constant length
			ocb = append(ocb, make([]byte, bn+1)...)

			lookup := ToHex(ocb[currBlock : currBlock+ks])
			if v, ok := m[lookup]; ok {
				ptb = append(ptb, v)
				//t.Log("\n The letter is : ", string(ptb))
			} else {
				ptb = append(ptb, 46) //"."
				//t.Error("\n Not found in bruteforce lookup map")
			}
			if bn == ks-1 {
				decrypted = append(decrypted, ptb...)
				if verbose {
					fmt.Print("\nptb=>", ToSafeString(ptb), "\n")
				}
			}
		}
	}
	pad := ((len(cb)+ks-1)/ks)*ks - len(cb)
	decrypted = decrypted[0 : len(decrypted)-pad]
	if verbose {
		fmt.Print("\nDecrypted: ", string(decrypted))
	}
	return nil
}
