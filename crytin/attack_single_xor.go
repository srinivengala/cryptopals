package crytin

import (
	"bytes"
	"fmt"
)

//Herbert S. Zim, in his classic introductory cryptography text "Codes and Secret Writing",
// gives the English letter frequency sequence as "ETAON RISHD LFCMU GYPWB VKJXQ Z",
// the most common letter pairs as "TH HE AN RE ER IN ON AT ND ST ES EN OF TE ED OR TI HI AS TO",
// and the most common doubled letters as "LL EE SS OO TT FF RR NN PP CC".

//According to Lewand, arranged from most to least common in appearance,
//the letters are: etaoinshrdlcumwfgypbvkjxqz
//Lewand's ordering differs slightly from others,
//such as Cornell University Math Explorer's Project, which produced a table after measuring 40,000 words.
// http://www.math.cornell.edu/~mec/

// ASCIIScore1 : reward frequent ascii chars
func ASCIIScore1(pt []byte) (score int) {
	score = 0
	if len(pt) > 80 {
		pt = pt[0:80]
	}
	for i := range pt {
		// printable range is 32 to 126
		// capitals
		if pt[i] >= 65 && pt[i] <= 90 {
			score++
		}
		// small
		if pt[i] >= 97 && pt[i] <= 122 {
			score += 2
		}
		// numbers
		//if pt[i] >= 48 && pt[i] <= 57 {
		//	score++
		//}
		// space ,.'"
		if pt[i] == 32 || pt[i] == 44 || pt[i] == 46 || pt[i] == 39 || pt[i] == 34 {
			score += 3
		}
	}
	return score
}

// ASCIIScore2 : reward "ETAOIN SHRDLU CMFWYP" the most used characters
func ASCIIScore2(pt []byte) (score int) {
	score = 0
	shrdlu := []byte{0x45, 0x54, 0x41, 0x4F, 0x49, 0x4E, //ETAOIN
		0x43, 0x4D, 0x46, 0x57, 0x59, 0x50, //CMFWYP
		0x53, 0x48, 0x52, 0x44, 0x4C, 0x55} //SHRDLU

	if len(pt) > 80 {
		pt = pt[0:80]
	}

	for i := range pt {
		for j := range shrdlu {
			// a - A = 32 >> 97-65=32
			if pt[i] == shrdlu[j] || pt[i] == shrdlu[j]+32 {
				score++
				break
			}
		}
		// space
		if pt[i] == 32 {
			score++
		}
	}
	return score
}

// ASCIIScore3 : reward space, period and comma
func ASCIIScore3(pt []byte) (score int) {
	score = 0
	selectChars := []byte{32, 46, 44, 39, 34}

	if len(pt) > 80 {
		pt = pt[0:80]
	}

	for i := range pt {
		for j := range selectChars {
			if pt[i] == selectChars[j] {
				score += 1
				break
			}
		}
	}
	return score
}

// ASCIIScore 😎 : reward english letter frequency
// punish if not from frequency letters
func ASCIIScore(pt []byte) (score int) {
	//etaoinshrdlcumwfgypbvkjxqz
	frequency := []byte("zqxjkvbpygfwmucldrhsnioate")

	if len(pt) > 80 {
		pt = pt[0:80] // truncate to 80 for performance
	}

	score = 0
	for _, v := range pt {
		score += bytes.IndexByte(frequency, v) // IndexByte returns -1 if not present
	}
	return score
}

// Lesson learned for scoring algorithms : reward desired behavior and punish undesired behavior

// AttackSingleByteXOR : Attack single byte XOR cipher text
// score can be crytin.ASCIIScore
func AttackSingleByteXOR(cb []byte, score func([]byte) int, verbose bool) (pbWinner []byte, winnerKey byte, winnerScore int) {
	pbWinner = make([]byte, len(cb))
	winnerScore = 0
	winnerKey = byte(0)
	for k := byte(32); k <= 126; k++ {
		pb := XOR(cb, []byte{k})
		s := score(pb)
		if s >= winnerScore {
			winnerScore = s
			winnerKey = k
			copy(pbWinner, pb)

			if verbose {
				fmt.Printf("\n %s score(%3d) = %s", string(winnerKey), winnerScore, ToSafeString(pb))
			}
		}
	}
	if verbose {
		fmt.Printf("\n...\n")
	}
	if winnerScore == 0 {
		return []byte{}, byte(0), 0
	}
	return pbWinner, winnerKey, winnerScore
}
