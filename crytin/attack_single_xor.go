package crytin

import (
	"fmt"
	"regexp"
)

//Herbert S. Zim, in his classic introductory cryptography text "Codes and Secret Writing",
// gives the English letter frequency sequence as "ETAON RISHD LFCMU GYPWB VKJXQ Z",
// the most common letter pairs as "TH HE AN RE ER IN ON AT ND ST ES EN OF TE ED OR TI HI AS TO",
// and the most common doubled letters as "LL EE SS OO TT FF RR NN PP CC".

//According to Lewand, arranged from most to least common in appearance,
//the letters are: etaoinshrdlcumwfgypbvkjxqz
//Lewand's ordering differs slightly from others,
//such as Cornell University Math Explorer's Project, which produced a table after measuring 40,000 words.

// ASCIIScore1 : reward frequent ascii chars
func ASCIIScore1(pt []byte) int {
	score := 0
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
func ASCIIScore2(pt []byte) int {
	score := 0
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
func ASCIIScore3(pt []byte) int {
	score := 0
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

// AttackSingleByteXOR : Attack single byte XOR cipher text
// score can be ASCIIScore or ASCIIScoreEx
func AttackSingleByteXOR(cb []byte, score func([]byte) int, verbose bool) ([]byte, byte) {
	pb := make([]byte, len(cb))
	pbWinner := make([]byte, len(cb))
	winnerScore := 0
	winner := byte(0)
	for k := byte(32); k <= 126; k++ {
		for i := range cb {
			pb[i] = cb[i] ^ k
		}
		s := score(pb)
		if s >= winnerScore {
			winnerScore = s
			winner = k
			copy(pbWinner, pb)

			if verbose {
				reg, _ := regexp.Compile("[^a-zA-Z0-9 ]")
				fmt.Printf("\n %s score(%3d) = %s", string(winner), winnerScore, reg.ReplaceAllString(string(pbWinner), "*"))
			}
		}
	}
	if verbose {
		fmt.Printf("\n...")
	}
	if winnerScore == 0 {
		return []byte{}, byte(0)
	}
	return pbWinner, winner
}
