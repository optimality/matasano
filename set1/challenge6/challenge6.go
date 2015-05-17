package challenge6

import (
	"fmt"
	"sort"
)

// HammingDistance computes the number of differing bits in the two byte slices.
func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("HammingDistance inputs must be same length.")
	}
	distance := 0
	for i, x := range a {
		y := b[i]
		distance += setBits(x ^ y)
	}
	return distance
}

func setBits(b byte) int {
	total := 0
	for b > 0 {
		if b&1 > 0 {
			total++
		}
		b >>= 1
	}
	return total
}

type sortedMap struct {
	m map[int]float64
	s []int
}

func (sm *sortedMap) Len() int {
	return len(sm.m)
}

func (sm *sortedMap) Less(i, j int) bool {
	return sm.m[sm.s[i]] < sm.m[sm.s[j]]
}

func (sm *sortedMap) Swap(i, j int) {
	sm.s[i], sm.s[j] = sm.s[j], sm.s[i]
}

func sortedKeys(m map[int]float64) []int {
	sm := new(sortedMap)
	sm.m = m
	sm.s = make([]int, len(m))
	i := 0
	for key := range m {
		sm.s[i] = key
		i++
	}
	sort.Sort(sm)
	return sm.s
}

// FindKeysize examines a ciphertext and attempts to determine the size of its key.
// TODO(austin): I don't think this is working right; the actual key winds up halfway in the middle.
func FindKeysize(ciphertext []byte) []int {
	scores := map[int]float64{}
	for keysize := 2; keysize <= 40; keysize++ {
		if 2*keysize > len(ciphertext) {
			break
		}
		scores[keysize] = float64(HammingDistance(ciphertext[0:keysize], ciphertext[keysize:2*keysize])) / float64(keysize)
	}
	fmt.Printf("Keysizes: %v\n", scores)
	return sortedKeys(scores)
}

// TransposeBlocks splits a ciphertext into keysize blocks, where block i consists of all the ith characters
func TransposeBlocks(ciphertext []byte, keysize int) [][]byte {
	blocks := make([][]byte, keysize)
	for i := 0; i < keysize; i++ {
		blocks[i] = []byte{}
	}

	for i, b := range ciphertext {
		blocks[i%keysize] = append(blocks[i%keysize], b)
	}
	return blocks
}

// ScoreString tells you how likely a string is to be in English.
func ScoreString(s []byte) int {
	likelyCharacters := map[byte]bool{}
	for _, c := range []byte("etaoin shrdlu ETAOIN SHRDLU") {
		likelyCharacters[c] = true
	}
	score := 0
	for _, c := range s {
		if likelyCharacters[c] {
			score++
		}
	}

	return score
}

// XorSingle xors a string with a single byte
func XorSingle(b byte, s []byte) []byte {
	x := make([]byte, len(s))
	for i, c := range s {
		x[i] = c ^ b
	}
	return x
}

// BestSingleByteDecoding returns the byte which produces the best decoding of the given block.
func BestSingleByteDecoding(ciphertext []byte) byte {
	var topScore int
	var bestKey byte
	for x := 0; x <= 255; x++ {
		decoded := XorSingle(byte(x), ciphertext)
		score := ScoreString(decoded)
		if score > topScore {
			topScore = score
			bestKey = byte(x)
		}
	}
	return bestKey
}

// GuessKeys guesses the best keys for a given ciphertext
func GuessKeys(ciphertext []byte) [][]byte {
	keysizes := FindKeysize(ciphertext)
	fmt.Printf("Keysizes:%v\n", keysizes)
	keys := make([][]byte, len(keysizes))
	for i, keysize := range keysizes {
		blocks := TransposeBlocks(ciphertext, keysize)
		keys[i] = make([]byte, keysize)
		for j, block := range blocks {
			keys[i][j] = BestSingleByteDecoding(block)
		}
	}
	return keys
}

// Decode decodes a ciphertext.
func Decode(ciphertext []byte) ([]byte, []byte) {
	keys := GuessKeys(ciphertext)
	fmt.Printf("Keys: %s\n", keys)
	var bestPlaintext []byte
	var bestPlaintextScore int
	var bestKey []byte
	for _, key := range keys {
		plaintext := make([]byte, len(ciphertext))
		for i, p := range ciphertext {
			plaintext[i] = p ^ key[i%len(key)]
		}
		score := ScoreString(plaintext)
		if score > bestPlaintextScore {
			bestPlaintextScore = score
			bestPlaintext = plaintext
			bestKey = key
		}
	}
	return bestPlaintext, bestKey
}
