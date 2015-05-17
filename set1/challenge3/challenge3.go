package challenge3

import (
	"encoding/hex"
	"fmt"
)

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

// DecodeString tries also possible single-XOR decodings of a string.
func DecodeString(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("Unable to decode input %v\n", s)
	}

	topScore := 0
	bestDecoding := []byte{}
	for x := 0; x <= 255; x++ {
		decoded := XorSingle(byte(x), b)
		score := ScoreString(decoded)
		if score > topScore {
			topScore = score
			bestDecoding = decoded
		}
	}
	return string(bestDecoding), nil
}
