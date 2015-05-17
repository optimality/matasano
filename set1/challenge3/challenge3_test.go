package challenge3

import (
	"encoding/hex"
	"fmt"
	"testing"
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

	var topScore int
	var bestDecoding []byte
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

func TestDecode(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"
	actual, err := DecodeString(input)
	if err != nil {
		t.Errorf("Failed to decode input: %v", input)
	}
	if expected != actual {
		t.Errorf("Expected: %v\nActual: %v\n", expected, actual)
	}
}
