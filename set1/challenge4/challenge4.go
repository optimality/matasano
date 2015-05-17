package challenge3

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
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
func DecodeString(s string) ([]byte, int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, 0, fmt.Errorf("Unable to decode input %v\n", s)
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
	return bestDecoding, topScore, nil
}

// DecodeFile takes a filename containing a list of strings that may have been single-XOR encoded and finds the one
// which is mostly likely to have been single-XOR encoded.
func DecodeFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var bestDecoding []byte
	var bestScore int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		decoding, score, err := DecodeString(scanner.Text())
		if err != nil {
			return "", err
		}
		if score > bestScore {
			bestDecoding = decoding
			bestScore = score
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return string(bestDecoding), nil
}
