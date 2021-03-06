package challenge5

import (
	"encoding/hex"
	"testing"
)

// RepeatedKeyXOR encrypts a plaintext by xoring with a given key, repeating it.
func RepeatedKeyXOR(plaintext, key []byte) []byte {
	cyphertext := make([]byte, len(plaintext))
	for i, p := range plaintext {
		keyIndex := i % len(key)
		cyphertext[i] = p ^ key[keyIndex]
	}
	return cyphertext
}

func TestRepeatedKeyEncoding(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	actual := hex.EncodeToString(RepeatedKeyXOR(input, key))
	if expected != actual {
		t.Errorf("\nExpected: %v\nActual:   %v\n", expected, actual)
	}
}
