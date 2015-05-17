package challenge2

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Xor produces the xor of two byte arrays.
func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("Xor requires slices to be the same length: %v, %v", len(a), len(b))
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c, nil
}

func TestXor(t *testing.T) {
	encoded1 := "1c0111001f010100061a024b53535009181c"
	decoded1, err := hex.DecodeString(encoded1)
	if err != nil {
		t.Errorf("Failed to decode input: %v\n", encoded1)
	}

	encoded2 := "686974207468652062756c6c277320657965"
	decoded2, err := hex.DecodeString(encoded2)
	if err != nil {
		t.Errorf("Failed to decode input: %v\n", encoded2)
	}

	expectedEncoded := "746865206b696420646f6e277420706c6179"
	actual, err := Xor(decoded1, decoded2)
	if err != nil {
		t.Errorf("Failed to xor: %v\n", err)
	}
	actualEncoded := hex.EncodeToString(actual)
	if expectedEncoded != actualEncoded {
		t.Errorf("Expected: %v\nActual: %v\n", expectedEncoded, actualEncoded)
	}
}
