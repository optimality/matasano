package challenge2

import (
	"encoding/hex"
	"testing"
)

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
