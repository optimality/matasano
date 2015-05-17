package challenge3

import "testing"

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
