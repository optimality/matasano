package challenge3

import "testing"

func TestDecode(t *testing.T) {
	input := "strings.txt"
	expected := "Now that the party is jumping\n"
	actual, err := DecodeFile(input)
	if err != nil {
		t.Errorf("Failed to decode file: %v\n", err)
	}
	if expected != actual {
		t.Errorf("Expected: %v\nActual: %v\n", expected, actual)
	}
}
