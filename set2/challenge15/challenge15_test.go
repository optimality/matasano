package challenge15

import (
	"fmt"
	"testing"
)

func StripPadding(plaintext []byte) ([]byte, error) {
	possiblePaddingLength := int(plaintext[len(plaintext)-1])
	for i := 1; i <= possiblePaddingLength; i++ {
		if int(plaintext[len(plaintext)-i]) != possiblePaddingLength {
			return plaintext, fmt.Errorf("Plaintext had invalid padding!")
		}
	}
	return plaintext[:len(plaintext)-possiblePaddingLength], nil
}

func TestStripPadding(t *testing.T) {
	input := "ICE ICE BABY\x04\x04\x04\x04"
	expected := "ICE ICE BABY"
	actual, err := StripPadding([]byte(input))
	if err != nil {
		t.Errorf("Failed to strip padding: %v", err)
	}
	if expected != string(actual) {
		t.Errorf("Expected: %v Actual: %v", expected, string(actual))
	}
}

func TestStripPaddingFailure(t *testing.T) {
	input := "ICE ICE BABY\x05\x05\x05\x05"
	_, err := StripPadding([]byte(input))
	if err == nil {
		t.Errorf("Expected error when stripping.\n")
	}

	input = "ICE ICE BABY\x01\x02\x03\x04"
	_, err = StripPadding([]byte(input))
	if err == nil {
		t.Errorf("Expected error when stripping.\n")
	}
}
