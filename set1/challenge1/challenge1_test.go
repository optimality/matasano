package challenge1

import "testing"

func TestHexToBase64(t *testing.T) {
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual, err := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Errorf("Error converting hex to base64: %v", err)
	}
	if expected != actual {
		t.Errorf("Expected: %v\nActual: %v\n", expected, actual)
	}
}
