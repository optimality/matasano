package challenge9

import (
	"bytes"
	"testing"
)

func PKCS7Padding(b []byte, length int) []byte {
	paddingLength := length - len(b)
	if paddingLength > 255 {
		panic("More than 255 bytes of padding needed!")
	}
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	return append(b, padding...)
}

func TestPKCS7(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	actual := PKCS7Padding(input, 20)
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %s\nActual:%s\n", expected, actual)
	}
}
