package challenge6

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

const ciphertextFilename = "ciphertext.txt"

func readCiphertext() ([]byte, error) {
	ciphertext, err := ioutil.ReadFile(ciphertextFilename)
	if err != nil {
		return nil, err
	}
	decodedCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}
	return decodedCiphertext, nil
}

func TestHammingDistance(t *testing.T) {
	input1 := []byte("this is a test")
	input2 := []byte("wokka wokka!!!")
	expected := 37
	actual := HammingDistance(input1, input2)
	if expected != actual {
		t.Errorf("Expected: %v\nActual: %v\n", expected, actual)
	}
}

func TestDecoding(t *testing.T) {
	ciphertext, err := readCiphertext()
	if err != nil {
		t.Errorf("Couldn't read ciphertext: %v", err)
	}
	plaintext, key := Decode(ciphertext)
	fmt.Printf("Plaintext:\n%s\nKey:\n%s\nKeysize:\n%v\n", plaintext, key, len(key))
}
