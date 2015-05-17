package challenge7

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestAES(t *testing.T) {
	ciphertextBase64, err := ioutil.ReadFile("ciphertext.txt")
	if err != nil {
		t.Errorf("Couldn't read ciphertext: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertextBase64))
	if err != nil {
		t.Errorf("Couldn't decode ciphertext: %v", err)
	}

	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("AES error: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}

	fmt.Printf("%s\n", plaintext)
}
