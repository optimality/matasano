package challenge18

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

func CTR(plaintext []byte, key []byte, nonce uint64) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Couldn't get AES!")
	}

	ciphertext := make([]byte, len(plaintext))
	keystream := make([]byte, 16)
	for i, p := range plaintext {
		if i%16 == 0 {
			nonceBytes := make([]byte, 16)
			binary.LittleEndian.PutUint64(nonceBytes, nonce)
			nonceBytes = append(nonceBytes[8:16], nonceBytes[0:8]...)
			fmt.Printf("Nonce bytes: %v\n", nonceBytes)
			nonce++
			block.Encrypt(keystream, nonceBytes)
		}
		ciphertext[i] = p ^ keystream[i%16]
	}
	return ciphertext
}

func TestCTR(t *testing.T) {
	input := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	ciphertext, err := base64.StdEncoding.DecodeString(input)
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	if err != nil {
		t.Errorf("Failed to decode input: %v\n", err)
	}
	plaintext := CTR(ciphertext, key, nonce)
	t.Logf("Plaintext: %s\n", plaintext)
}
