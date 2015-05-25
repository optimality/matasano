package challenge25

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"io/ioutil"
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
			nonce++
			block.Encrypt(keystream, nonceBytes)
		}
		ciphertext[i] = p ^ keystream[i%16]
	}
	return ciphertext
}

func RandomAccessWrite(ciphertext []byte, key []byte, nonce uint64, offset int, edit []byte) []byte {
	plaintext := CTR(ciphertext, key, nonce)
	copy(plaintext[offset:], edit)
	return CTR(plaintext, key, nonce)
}

func Attack(ciphertext []byte, editFunc func(ciphertext []byte, offset int, edit []byte) []byte) []byte {
	attackText := make([]byte, len(ciphertext))
	attackCipher := editFunc(ciphertext, 0, attackText)
	recoveredPlaintext := make([]byte, len(ciphertext))
	for i, c := range attackCipher {
		recoveredPlaintext[i] = c ^ attackText[i] ^ ciphertext[i]
	}
	return recoveredPlaintext
}

func TestCTR(t *testing.T) {
	plaintext, err := ioutil.ReadFile("plaintext.txt")
	if err != nil {
		t.Errorf("Failed to read input file: %v\n", err)
	}
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	ciphertext := CTR(plaintext, key, nonce)
	editFunc := func(ciphertext []byte, offset int, edit []byte) []byte {
		return RandomAccessWrite(ciphertext, key, nonce, offset, edit)
	}
	recoveredPlaintext := Attack(ciphertext, editFunc)
	if !bytes.Equal(plaintext, recoveredPlaintext) {
		t.Errorf("Failed to recover plaintext.\nExpected: %s\n Actual: %s\n", plaintext, recoveredPlaintext)
	}
}
