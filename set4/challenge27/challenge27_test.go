package challenge27

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Arrays must be the same length!")
	}
	c := make([]byte, len(a))
	for i, x := range a {
		y := b[i]
		c[i] = x ^ y
	}
	return c
}

func CBCEncrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	paddingLength := len(key) - (len(plaintext) % len(key))
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	plaintext = append(plaintext, padding...)

	ciphertext := make([]byte, len(plaintext))
	previousBlock := key
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		currentBlock := XOR(previousBlock, plaintext[i:i+block.BlockSize()])
		block.Encrypt(ciphertext[i:], currentBlock)
		previousBlock = ciphertext[i : i+block.BlockSize()]
	}
	return ciphertext
}

func CBCDecrypt(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	plaintext := make([]byte, len(ciphertext))
	previousBlock := key
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		currentBlock := make([]byte, block.BlockSize())
		block.Decrypt(currentBlock, ciphertext[i:])
		copy(plaintext[i:], XOR(currentBlock, previousBlock))
		previousBlock = ciphertext[i : i+block.BlockSize()]
	}

	possiblePaddingLength := int(plaintext[len(plaintext)-1])
	for i := 1; i <= possiblePaddingLength; i++ {
		if int(plaintext[len(plaintext)-i]) != possiblePaddingLength {
			return plaintext
		}
	}
	return plaintext[:len(plaintext)-possiblePaddingLength]
}

func MessageIsValid(message []byte) bool {
	for _, m := range message {
		if m >= byte(128) {
			return false
		}
	}
	return true
}

func TestBitflipping(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	// Sender
	message := make([]byte, aes.BlockSize*3)
	ciphertext := CBCEncrypt(message, key)
	fmt.Println(ciphertext)

	// Attacker
	for i := range ciphertext[aes.BlockSize : aes.BlockSize*2] {
		ciphertext[aes.BlockSize+i] = 0
	}
	for i := range ciphertext[aes.BlockSize*2 : aes.BlockSize*3] {
		ciphertext[aes.BlockSize*2+i] = ciphertext[i]
	}
	fmt.Println(ciphertext)

	// Receiver
	plaintext := CBCDecrypt(ciphertext, key)
	if MessageIsValid(plaintext) {
		t.Errorf("Attacker failed to trigger error.  Recovered plaintext: %v\n", plaintext)
	}
	fmt.Println(plaintext)

	// Attacker now gets decrypted message.
	attackKey := XOR(plaintext[:aes.BlockSize], plaintext[aes.BlockSize*2:aes.BlockSize*3])
	if !bytes.Equal(key, attackKey) {
		t.Errorf("Attacker failed to recover key.  Expected: %s Actual: %s\n", key, attackKey)
	}
}
