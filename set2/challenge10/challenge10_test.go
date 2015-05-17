package challenge10

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"
	"testing"
)

const iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

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
	previousBlock := []byte(iv)
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
	previousBlock := []byte(iv)
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

func TestEncryption(t *testing.T) {
	plaintext := []byte("trololol")
	key := []byte("YELLOW SUBMARINE")
	ciphertext := CBCEncrypt(plaintext, key)
	decodedText := CBCDecrypt(ciphertext, key)
	if !bytes.Equal(plaintext, decodedText) {
		t.Errorf("Expected:%s\nActual:%s\n", plaintext, decodedText)
	}
}

func TestDecryptSample(t *testing.T) {
	ciphertext64, err := ioutil.ReadFile("ciphertext.txt")
	key := []byte("YELLOW SUBMARINE")
	if err != nil {
		t.Errorf("Failed to read file:%v\n", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertext64))
	plaintext := CBCDecrypt(ciphertext, key)
	t.Logf("Plaintext: %s\n", plaintext)
}
