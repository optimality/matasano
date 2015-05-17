package challenge12

import (
	"bytes"
	"crypto/aes"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"testing"
)

func RandomBytes(c int) []byte {
	b := make([]byte, c)
	_, err := cryptoRand.Read(b)
	if err != nil {
		panic("Unable to generate key!")
	}
	return b
}

func Pad(plaintext []byte) []byte {
	paddingLength := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	return append(plaintext, padding...)
}

func ECBOracle(ciphertext []byte, blockSize int) bool {
	for i := 0; i < len(ciphertext); i += blockSize {
		for j := i + blockSize; j < len(ciphertext); j += blockSize {
			if bytes.Equal(ciphertext[i:i+blockSize], ciphertext[j:j+blockSize]) {
				return true
			}
		}
	}
	return false
}

func ECBEncrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	plaintext = Pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return ciphertext
}

func FindBlocksize(encrypt func([]byte) []byte) (int, int) {
	test := []byte{}
	previousTextSize := len(encrypt(test))
	for {
		test = append(test, 'A')
		textSize := len(encrypt(test))
		if textSize != previousTextSize {
			return textSize - previousTextSize, previousTextSize - len(test)
		}
	}
}

func DecryptSecretByte(encrypt func([]byte) []byte, known []byte, blockSize int) byte {
	padding := blockSize - (len(known) % blockSize) - 1
	test := make([]byte, padding+len(known)+1)
	for i := 0; i < padding; i++ {
		test[i] = 'A'
	}
	copy(test[padding:], known)

	table := map[string]byte{}
	for i := 0; i <= 255; i++ {
		test[len(test)-1] = byte(i)
		ciphertext := encrypt(test)
		table[string(ciphertext[len(test)-blockSize:len(test)])] = byte(i)
	}

	ciphertext := encrypt(test[:padding])
	return table[string(ciphertext[len(test)-blockSize:len(test)])]
}

func DecryptSecret(encrypt func([]byte) []byte, blockSize int, secretSize int) []byte {
	secret := make([]byte, secretSize)
	for i := range secret {
		secret[i] = DecryptSecretByte(encrypt, secret[:i], blockSize)
	}
	return secret
}

func TestECBDecryption(t *testing.T) {
	key := RandomBytes(aes.BlockSize)
	secret, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		t.Errorf("Failed to decode input: %v", err)
	}
	encrypt := func(plaintext []byte) []byte {
		plaintext = append(plaintext, secret...)
		return ECBEncrypt(plaintext, key)
	}

	blockSize, secretSize := FindBlocksize(encrypt)
	if blockSize != aes.BlockSize {
		t.Errorf("Failed to detect block size.  Expected: %v Actual: %v\n", aes.BlockSize, blockSize)
	}
	if secretSize != len(secret) {
		t.Errorf("Failed to detect secret size.  Expected: %v Actual: %v\n", len(secret), secretSize)
	}

	testString := make([]byte, 1024)
	for i := range testString {
		testString[i] = 'A'
	}
	usingECB := ECBOracle(encrypt(testString), blockSize)
	if !usingECB {
		t.Errorf("Oracle failed to detect ECB\n")
	}

	t.Logf("Secret: %s\n", DecryptSecret(encrypt, blockSize, secretSize))
}
