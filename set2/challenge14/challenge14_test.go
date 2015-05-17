package challenge12

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func RandomBytes(c int) []byte {
	b := make([]byte, c)
	_, err := rand.Read(b)
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

func FindRepeatedBlocks(ciphertext []byte, blockSize int) int {
	for i := 0; i < len(ciphertext)-blockSize; i += blockSize {
		if bytes.Equal(ciphertext[i:i+blockSize], ciphertext[i+blockSize:i+blockSize+blockSize]) {
			return i
		}
	}
	return -1
}

func Analyze(encrypt func([]byte) []byte) (blockSize, prefixSize, secretSize int) {
	test := []byte{}
	emptyPlaintext := encrypt(test) // prefixSize + secretSize + paddingSize
	paddingSize := 0
	ciphertext := []byte{}
	for {
		test = append(test, 'A')
		ciphertext = encrypt(test)
		if len(ciphertext) != len(emptyPlaintext) {
			paddingSize = len(test) - 1
			blockSize = len(ciphertext) - len(emptyPlaintext)
			break
		}
	}

	repeatedBlocks := 0
	for {
		ciphertext = encrypt(test)
		repeatedBlocks = FindRepeatedBlocks(ciphertext, blockSize)
		if repeatedBlocks != -1 {
			break
		}
		test = append(test, 'A')
	}
	prefixSize = repeatedBlocks - (len(test) - blockSize*2)
	secretSize = len(emptyPlaintext) - prefixSize - paddingSize - 1

	return
}

func DecryptSecretByte(encrypt func([]byte) []byte, known []byte, blockSize int, prefixSize int) byte {
	prefixPadding := blockSize - (prefixSize % blockSize)
	knownPadding := blockSize - (len(known) % blockSize) - 1
	padding := prefixPadding + knownPadding
	test := make([]byte, padding+len(known)+1)
	for i := 0; i < padding; i++ {
		test[i] = 'A'
	}
	copy(test[padding:], known)

	testBlockLocation := prefixSize + len(test) - blockSize
	table := map[string]byte{}
	for i := 0; i <= 255; i++ {
		test[len(test)-1] = byte(i)
		ciphertext := encrypt(test)
		table[string(ciphertext[testBlockLocation:testBlockLocation+blockSize])] = byte(i)
	}

	ciphertext := encrypt(test[:padding])
	return table[string(ciphertext[testBlockLocation:testBlockLocation+blockSize])]
}

func DecryptSecret(encrypt func([]byte) []byte, blockSize int, prefixSize int, secretSize int) []byte {
	secret := make([]byte, secretSize)
	for i := range secret {
		secret[i] = DecryptSecretByte(encrypt, secret[:i], blockSize, prefixSize)
	}
	return secret
}

func TestECBDecryption(t *testing.T) {
	key := RandomBytes(aes.BlockSize)
	randomPrefix := RandomBytes(412)
	secret, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		t.Errorf("Failed to decode input: %v", err)
	}
	encrypt := func(plaintext []byte) []byte {
		plaintext = append(randomPrefix, plaintext...)
		plaintext = append(plaintext, secret...)
		return ECBEncrypt(plaintext, key)
	}

	blockSize, prefixSize, secretSize := Analyze(encrypt)
	if blockSize != aes.BlockSize {
		t.Errorf("Failed to detect block size.  Expected: %v Actual: %v\n", aes.BlockSize, blockSize)
	}
	if prefixSize != len(randomPrefix) {
		t.Errorf("Failed to detect prefix size.  Expected: %v Actual: %v\n", len(randomPrefix), prefixSize)
	}
	if secretSize != len(secret) {
		t.Errorf("Failed to detect secret size.  Expected: %v Actual: %v\n", len(secret), secretSize)
	}

	t.Logf("Secret: %s\n", DecryptSecret(encrypt, blockSize, prefixSize, secretSize))
}
