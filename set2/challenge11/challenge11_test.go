package challenge11

import (
	"bytes"
	"crypto/aes"
	cryptoRand "crypto/rand"
	"testing"
)
import mathRand "math/rand"

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

func CBCEncrypt(plaintext []byte) []byte {
	key := RandomBytes(aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	plaintext = Pad(plaintext)

	ciphertext := make([]byte, len(plaintext))
	randomIV := RandomBytes(block.BlockSize())
	previousBlock := randomIV
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		currentBlock := XOR(previousBlock, plaintext[i:i+block.BlockSize()])
		block.Encrypt(ciphertext[i:], currentBlock)
		previousBlock = ciphertext[i : i+block.BlockSize()]
	}
	return ciphertext
}

func ECBEncrypt(plaintext []byte) []byte {
	key := RandomBytes(aes.BlockSize)
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

func RandomEncrypt(plaintext []byte) ([]byte, bool) {
	frontCrap := RandomBytes(mathRand.Intn(5) + 5)
	rearCrap := RandomBytes(mathRand.Intn(5) + 5)

	plaintext = append(frontCrap, plaintext...)
	plaintext = append(plaintext, rearCrap...)
	if mathRand.Float64() < 0.5 {
		return CBCEncrypt(plaintext), false
	}
	return ECBEncrypt(plaintext), true
}

func ECBOracle(ciphertext []byte) bool {
	for i := 0; i < len(ciphertext); i += 16 {
		for j := i + 16; j < len(ciphertext); j += 16 {
			if bytes.Equal(ciphertext[i:i+16], ciphertext[j:j+16]) {
				return true
			}
		}
	}
	return false
}

func TestOracle(t *testing.T) {
	for i := 0; i < 100; i++ {
		plaintext := RandomBytes(1024)
		for i := range plaintext {
			plaintext[i] = 'a'
		}
		ciphertext, ecb := RandomEncrypt(plaintext)
		oracle := ECBOracle(ciphertext)
		if oracle != ecb {
			t.Errorf("Oracle failed.  Expected: %v Actual: %v\n", ecb, oracle)
		}
	}
}
