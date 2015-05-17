package challenge17

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
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

func CBCEncrypt(plaintext []byte, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	paddingLength := len(key) - (len(plaintext) % len(key))
	if paddingLength == 0 {
		paddingLength = aes.BlockSize
	}
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
	return ciphertext, []byte(iv)
}

func StripPadding(plaintext []byte) ([]byte, bool) {
	possiblePaddingLength := int(plaintext[len(plaintext)-1])
	if possiblePaddingLength == 0 {
		return plaintext, false
	}
	for i := 1; i <= possiblePaddingLength; i++ {
		if int(plaintext[len(plaintext)-i]) != possiblePaddingLength {
			return plaintext, false
		}
	}
	return plaintext[:len(plaintext)-possiblePaddingLength], true
}

func CBCDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, bool) {
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

	return StripPadding(plaintext)
}

// TODO(austin): This function could undoubtedly be cleaned up.  I think we can cut down on the number of copies
// we make.
func Attack(ciphertext []byte, oracle func([]byte, []byte) bool, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	for targetByte := len(plaintext) - 1; targetByte >= aes.BlockSize; targetByte-- {
		attackByte := targetByte - aes.BlockSize
		attack := make([]byte, (targetByte/aes.BlockSize+1)*aes.BlockSize)
		copy(attack, ciphertext)
		padding := aes.BlockSize - (targetByte % aes.BlockSize)
		for i := 1; i < padding; i++ {
			attack[attackByte+i] = ciphertext[attackByte+i] ^ byte(padding) ^ plaintext[targetByte+i]
		}
		found := false
		for testByte := 0; testByte <= 255; testByte++ {
			if testByte == padding {
				continue
			}
			attack[attackByte] = ciphertext[attackByte] ^ byte(testByte) ^ byte(padding)
			if oracle(attack, iv) {
				plaintext[targetByte] = byte(testByte)
				found = true
				break
			}
		}
		if !found {
			plaintext[targetByte] = byte(padding)
		}
	}

	for targetByte := aes.BlockSize - 1; targetByte >= 0; targetByte-- {
		attack := make([]byte, (targetByte/aes.BlockSize+1)*aes.BlockSize)
		copy(attack, ciphertext)
		attackIV := make([]byte, len(iv))
		copy(attackIV, iv)
		padding := aes.BlockSize - (targetByte % aes.BlockSize)
		for i := 1; i < padding; i++ {
			attackIV[targetByte+i] = iv[targetByte+i] ^ byte(padding) ^ plaintext[targetByte+i]
		}
		found := false
		for testByte := 0; testByte <= 255; testByte++ {
			if testByte == padding {
				continue
			}
			attackIV[targetByte] = iv[targetByte] ^ byte(testByte) ^ byte(padding)
			if oracle(attack, attackIV) {
				plaintext[targetByte] = byte(testByte)
				found = true
				break
			}
		}
		if !found {
			plaintext[targetByte] = byte(padding)
		}
	}
	plaintext, _ = StripPadding(plaintext)
	return plaintext
}

func TestPaddingOracleAttack(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	cookies64 := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	for _, cookie := range cookies64 {
		plaintext, err := base64.StdEncoding.DecodeString(cookie)
		if err != nil {
			t.Errorf("Failed to decrypt plaintext: %v\n", err)
		}
		ciphertext, iv := CBCEncrypt(plaintext, key)

		oracle := func(ciphertext []byte, iv []byte) bool {
			_, valid := CBCDecrypt(ciphertext, key, iv)
			return valid
		}

		decryptedPlaintext := Attack(ciphertext, oracle, iv)
		if !bytes.Equal(decryptedPlaintext, plaintext) {
			t.Errorf("Failed to decrypt.  Expected: %v Actual: %v\n", plaintext, decryptedPlaintext)
		}
		t.Logf("Decrypted: %s\n", decryptedPlaintext)
	}
}
