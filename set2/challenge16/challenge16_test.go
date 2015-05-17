package challenge16

import (
	"crypto/aes"
	"strings"
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

func AddUserdata(data string) string {
	data = strings.Replace(data, ";", "%59", -1)
	data = strings.Replace(data, "=", "%61", -1)
	return "comment1=cooking%20MCs;userdata=" + data + ";comment2=%20like%20a%20pound%20of%20bacon"
}

func Attack(oracle func(data string) []byte) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	prefixPadding := aes.BlockSize - (len(prefix) % aes.BlockSize)

	userdata := make([]byte, prefixPadding+aes.BlockSize)
	ciphertext := oracle(string(userdata))

	attackTarget := ";admin=true;"
	attackBlockStart := len(prefix) + prefixPadding
	attackBits := XOR([]byte(attackTarget), []byte(suffix[:len(attackTarget)]))
	attackSlice := ciphertext[attackBlockStart : attackBlockStart+len(attackBits)]
	attack := XOR(attackSlice, attackBits)
	copy(attackSlice, attack)
	return ciphertext
}

func TestBitflipping(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	oracle := func(data string) []byte {
		return CBCEncrypt([]byte(AddUserdata(data)), key)
	}

	ciphertext := Attack(oracle)

	plaintext := CBCDecrypt(ciphertext, key)
	t.Logf("Plaintext: %s\n", plaintext)

	if !strings.Contains(string(plaintext), ";admin=true;") {
		t.Errorf("Attack failed!\n")
	}
}
