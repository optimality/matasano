package challenge26

import (
	"crypto/aes"
	"encoding/binary"
	"strings"
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

func AddUserdata(data string) string {
	data = strings.Replace(data, ";", "%59", -1)
	data = strings.Replace(data, "=", "%61", -1)
	return "comment1=cooking%20MCs;userdata=" + data + ";comment2=%20like%20a%20pound%20of%20bacon"
}

func Attack(oracle func(data string) []byte) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	prefixPadding := aes.BlockSize - (len(prefix) % aes.BlockSize)

	userdata := make([]byte, prefixPadding+aes.BlockSize)
	ciphertext := oracle(string(userdata))

	attackTarget := []byte(";admin=true;")
	attackBlockStart := len(prefix) + prefixPadding
	for i, a := range attackTarget {
		ciphertext[attackBlockStart+i] ^= 0 ^ a
	}

	return ciphertext
}

func TestBitflipping(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	oracle := func(data string) []byte {
		return CTR([]byte(AddUserdata(data)), key, nonce)
	}

	ciphertext := Attack(oracle)

	plaintext := CTR(ciphertext, key, nonce)
	t.Logf("Plaintext: %s\n", plaintext)

	if !strings.Contains(string(plaintext), ";admin=true;") {
		t.Errorf("Attack failed!\n")
	}
}
