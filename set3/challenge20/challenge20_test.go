package challenge19

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"io/ioutil"
	"strings"
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

func EnglishFrequency(s []byte) int {
	characterScore := map[byte]int{}
	frequentCharacters := []byte("etaoin shrdlu ETAOIN SHRDLU")
	for _, c := range frequentCharacters {
		characterScore[c] = 1
	}
	score := 0
	for _, c := range s {
		score += characterScore[c]
	}

	return score
}

// TODO(austin): This attack doesn't get everything, but it's pretty good.  Not going to spend time improving it more,
// per the instructions.
func TestReusedNonces(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	file, err := ioutil.ReadFile("ciphertexts.txt")
	if err != nil {
		t.Errorf("Failed to read input: %v", err)
	}
	plaintext64s := strings.Split(string(file), "\n")
	plaintext64s = plaintext64s[:len(plaintext64s)-1]

	plaintexts := make([][]byte, len(plaintext64s))
	for i, p64 := range plaintext64s {
		var err error
		plaintexts[i], err = base64.StdEncoding.DecodeString(p64)
		if err != nil {
			t.Errorf("Failed to base64 decode: %v\n", err)
		}
	}
	ciphertexts := make([][]byte, len(plaintexts))
	for i, plaintext := range plaintexts {
		ciphertexts[i] = CTR(plaintext, key, nonce)
	}

	minimumKeystreamLength := 1000000
	for _, c := range ciphertexts {
		if len(c) < minimumKeystreamLength {
			minimumKeystreamLength = len(c)
		}
	}

	keystream := make([]byte, minimumKeystreamLength)
	test := make([]byte, len(plaintexts))
	for keystreamIndex := 0; keystreamIndex < len(keystream); keystreamIndex++ {
		bestKeyScore := 0
		bestKey := 0
		for key := 0; key <= 255; key++ {
			for i, ciphertext := range ciphertexts {
				test[i] = ciphertext[keystreamIndex] ^ byte(key)
			}
			score := EnglishFrequency(test)
			if score > bestKeyScore {
				bestKeyScore = score
				bestKey = key
			}
		}
		keystream[keystreamIndex] = byte(bestKey)
	}
	t.Logf("Best keystream: %v\n", keystream)

	decodes := make([][]byte, len(ciphertexts))
	for i, ciphertext := range ciphertexts {
		decodes[i] = XOR(ciphertext[:len(keystream)], keystream)
	}
	for _, decode := range decodes {
		t.Logf("%s\n", decode)
	}
}
