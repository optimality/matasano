package challenge19

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
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
	for i, c := range frequentCharacters {
		characterScore[c] = len(frequentCharacters) - i
	}
	score := 0
	for _, c := range s {
		score += characterScore[c]
	}

	return score
}

// TODO(austin): This attack doesn't get everything, but it's pretty good.  Not going to spend time improving it more,
// per the instructins.
func TestReusedNonces(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	plaintext64s := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}
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

	maximumKeystreamLength := 0
	for _, c := range ciphertexts {
		if len(c) > maximumKeystreamLength {
			maximumKeystreamLength = len(c)
		}
	}

	keystream := make([]byte, maximumKeystreamLength)
	for keystreamIndex := 0; keystreamIndex < len(keystream); keystreamIndex++ {
		bestKeyScore := 0
		bestKey := 0
		for key := 0; key <= 255; key++ {
			keystream[keystreamIndex] = byte(key)
			score := 0
			for _, ciphertext := range ciphertexts {
				score += EnglishFrequency(XOR(ciphertext, keystream[:len(ciphertext)]))
			}
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
		decodes[i] = XOR(ciphertext, keystream[:len(ciphertext)])
	}
	for _, decode := range decodes {
		t.Logf("%s\n", decode)
	}
}
