package challenge29

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func SHA1(message []byte) []byte {
	h0, h1, h2, h3, h4 := uint32(0x67452301), uint32(0xEFCDAB89), uint32(0x98BADCFE), uint32(0x10325476), uint32(0xC3D2E1F0)
	return SHA1Fixated(message, 0, h0, h1, h2, h3, h4)
}

func MakePadding(ml int, prefixLength int) []byte {
	padding := make([]byte, 64-(ml+9)%64+9)
	padding[0] = 0x80
	for i := 1; i < len(padding)-8; i++ {
		padding[i] = 0
	}
	binary.BigEndian.PutUint64(padding[len(padding)-8:], uint64((ml+prefixLength)*8))
	return padding
}

func SHA1Fixated(message []byte, prefixLength int, h0, h1, h2, h3, h4 uint32) []byte {
	padding := MakePadding(len(message), prefixLength)
	message = append(message, padding...)
	for c := 0; c < len(message); c += 64 {
		chunk := message[c : c+64]
		w := make([]uint32, 80)
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(chunk[i*4 : (i+1)*4])
		}
		for i := 16; i < 80; i++ {
			t := (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
			w[i] = (t << 1) | t>>(32-1)
		}

		a, b, c, d, e := h0, h1, h2, h3, h4
		for i := 0; i < 80; i++ {
			var f, k uint32
			if i < 20 {
				f = (b & c) | (^b & d)
				k = 0x5A827999
			} else if i < 40 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i < 60 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			temp := ((a << 5) | (a >> (32 - 5))) + f + e + k + w[i]
			e, d, c, b, a = d, c, b<<30|b>>(32-30), a, temp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}

	hash := make([]byte, 20)
	binary.BigEndian.PutUint32(hash[0:4], h0)
	binary.BigEndian.PutUint32(hash[4:8], h1)
	binary.BigEndian.PutUint32(hash[8:12], h2)
	binary.BigEndian.PutUint32(hash[12:16], h3)
	binary.BigEndian.PutUint32(hash[16:20], h4)

	return hash
}

func TestSHA1(t *testing.T) {
	testPairs := map[string]string{
		"The quick brown fox jumps over the lazy dog": "L9ThxnotKPzthJ7hu3bnORuT6xI=",
		"The quick brown fox jumps over the lazy cog": "3p8sf9JeGzr60+haC9F9mxANtLM=",
	}
	for input, expected := range testPairs {
		actual := base64.StdEncoding.EncodeToString(SHA1([]byte(input)))
		if expected != actual {
			t.Errorf("Unexpected output in SHA1.  Expected: %v Actual: %v", expected, actual)
		}
	}
}

func TestLengthExtension(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	originalSignature := SHA1(append(key, message...))

	guessedKeyLength := len(key) // challenge doesn't say how to guess this, assuming we're not supposed to.
	messageLength := len(message)
	gluePadding := MakePadding(guessedKeyLength+messageLength, 0)

	attackText := []byte(";admin=true")
	attackMessage := append(message, append(gluePadding, attackText...)...)
	h0 := binary.BigEndian.Uint32(originalSignature[0:4])
	h1 := binary.BigEndian.Uint32(originalSignature[4:8])
	h2 := binary.BigEndian.Uint32(originalSignature[8:12])
	h3 := binary.BigEndian.Uint32(originalSignature[12:16])
	h4 := binary.BigEndian.Uint32(originalSignature[16:20])
	attackSignature := SHA1Fixated(attackText, guessedKeyLength+len(message)+len(gluePadding), h0, h1, h2, h3, h4)

	desiredSignature := SHA1(append(key, attackMessage...))
	if !bytes.Equal(desiredSignature, attackSignature) {
		t.Errorf("Attacker failed to match signatures!\nExpected: %v\n Actual: %v\n", desiredSignature, attackSignature)
	}
}
