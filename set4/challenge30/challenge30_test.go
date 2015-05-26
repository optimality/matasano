package challenge30

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func MD4(input []byte) []byte {
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	return MD4Fixated(input, 0, h0, h1, h2, h3)
}

func MakePadding(ml int, prefixLength int) []byte {
	padding := make([]byte, 64-(ml+9)%64+9)
	padding[0] = 0x80
	for i := 1; i < len(padding)-8; i++ {
		padding[i] = 0
	}
	ml = (ml + prefixLength) << 3
	for i := 0; i < 8; i++ {
		padding[len(padding)-8+i] = byte(ml >> uint32(i*8))
	}
	return padding
}

func MD4Fixated(message []byte, prefixLength int, h0, h1, h2, h3 uint32) []byte {
	padding := MakePadding(len(message), prefixLength)
	message = append(message, padding...)
	a := h0
	b := h1
	c := h2
	d := h3
	for o := 0; o < len(message); o += 64 {
		chunk := message[o : o+64]
		x := make([]uint32, 16)
		for i := range x {
			x[i] = pack(chunk[i*4 : i*4+4])
		}

		aa := a
		bb := b
		cc := c
		dd := d

		// Round 1.
		for i := 0; i < 4; i++ {
			a = rotateLeft(a+F(b, c, d)+x[0+i*4], 3)
			d = rotateLeft(d+F(a, b, c)+x[1+i*4], 7)
			c = rotateLeft(c+F(d, a, b)+x[2+i*4], 11)
			b = rotateLeft(b+F(c, d, a)+x[3+i*4], 19)
		}

		// Round 2.
		for i := 0; i < 4; i++ {
			a = rotateLeft(a+G(b, c, d)+x[0+i]+0x5A827999, 3)
			d = rotateLeft(d+G(a, b, c)+x[4+i]+0x5A827999, 5)
			c = rotateLeft(c+G(d, a, b)+x[8+i]+0x5A827999, 9)
			b = rotateLeft(b+G(c, d, a)+x[12+i]+0x5A827999, 13)
		}

		// Round 3.
		roundIs := []int{0, 2, 1, 3}
		for _, i := range roundIs {
			a = rotateLeft(a+H(b, c, d)+x[0+i]+0x6ED9EBA1, 3)
			d = rotateLeft(d+H(a, b, c)+x[8+i]+0x6ED9EBA1, 9)
			c = rotateLeft(c+H(d, a, b)+x[4+i]+0x6ED9EBA1, 11)
			b = rotateLeft(b+H(c, d, a)+x[12+i]+0x6ED9EBA1, 15)
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}
	hash := make([]byte, 16)
	unpack(a, hash[0:4])
	unpack(b, hash[4:8])
	unpack(c, hash[8:12])
	unpack(d, hash[12:16])

	return hash
}

func unpack(x uint32, b []byte) {
	b[0] = byte(x)
	b[1] = byte(x >> 8)
	b[2] = byte(x >> 16)
	b[3] = byte(x >> 24)
}

func pack(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func F(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func G(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func H(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func rotateLeft(x uint32, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}

func TestMD4(t *testing.T) {
	testPairs := map[string]string{
		"a":                                                                                "bde52cb31de33e46245e05fbdbd6fb24",
		"abc":                                                                              "a448017aaf21d8525fc10ae87aa6729d",
		"message digest":                                                                   "d9130a8164549fe818874806e1c7014b",
		"abcdefghijklmnopqrstuvwxyz":                                                       "d79e1c308aa5bbcdeea8ed63df412da9",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":                   "043f8582f241db351ce627e153e7f0e4",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
	}
	for input, expected := range testPairs {
		actual := hex.EncodeToString(MD4([]byte(input)))
		if expected != actual {
			t.Errorf("Unexpected output in MD4.  Expected: %v Actual: %v", expected, actual)
		}
	}
}

func TestLengthExtension(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	originalSignature := MD4(append(key, message...))

	guessedKeyLength := len(key) // challenge doesn't say how to guess this, assuming we're not supposed to.
	messageLength := len(message)
	gluePadding := MakePadding(guessedKeyLength+messageLength, 0)

	attackText := []byte(";admin=true")
	attackMessage := append(message, append(gluePadding, attackText...)...)
	h0 := pack(originalSignature[0:4])
	h1 := pack(originalSignature[4:8])
	h2 := pack(originalSignature[8:12])
	h3 := pack(originalSignature[12:16])
	attackSignature := MD4Fixated(attackText, guessedKeyLength+len(message)+len(gluePadding), h0, h1, h2, h3)

	desiredSignature := MD4(append(key, attackMessage...))
	if !bytes.Equal(desiredSignature, attackSignature) {
		t.Errorf("Attacker failed to match signatures!\nExpected: %v\n Actual: %v\n", desiredSignature, attackSignature)
	}
}
