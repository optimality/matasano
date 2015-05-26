package challenge32

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func SHA1(message []byte) []byte {
	h0, h1, h2, h3, h4 := uint32(0x67452301), uint32(0xEFCDAB89), uint32(0x98BADCFE), uint32(0x10325476), uint32(0xC3D2E1F0)

	m1 := uint64(len(message) * 8)

	message = append(message, 0x80)
	k := 64 - (len(message)+8)%64
	message = append(message, make([]byte, k)...)
	message = append(message, make([]byte, 8)...)
	binary.BigEndian.PutUint64(message[len(message)-8:], m1)

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

func HMAC(key []byte, message []byte) []byte {
	if len(key) > 64 {
		key = SHA1(key)
	}
	if len(key) < 64 {
		key = append(key, make([]byte, 64-len(key))...)
	}
	opad := make([]byte, 64)
	ipad := make([]byte, 64)
	for i := range opad {
		opad[i] = byte(0x5c) ^ key[i]
		ipad[i] = byte(0x36) ^ key[i]
	}

	return SHA1(append(opad, SHA1(append(ipad, message...))...))
}

func InsecureCompare(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	for i := range b1 {
		time.Sleep(5 * time.Millisecond)
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func TimingAttack(oracle func(b []byte) bool) []byte {
	signature := make([]byte, 20)
	for i := range signature {
		best := byte(0)
		bestTime := 0 * time.Second
		for j := 0; j <= 255; j++ {
			signature[i] = byte(j)
			start := time.Now()
			_ = oracle(signature)
			duration := time.Since(start)
			if duration > bestTime {
				bestTime = duration
				best = byte(j)
			}
		}
		fmt.Printf("%v ", best)
		signature[i] = best
	}
	fmt.Println()
	return signature
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

func TestTimingAttack(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	filename := []byte("foo.txt")
	signature := HMAC(key, filename)
	for _, s := range signature {
		fmt.Printf("%v ", s)
	}
	fmt.Println()

	oracle := func(b []byte) bool {
		return InsecureCompare(b, signature)
	}

	recoveredSignature := TimingAttack(oracle)
	if !bytes.Equal(signature, recoveredSignature) {
		t.Errorf("Failed to recover signature.\nExpected: %v\nActual: %v\n", signature, recoveredSignature)
	}
}
