package challenge24

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type MersenneTwister struct {
	MT    [624]uint32
	index uint32
}

func NewMersenneTwister(seed uint32) MersenneTwister {
	mt := MersenneTwister{}
	mt.index = 0
	mt.MT[0] = seed
	for i := uint32(1); i < 624; i++ {
		mt.MT[i] = 1812433253 * (mt.MT[i-1] ^ (mt.MT[i-1] >> 30) + i)
	}
	return mt
}

func (mt *MersenneTwister) NextInt() uint32 {
	if mt.index == 0 {
		mt.GenerateNumbers()
	}
	y := Temper(mt.MT[mt.index])

	mt.index = (mt.index + 1) % 624
	return y
}

func Temper(y uint32) uint32 {
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

func (mt *MersenneTwister) GenerateNumbers() {
	for i := 0; i < 624; i++ {
		y := mt.MT[i]&0x80000000 + mt.MT[(i+1)%624]&0x7fffffff
		mt.MT[i] = mt.MT[(i+397)%624] ^ (y >> 1)
		if y%2 != 0 {
			mt.MT[i] ^= 0x9908b0df
		}
	}
}

func CTRMT(plaintext []byte, key []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	seed := uint32(binary.LittleEndian.Uint16(key))
	mt := NewMersenneTwister(seed)
	keystream := make([]byte, 4)
	for i, p := range plaintext {
		if i%4 == 0 {
			binary.LittleEndian.PutUint32(keystream, mt.NextInt())
		}
		ciphertext[i] = p ^ keystream[i%4]
	}
	return ciphertext
}

func Untemper(y uint32) uint32 {
	y ^= y >> 18
	y ^= (y << 15) & 0xefc60000

	x := y
	for i := 0; i < 5; i++ {
		x <<= 7
		x = y ^ (x & 0x9d2c5680)
	}
	y = x

	x = y >> 11
	x ^= y
	x >>= 11
	y ^= x

	return y
}

func TestBruteForceKey(t *testing.T) {
	garbage := []byte("aaaaaaaaaa")
	message := []byte("AAAAAAAAAAAAAA")
	plaintext := append(garbage, message...)
	key := []byte("xx")
	ciphertext := CTRMT(plaintext, key)

	testKey := make([]byte, 2)
	for i := uint16(0); i <= 65535; i++ {
		binary.LittleEndian.PutUint16(testKey, i)
		testCiphertext := CTRMT(ciphertext, testKey)
		if bytes.Equal(testCiphertext[len(ciphertext)-len(message):], message) {
			break
		}
	}
	recoveredPlaintext := CTRMT(ciphertext, testKey)
	if !bytes.Equal(recoveredPlaintext, plaintext) {
		t.Errorf("Failed to recover plaintext.  Expected: %s Actual: %s", plaintext, recoveredPlaintext)
	}
}
