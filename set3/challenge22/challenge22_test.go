package challenge22

import (
	"testing"
	"time"
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
	y := mt.MT[mt.index]
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18

	mt.index = (mt.index + 1) % 624
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

func TestMersenneTwisterCrack(t *testing.T) {
	time.Sleep(50 * time.Second)
	seed := uint32(time.Now().Unix())
	twister := NewMersenneTwister(seed)
	time.Sleep(50 * time.Second)
	r := twister.NextInt()

	testSeed := uint32(time.Now().Unix())
	for {
		testTwister := NewMersenneTwister(testSeed)
		testR := testTwister.NextInt()
		if testR == r {
			break
		}
		testSeed--
	}
	if seed != testSeed {
		t.Errorf("Failed to get testSeed!  Expected: %v Actual: %v", seed, testSeed)
	}
}
