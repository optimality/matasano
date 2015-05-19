package challenge23

import "testing"

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

func TestUntemper(t *testing.T) {
	for i := uint32(0); i < 8675309; i += 10 {
		y := Untemper(Temper(i))
		if y != i {
			t.Fatalf("Expected: %v Actual: %v\n", i, y)
		}
	}
}

func TestMersenneTwisterCrack(t *testing.T) {
	twister := NewMersenneTwister(0)
	rands := make([]uint32, 624)
	clone := MersenneTwister{}
	for i := range rands {
		rands[i] = twister.NextInt()
		clone.MT[i] = Untemper(rands[i])
	}
	for i := 0; i < 1000; i++ {
		expected := twister.NextInt()
		actual := clone.NextInt()
		if expected != actual {
			t.Fatalf("Expected: %v Actual: %v\n", expected, actual)
		}
	}
}
