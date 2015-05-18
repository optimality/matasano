package challenge21

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
	y := mt.MT[mt.index]
	y = y ^ (y >> 11)
	y = y ^ ((y << 7) & 2636928640)
	y = y ^ ((y << 15) & 4022730752)
	y = y ^ (y >> 18)

	mt.index = (mt.index + 1) % 624
	return y
}

func (mt *MersenneTwister) GenerateNumbers() {
	for i := 0; i < 623; i++ {
		y := mt.MT[i]&0x80000000 + mt.MT[(i+1)%624]&0x7fffffff
		mt.MT[i] = mt.MT[(i+397)%624] ^ (y >> 1)
		if y%2 != 0 {
			mt.MT[i] = mt.MT[i] ^ 2567483615
		}
	}
}

func TestMersenneTwister(t *testing.T) {
	twister := NewMersenneTwister(0)
	for i := 0; i < 100; i++ {
		t.Log(twister.NextInt())
	}
}
