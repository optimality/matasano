package challenge6

import "fmt"

// HammingDistance computes the number of differing bits in the two byte slices.
func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("inputs must be the same length")
	}
	distance := 0
	for i, x := range a {
		y := b[i]
		distance += setBits(x ^ y)
	}
	return distance, nil
}

func setBits(b byte) int {
	total := 0
	for b > 0 {
		if b&1 > 0 {
			total++
		}
		b >>= 1
	}
	return total
}
