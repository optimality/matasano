package challenge2

import "fmt"

// Xor produces the xor of two byte arrays.
func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("Xor requires slices to be the same length: %v, %v", len(a), len(b))
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c, nil
}
