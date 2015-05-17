package challenge5

// RepeatedKeyXOR encrypts a plaintext by xoring with a given key, repeating it.
func RepeatedKeyXOR(plaintext, key []byte) []byte {
	cyphertext := make([]byte, len(plaintext))
	for i, p := range plaintext {
		keyIndex := i % len(key)
		cyphertext[i] = p ^ key[keyIndex]
	}
	return cyphertext
}
