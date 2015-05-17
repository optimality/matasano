package challenge8

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"os"
	"testing"
)

func checkForRepeats(ciphertext []byte) bool {
	for i := 0; i < len(ciphertext); i += 16 {
		for j := i + 16; j < len(ciphertext); j += 16 {
			if bytes.Equal(ciphertext[i:i+16], ciphertext[j:j+16]) {
				return true
			}
		}
	}
	return false
}

func TestAES(t *testing.T) {
	file, err := os.Open("ciphertext.txt")
	if err != nil {
		t.Errorf("Error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ciphertext, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			t.Errorf("Failed to decode string: %v", err)
		}
		if checkForRepeats(ciphertext) {
			t.Logf("Duplicated blocks present in: %v\n", base64.StdEncoding.EncodeToString(ciphertext))
		}
	}
}
