package challenge1

import (
	"encoding/base64"
	"encoding/hex"
)

// HexToBase64 converts a hex string to a base64 string.
func HexToBase64(h string) (string, error) {
	bytes, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(bytes)
	return b64, nil
}
