package challenge13

import (
	"crypto/aes"
	"net/url"
	"strings"
	"testing"
)

func Pad(plaintext []byte) []byte {
	paddingLength := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	return append(plaintext, padding...)
}

func ECBEncrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	plaintext = Pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return ciphertext
}

func ECBDecrypt(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Error making AES cipher!")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}

	possiblePaddingLength := int(plaintext[len(plaintext)-1])
	for i := 1; i <= possiblePaddingLength; i++ {
		if int(plaintext[len(plaintext)-i]) != possiblePaddingLength {
			return plaintext
		}
	}
	return plaintext[:len(plaintext)-possiblePaddingLength]
}

func ProfileFor(email string) string {
	email = strings.Replace(email, "=", "", -1)
	email = strings.Replace(email, "&", "", -1)
	return "email=" + email + "&uid=10&role=user"
}

func Attack(encryptedProfileFor func(string) []byte) []byte {
	prefixLen := len("email=")
	blockBoundaryEmailAddressPrefix := ""
	for i := prefixLen; i < aes.BlockSize; i++ {
		blockBoundaryEmailAddressPrefix += "A"
	}

	blockBoundaryEmailAddressSuffix := "admin"
	paddingSize := aes.BlockSize - len(blockBoundaryEmailAddressSuffix)
	for i := 0; i < paddingSize; i++ {
		blockBoundaryEmailAddressSuffix += string(byte(paddingSize))
	}

	blocks := encryptedProfileFor(blockBoundaryEmailAddressPrefix + blockBoundaryEmailAddressSuffix)
	adminBlock := blocks[aes.BlockSize : aes.BlockSize*2]

	emailSuffix := "A@bar.com"
	attackPrefixLen := len("email=&uid=10&role=") + len(emailSuffix)
	padding := aes.BlockSize - (attackPrefixLen % aes.BlockSize)
	emailPrefix := ""
	for i := 0; i < padding; i++ {
		emailPrefix += "A"
	}

	attackPrefix := encryptedProfileFor(emailPrefix + emailSuffix)
	attack := append(attackPrefix[:len(attackPrefix)-aes.BlockSize], adminBlock...)

	return attack
}

func TestPrivilegeEscalation(t *testing.T) {
	// Test values parsing.
	values, err := url.ParseQuery(`email=foo@bar.com&uid=10&role=user`)
	if err != nil {
		t.Errorf("Failed to parse query: %v\n", err)
	}
	expected := map[string]string{
		"email": "foo@bar.com",
		"uid":   "10",
		"role":  "user",
	}
	for k, v := range expected {
		actual := values.Get(k)
		if actual != v {
			t.Errorf("Mismatch in key %v.  Expected: %v Actual: %v", k, v, actual)
		}
	}

	// Test ProfileFor
	encodedValues := ProfileFor("foo@bar.com")
	decodedValues, err := url.ParseQuery(encodedValues)
	if err != nil {
		t.Errorf("Failed to parse query: %v\n", err)
	}
	for k, v := range expected {
		actual := decodedValues.Get(k)
		if actual != v {
			t.Errorf("Mismatch in key %v.  Expected: %v Actual: %v", k, v, actual)
		}
	}

	// Test encoding/decoding.
	key := []byte("YELLOW SUBMARINE")
	ciphertext := ECBEncrypt([]byte(encodedValues), key)
	plaintext := ECBDecrypt(ciphertext, key)
	if encodedValues != string(plaintext) {
		t.Errorf("Encode/Decode failed: Expected: %v Actual: %s\n", encodedValues, plaintext)
	}

	// Attack function.
	encryptedProfileFor := func(email string) []byte {
		return ECBEncrypt([]byte(ProfileFor(email)), key)
	}

	// Test attack function.
	encryptedProfile := encryptedProfileFor("foo@bar.com")
	if string(encryptedProfile) != string(ciphertext) {
		t.Errorf("Failure in encrypting profile.  Expected: %v Actual: %v\n", encryptedProfile, ciphertext)
	}

	// Attack!
	attack := Attack(encryptedProfileFor)

	decrypted := ECBDecrypt(attack, key)
	attackValues, err := url.ParseQuery(string(decrypted))
	if err != nil {
		t.Errorf("Failed to parse query: %v", err)
	}

	if attackValues.Get("role") != "admin" {
		t.Errorf("Attack failed: %v\n", attackValues)
	}
}
