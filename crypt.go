package cryptem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
)

const (
	nonceSize int = 12
	keyLength int = 16
)

func EncryptFile(key []byte, clearFilePath, encryptedFilePath string) error {
	clearData, err := os.ReadFile(clearFilePath)
	if err != nil {
		return fmt.Errorf("error while reading file '%s': %w", clearFilePath, err)
	}
	cryptData, err := Encrypt(key, clearData)
	if err != nil {
		return fmt.Errorf("error while encrypting file '%s': %w", clearFilePath, err)
	}
	err = os.WriteFile(encryptedFilePath, cryptData, 0600)
	if err != nil {
		return fmt.Errorf("error while writing encrypted file '%s': %w", encryptedFilePath, err)
	}
	return nil
}

func DecryptFile(key []byte, encryptedFilePath, clearFilePath string) error {
	cryptData, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("error while reading encrypted file '%s': %w", encryptedFilePath, err)
	}
	clearData, err := Decrypt(key, cryptData)
	if err != nil {
		return fmt.Errorf("error while decrypting file '%s': %w", clearFilePath, err)
	}
	err = os.WriteFile(clearFilePath, clearData, 0600)
	if err != nil {
		return fmt.Errorf("error while writing file '%s': %w", clearFilePath, err)
	}
	return nil
}

// Encrypt a text with a key
func Encrypt(key, data []byte) ([]byte, error) {
	if len(key) != keyLength {
		return nil, fmt.Errorf("unexpected key length: %d must be %d", len(key), keyLength)
	}
	// Generate a 96-bit nonce using a CSPRNG.
	nonce := make([]byte, nonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	enc := c.Seal(nil, nonce, data, nil)
	encrypted := make([]byte, 0, len(enc)+nonceSize)
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, enc...)
	return encrypted, nil
}

// Decrypt an encoded text with a key
func Decrypt(key, encoded []byte) ([]byte, error) {
	if len(key) != keyLength {
		return nil, fmt.Errorf("unexpected key length: %d must be %d", len(key), keyLength)
	}
	// Create slices pointing to the ciphertext and nonce.
	if len(encoded) < nonceSize {
		return nil, fmt.Errorf("encrypted data shorter than nonce")
	}
	nonce := encoded[:nonceSize]
	enc := encoded[nonceSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Decrypt and return result.
	text, err := c.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, err
	}
	return text, nil
}
