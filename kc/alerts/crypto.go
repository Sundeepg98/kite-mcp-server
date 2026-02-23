package alerts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveEncryptionKey derives a 32-byte AES-256 key from a secret using HKDF-SHA256.
// The info string provides domain separation so the same secret used for JWT signing
// produces a different key when used for credential encryption.
func DeriveEncryptionKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("empty secret")
	}
	hkdfReader := hkdf.New(sha256.New, []byte(secret), nil, []byte("kite-mcp-credential-encryption-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}

// encrypt encrypts plaintext using AES-256-GCM and returns hex-encoded ciphertext.
// Format: hex(nonce || ciphertext || tag)
func encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(sealed), nil
}

// decrypt decrypts hex-encoded AES-256-GCM ciphertext.
// Returns the plaintext string. If the value is not valid hex or fails
// decryption, returns it as-is (plaintext fallback for migration).
func decrypt(key []byte, hexCiphertext string) string {
	data, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return hexCiphertext // Not hex — treat as plaintext (pre-encryption data)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return hexCiphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return hexCiphertext
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return hexCiphertext
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "" // Decryption failed on valid hex data — don't leak ciphertext
	}
	return string(plaintext)
}
