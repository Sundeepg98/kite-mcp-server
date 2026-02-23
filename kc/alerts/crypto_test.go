package alerts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveEncryptionKey(t *testing.T) {
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// Same secret produces same key (deterministic)
	key2, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	assert.Equal(t, key, key2)

	// Different secret produces different key
	key3, err := DeriveEncryptionKey("other-secret")
	require.NoError(t, err)
	assert.NotEqual(t, key, key3)
}

func TestDeriveEncryptionKeyEmpty(t *testing.T) {
	_, err := DeriveEncryptionKey("")
	assert.Error(t, err)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	plaintext := "my-api-secret-value"
	ciphertext, err := encrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	result := decrypt(key, ciphertext)
	assert.Equal(t, plaintext, result)
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	key, _ := DeriveEncryptionKey("test-secret")
	ct1, _ := encrypt(key, "same-value")
	ct2, _ := encrypt(key, "same-value")
	// Different nonces → different ciphertexts
	assert.NotEqual(t, ct1, ct2)
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := DeriveEncryptionKey("secret-1")
	key2, _ := DeriveEncryptionKey("secret-2")

	ciphertext, err := encrypt(key1, "sensitive-data")
	require.NoError(t, err)

	// Decrypt with wrong key falls back to returning ciphertext as-is
	result := decrypt(key2, ciphertext)
	assert.Equal(t, ciphertext, result)
}

func TestDecryptPlaintextFallback(t *testing.T) {
	key, _ := DeriveEncryptionKey("test-secret")

	// Non-hex string returns as-is (plaintext migration path)
	result := decrypt(key, "plaintext-api-key")
	assert.Equal(t, "plaintext-api-key", result)

	// Empty string returns as-is
	result = decrypt(key, "")
	assert.Equal(t, "", result)
}
