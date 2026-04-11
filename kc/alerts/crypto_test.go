package alerts

import (
	"testing"
	"time"

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

	// Decrypt with wrong key returns empty string (don't leak ciphertext)
	result := decrypt(key2, ciphertext)
	assert.Equal(t, "", result)
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

func TestDeriveEncryptionKeyWithSalt(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")

	key, err := DeriveEncryptionKeyWithSalt("test-secret", salt)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// Same secret+salt produces same key
	key2, err := DeriveEncryptionKeyWithSalt("test-secret", salt)
	require.NoError(t, err)
	assert.Equal(t, key, key2)

	// Different salt produces different key
	key3, err := DeriveEncryptionKeyWithSalt("test-secret", []byte("different-salt-value-1234567890!"))
	require.NoError(t, err)
	assert.NotEqual(t, key, key3)

	// Nil salt matches legacy DeriveEncryptionKey
	keyNilSalt, err := DeriveEncryptionKeyWithSalt("test-secret", nil)
	require.NoError(t, err)
	keyLegacy, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	assert.Equal(t, keyLegacy, keyNilSalt)

	// Non-nil salt differs from nil salt
	assert.NotEqual(t, keyNilSalt, key)
}

func TestDeriveEncryptionKeyWithSaltEmpty(t *testing.T) {
	_, err := DeriveEncryptionKeyWithSalt("", []byte("salt"))
	assert.Error(t, err)
}

func TestEnsureEncryptionSalt(t *testing.T) {
	db := openTestDB(t)

	// First call: generates salt, returns salted key
	key1, err := EnsureEncryptionSalt(db, "test-secret")
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	// Salt was stored in config
	saltHex, err := db.GetConfig(hkdfSaltConfigKey)
	require.NoError(t, err)
	assert.Len(t, saltHex, 64) // 32 bytes hex-encoded

	// Second call: loads existing salt, returns same key
	key2, err := EnsureEncryptionSalt(db, "test-secret")
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// Key differs from nil-salt legacy key
	legacyKey, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	assert.NotEqual(t, legacyKey, key1)
}

func TestEnsureEncryptionSaltMigration(t *testing.T) {
	db := openTestDB(t)

	// Pre-populate with data encrypted using legacy nil-salt key
	legacyKey, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(legacyKey)

	now := time.Now().Truncate(time.Second)
	err = db.SaveCredential("user@example.com", "my-api-key", "my-api-secret", "app1", now)
	require.NoError(t, err)
	err = db.SaveToken("user@example.com", "my-access-token", "uid", "uname", now)
	require.NoError(t, err)

	// Run EnsureEncryptionSalt — should migrate data
	newKey, err := EnsureEncryptionSalt(db, "test-secret")
	require.NoError(t, err)

	// Switch to the new key and verify data is still readable
	db.SetEncryptionKey(newKey)
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "my-api-key", creds[0].APIKey)
	assert.Equal(t, "my-api-secret", creds[0].APISecret)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "my-access-token", tokens[0].AccessToken)

	// Verify old key can no longer decrypt
	db.SetEncryptionKey(legacyKey)
	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	// With wrong key, AES-GCM decrypt returns empty string
	assert.Equal(t, "", creds[0].APIKey)
}

func TestEnsureEncryptionSaltEmptySecret(t *testing.T) {
	db := openTestDB(t)
	_, err := EnsureEncryptionSalt(db, "")
	assert.Error(t, err)
}

// encrypt/decrypt edge cases for coverage.

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	// AES requires 16, 24, or 32 byte keys. A 5-byte key triggers aes.NewCipher error.
	_, err := encrypt([]byte("short"), "plaintext")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aes cipher")
}

func TestDecrypt_InvalidKeyLength(t *testing.T) {
	// Valid hex but wrong-length AES key.
	result := decrypt([]byte("short"), "4142434445464748") // valid hex
	// Returns hex-as-is since aes.NewCipher fails (plaintext fallback).
	assert.Equal(t, "4142434445464748", result)
}

func TestDecrypt_TooShortData(t *testing.T) {
	key, _ := DeriveEncryptionKey("s")
	// Valid hex that decodes to less than nonce-size bytes (12 for AES-256-GCM).
	result := decrypt(key, "aabb")
	assert.Equal(t, "aabb", result) // Falls back to returning hex string
}

func TestEncrypt_NilKey(t *testing.T) {
	_, err := encrypt(nil, "plaintext")
	require.Error(t, err)
}

func TestEnsureEncryptionSalt_CorruptSaltInDB(t *testing.T) {
	db := openTestDB(t)
	// Store invalid hex as salt.
	require.NoError(t, db.SetConfig(hkdfSaltConfigKey, "not-valid-hex!!!"))

	_, err := EnsureEncryptionSalt(db, "test-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode stored salt")
}

func TestReEncryptTable_EmptyValues(t *testing.T) {
	db := openTestDB(t)
	key1, _ := DeriveEncryptionKey("old")
	key2, _ := DeriveEncryptionKey("new")

	// Insert a credential with empty api_secret to hit the empty-value branch.
	_, err := db.db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?, '', '', ?)`,
		"empty@test.com", time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// reEncryptTable should skip empty values without error.
	err = reEncryptTable(db, key1, key2, "kite_credentials", "email", []string{"api_key", "api_secret"})
	require.NoError(t, err)
}
