package alerts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCredentialCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveCredential("user@example.com", "key123", "secret456", now)
	require.NoError(t, err)

	// Load
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "user@example.com", creds[0].Email)
	assert.Equal(t, "key123", creds[0].APIKey)
	assert.Equal(t, "secret456", creds[0].APISecret)

	// Update (upsert)
	err = db.SaveCredential("user@example.com", "newkey", "newsecret", now)
	require.NoError(t, err)
	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "newkey", creds[0].APIKey)

	// Delete
	err = db.DeleteCredential("user@example.com")
	require.NoError(t, err)
	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestCredentialEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now()
	err = db.SaveCredential("enc@example.com", "mykey", "mysecret", now)
	require.NoError(t, err)

	// Verify values are encrypted in DB (raw query)
	var rawKey, rawSecret string
	row := db.db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "enc@example.com")
	require.NoError(t, row.Scan(&rawKey, &rawSecret))
	assert.NotEqual(t, "mykey", rawKey, "api_key should be encrypted in DB")
	assert.NotEqual(t, "mysecret", rawSecret, "api_secret should be encrypted in DB")

	// Load decrypts transparently
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "mykey", creds[0].APIKey)
	assert.Equal(t, "mysecret", creds[0].APISecret)
}

func TestCredentialPlaintextMigration(t *testing.T) {
	db := openTestDB(t)

	// Save without encryption (simulates pre-encryption data)
	now := time.Now()
	err := db.SaveCredential("old@example.com", "plainkey", "plainsecret", now)
	require.NoError(t, err)

	// Now enable encryption and load — plaintext values should load fine
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "plainkey", creds[0].APIKey)
	assert.Equal(t, "plainsecret", creds[0].APISecret)
}

func TestTokenCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	err := db.SaveToken("user@example.com", "token123", "uid1", "UserName", now)
	require.NoError(t, err)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "user@example.com", tokens[0].Email)
	assert.Equal(t, "token123", tokens[0].AccessToken)
	assert.Equal(t, "uid1", tokens[0].UserID)
	assert.Equal(t, "UserName", tokens[0].UserName)

	err = db.DeleteToken("user@example.com")
	require.NoError(t, err)
	tokens, err = db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestMultipleCredentials(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	db.SaveCredential("a@x.com", "k1", "s1", now)
	db.SaveCredential("b@x.com", "k2", "s2", now)
	db.SaveCredential("c@x.com", "k3", "s3", now)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	assert.Len(t, creds, 3)
}
