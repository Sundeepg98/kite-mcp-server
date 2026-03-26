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

func TestSessionCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Save
	err := db.SaveSession("kitemcp-abc-123", "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Load
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "kitemcp-abc-123", sessions[0].SessionID)
	assert.Equal(t, "user@example.com", sessions[0].Email)
	assert.Equal(t, now.UTC(), sessions[0].CreatedAt.UTC())
	assert.Equal(t, expires.UTC(), sessions[0].ExpiresAt.UTC())
	assert.False(t, sessions[0].Terminated)

	// Update (upsert) — mark as terminated
	err = db.SaveSession("kitemcp-abc-123", "user@example.com", now, expires, true)
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].Terminated)

	// Delete
	err = db.DeleteSession("kitemcp-abc-123")
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionEmptyEmail(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Sessions can have empty email (local dev, pre-OAuth)
	err := db.SaveSession("kitemcp-no-email", "", now, expires, false)
	require.NoError(t, err)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "", sessions[0].Email)
}

func TestMultipleSessions(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	db.SaveSession("kitemcp-s1", "a@x.com", now, expires, false)
	db.SaveSession("kitemcp-s2", "b@x.com", now, expires, false)
	db.SaveSession("kitemcp-s3", "a@x.com", now, expires, true)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	assert.Len(t, sessions, 3)
}

func TestTokenEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	err = db.SaveToken("enc@example.com", "my-access-token", "uid1", "TestUser", now)
	require.NoError(t, err)

	// Verify the raw value in SQLite is NOT plaintext
	var rawToken string
	row := db.db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "enc@example.com")
	require.NoError(t, row.Scan(&rawToken))
	assert.NotEqual(t, "my-access-token", rawToken, "access_token should be encrypted in DB")

	// Load decrypts transparently
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "my-access-token", tokens[0].AccessToken)
	assert.Equal(t, "enc@example.com", tokens[0].Email)
	assert.Equal(t, "uid1", tokens[0].UserID)
	assert.Equal(t, "TestUser", tokens[0].UserName)
}

func TestTokenEncryptionMigration(t *testing.T) {
	db := openTestDB(t)

	// Insert a plaintext token directly (simulates pre-encryption data)
	now := time.Now().Truncate(time.Second)
	_, err := db.db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"old@example.com", "plaintext-token", "uid2", "OldUser", now.Format(time.RFC3339))
	require.NoError(t, err)

	// Now enable encryption and load — plaintext should be returned as-is
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "plaintext-token", tokens[0].AccessToken)
}

func TestClientSecretEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	err = db.SaveClient("client-id-1", "super-secret", `["http://localhost"]`, "TestApp", now, false)
	require.NoError(t, err)

	// Verify the raw value in SQLite is NOT plaintext
	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "client-id-1")
	require.NoError(t, row.Scan(&rawSecret))
	assert.NotEqual(t, "super-secret", rawSecret, "client_secret should be encrypted in DB")

	// Load decrypts transparently
	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "super-secret", clients[0].ClientSecret)
	assert.Equal(t, "client-id-1", clients[0].ClientID)
	assert.Equal(t, "TestApp", clients[0].ClientName)
	assert.False(t, clients[0].IsKiteAPIKey)
}

func TestClientSecretEncryptionEmptySecret(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	// Kite API key clients may have empty secret — encryption should be skipped
	err = db.SaveClient("kite-api-key", "", `["http://localhost"]`, "KiteApp", now, true)
	require.NoError(t, err)

	// Raw value should still be empty
	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "kite-api-key")
	require.NoError(t, row.Scan(&rawSecret))
	assert.Equal(t, "", rawSecret, "empty secret should remain empty")

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "", clients[0].ClientSecret)
	assert.True(t, clients[0].IsKiteAPIKey)
}

func TestClientSecretEncryptionMigration(t *testing.T) {
	db := openTestDB(t)

	// Insert a plaintext client_secret directly (simulates pre-encryption data)
	now := time.Now().Truncate(time.Second)
	_, err := db.db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key) VALUES (?,?,?,?,?,?)`,
		"old-client", "plaintext-secret", `["http://localhost"]`, "OldApp", now.Format(time.RFC3339), 0)
	require.NoError(t, err)

	// Now enable encryption and load — plaintext should be returned as-is
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "plaintext-secret", clients[0].ClientSecret)
}
