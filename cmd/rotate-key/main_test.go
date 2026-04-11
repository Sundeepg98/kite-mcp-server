package main

import (
	"database/sql"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	_ "modernc.org/sqlite"
)

// createTestDB creates an in-memory SQLite DB with the schema used by rotate-key.
func createTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	ddl := `
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kite_tokens (
    email        TEXT PRIMARY KEY,
    access_token TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    user_name    TEXT NOT NULL,
    stored_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kite_credentials (
    email      TEXT PRIMARY KEY,
    api_key    TEXT NOT NULL,
    api_secret TEXT NOT NULL,
    stored_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    client_name   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    is_kite_key   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mcp_sessions (
    session_id      TEXT PRIMARY KEY,
    email           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    terminated      INTEGER NOT NULL DEFAULT 0,
    session_id_enc  TEXT NOT NULL DEFAULT ''
);
`
	_, err = db.Exec(ddl)
	require.NoError(t, err)
	return db
}

func TestRotateTable_EmptyTable(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)

	count, err := rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRotateTable_SingleRow(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)

	// Insert a row with a value encrypted using the old key.
	encrypted, err := alerts.Encrypt(oldKey, "my-access-token")
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"user@example.com", encrypted, "uid1", "User One", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	// Rotate.
	count, err := rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify the value is now decryptable with the new key.
	var newEncrypted string
	err = db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "user@example.com").Scan(&newEncrypted)
	require.NoError(t, err)

	decrypted := alerts.Decrypt(newKey, newEncrypted)
	assert.Equal(t, "my-access-token", decrypted)

	// Old key should no longer decrypt (returns empty on AES-GCM failure).
	decryptedOld := alerts.Decrypt(oldKey, newEncrypted)
	assert.Equal(t, "", decryptedOld)
}

func TestRotateTable_MultipleRows(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)

	// Insert two tokens.
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		enc, encErr := alerts.Encrypt(oldKey, "token-for-"+email)
		require.NoError(t, encErr)
		_, execErr := db.Exec(
			`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
			email, enc, "uid", email, "2026-01-01T00:00:00Z",
		)
		require.NoError(t, execErr)
	}

	count, err := rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Verify both rows are readable with new key.
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		var enc string
		err := db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, email).Scan(&enc)
		require.NoError(t, err)
		assert.Equal(t, "token-for-"+email, alerts.Decrypt(newKey, enc))
	}
}

func TestRotateTable_MultipleColumns(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)

	// Insert a credential with both api_key and api_secret encrypted.
	encKey, err := alerts.Encrypt(oldKey, "my-api-key")
	require.NoError(t, err)
	encSecret, err := alerts.Encrypt(oldKey, "my-api-secret")
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?, ?, ?, ?)`,
		"user@example.com", encKey, encSecret, "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	count, err := rotateTable(db, oldKey, newKey, "kite_credentials", "email", []string{"api_key", "api_secret"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify both columns.
	var newEncKey, newEncSecret string
	err = db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "user@example.com").
		Scan(&newEncKey, &newEncSecret)
	require.NoError(t, err)

	assert.Equal(t, "my-api-key", alerts.Decrypt(newKey, newEncKey))
	assert.Equal(t, "my-api-secret", alerts.Decrypt(newKey, newEncSecret))
}

func TestRotateTable_OAuthClients(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	encSecret, err := alerts.Encrypt(oldKey, "oauth-client-secret")
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at) VALUES (?, ?, ?, ?, ?)`,
		"client-1", encSecret, "http://localhost/callback", "Test Client", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	count, err := rotateTable(db, oldKey, newKey, "oauth_clients", "client_id", []string{"client_secret"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	var newEnc string
	err = db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "client-1").Scan(&newEnc)
	require.NoError(t, err)
	assert.Equal(t, "oauth-client-secret", alerts.Decrypt(newKey, newEnc))
}

func TestRotateTable_MCPSessions(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	encSID, err := alerts.Encrypt(oldKey, "encrypted-session-id")
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, session_id_enc) VALUES (?, ?, ?, ?, ?)`,
		"sess-1", "user@example.com", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", encSID,
	)
	require.NoError(t, err)

	count, err := rotateTable(db, oldKey, newKey, "mcp_sessions", "session_id", []string{"session_id_enc"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	var newEnc string
	err = db.QueryRow(`SELECT session_id_enc FROM mcp_sessions WHERE session_id = ?`, "sess-1").Scan(&newEnc)
	require.NoError(t, err)
	assert.Equal(t, "encrypted-session-id", alerts.Decrypt(newKey, newEnc))
}

func TestRotateTable_PlaintextFallback(t *testing.T) {
	// If the value was stored as plaintext (not encrypted), Decrypt falls back
	// and returns it as-is. rotateTable should still re-encrypt it.
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Store plaintext (non-hex, non-encrypted) directly in the DB.
	_, err = db.Exec(
		`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"plain@example.com", "plaintext-token", "uid", "name", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	count, err := rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// The plaintext should now be encrypted with the new key.
	var newEnc string
	err = db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "plain@example.com").Scan(&newEnc)
	require.NoError(t, err)
	assert.Equal(t, "plaintext-token", alerts.Decrypt(newKey, newEnc))
}

func TestRotateTable_WithSalt(t *testing.T) {
	// Simulate the full main() flow with HKDF salt in the config table.
	db := createTestDB(t)

	salt := []byte("test-salt-32-bytes-for-hkdf-key!")
	saltHex := hex.EncodeToString(salt)

	// Store salt in config table.
	_, err := db.Exec(`INSERT INTO config (key, value) VALUES ('hkdf_salt', ?)`, saltHex)
	require.NoError(t, err)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", salt)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", salt)
	require.NoError(t, err)

	// Encrypt with old key + salt.
	enc, err := alerts.Encrypt(oldKey, "salted-token")
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"salt@example.com", enc, "uid", "name", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	// Rotate.
	count, err := rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify with new key.
	var newEnc string
	err = db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "salt@example.com").Scan(&newEnc)
	require.NoError(t, err)
	assert.Equal(t, "salted-token", alerts.Decrypt(newKey, newEnc))
}

func TestRotateTable_AllTablesEndToEnd(t *testing.T) {
	// Simulates the full rotate-key flow across all 4 tables.
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)

	// Populate all 4 tables with encrypted data.
	encToken, _ := alerts.Encrypt(oldKey, "token-value")
	_, err = db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"user@test.com", encToken, "uid", "name", "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	encAPIKey, _ := alerts.Encrypt(oldKey, "api-key-value")
	encAPISecret, _ := alerts.Encrypt(oldKey, "api-secret-value")
	_, err = db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?, ?, ?, ?)`,
		"user@test.com", encAPIKey, encAPISecret, "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	encClientSecret, _ := alerts.Encrypt(oldKey, "client-secret-value")
	_, err = db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at) VALUES (?, ?, ?, ?, ?)`,
		"client-x", encClientSecret, "http://localhost", "Client X", "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	encSessID, _ := alerts.Encrypt(oldKey, "session-id-value")
	_, err = db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, session_id_enc) VALUES (?, ?, ?, ?, ?)`,
		"sess-x", "user@test.com", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", encSessID)
	require.NoError(t, err)

	// Rotate all tables (same order as main()).
	tables := []struct {
		table   string
		pkCol   string
		columns []string
	}{
		{"kite_tokens", "email", []string{"access_token"}},
		{"kite_credentials", "email", []string{"api_key", "api_secret"}},
		{"oauth_clients", "client_id", []string{"client_secret"}},
		{"mcp_sessions", "session_id", []string{"session_id_enc"}},
	}

	totalRotated := 0
	for _, tbl := range tables {
		count, rotErr := rotateTable(db, oldKey, newKey, tbl.table, tbl.pkCol, tbl.columns)
		require.NoError(t, rotErr)
		totalRotated += count
	}
	assert.Equal(t, 4, totalRotated)

	// Verify all values with new key.
	var val string

	db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "user@test.com").Scan(&val)
	assert.Equal(t, "token-value", alerts.Decrypt(newKey, val))

	var apiKey, apiSecret string
	db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "user@test.com").Scan(&apiKey, &apiSecret)
	assert.Equal(t, "api-key-value", alerts.Decrypt(newKey, apiKey))
	assert.Equal(t, "api-secret-value", alerts.Decrypt(newKey, apiSecret))

	db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "client-x").Scan(&val)
	assert.Equal(t, "client-secret-value", alerts.Decrypt(newKey, val))

	db.QueryRow(`SELECT session_id_enc FROM mcp_sessions WHERE session_id = ?`, "sess-x").Scan(&val)
	assert.Equal(t, "session-id-value", alerts.Decrypt(newKey, val))
}

func TestRotateTable_SameKey(t *testing.T) {
	// Rotating with the same key should be a no-op (data still readable).
	db := createTestDB(t)

	key, err := alerts.DeriveEncryptionKeyWithSalt("same-secret", nil)
	require.NoError(t, err)

	enc, err := alerts.Encrypt(key, "value")
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"same@example.com", enc, "uid", "name", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	count, err := rotateTable(db, key, key, "kite_tokens", "email", []string{"access_token"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Still readable with the same key.
	var newEnc string
	db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "same@example.com").Scan(&newEnc)
	assert.Equal(t, "value", alerts.Decrypt(key, newEnc))
}
