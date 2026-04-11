package main

import (
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
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

// ===========================================================================
// run() — integration tests for the extracted main logic
// ===========================================================================

// createOnDiskTestDB creates a SQLite DB on disk (in t.TempDir) with the
// standard schema, returning the file path.
func createOnDiskTestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

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
	db.Close()
	return dbPath
}

func TestRun_NoSalt(t *testing.T) {
	dbPath := createOnDiskTestDB(t)

	// Seed a row using old-secret derived key.
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", nil)
	require.NoError(t, err)
	enc, err := alerts.Encrypt(oldKey, "my-token")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"user@test.com", enc, "uid", "User", "2026-01-01T00:00:00Z")
	require.NoError(t, err)
	db.Close()

	// Run rotation.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old-secret", "new-secret", devNull)
	require.NoError(t, err)

	// Verify with new key.
	db2, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db2.Close()

	var newEnc string
	err = db2.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "user@test.com").Scan(&newEnc)
	require.NoError(t, err)

	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "my-token", alerts.Decrypt(newKey, newEnc))
}

func TestRun_WithSalt(t *testing.T) {
	dbPath := createOnDiskTestDB(t)

	salt := []byte("test-salt-32-bytes-for-hkdf-key!")
	saltHex := hex.EncodeToString(salt)

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	// Store salt in config.
	_, err = db.Exec(`INSERT INTO config (key, value) VALUES ('hkdf_salt', ?)`, saltHex)
	require.NoError(t, err)

	// Seed a row.
	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old-secret", salt)
	require.NoError(t, err)
	enc, err := alerts.Encrypt(oldKey, "salted-value")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?,?,?,?)`,
		"user@test.com", enc, enc, "2026-01-01T00:00:00Z")
	require.NoError(t, err)
	db.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old-secret", "new-secret", devNull)
	require.NoError(t, err)

	// Verify.
	db2, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db2.Close()

	var apiKey, apiSecret string
	err = db2.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "user@test.com").
		Scan(&apiKey, &apiSecret)
	require.NoError(t, err)

	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new-secret", salt)
	require.NoError(t, err)
	assert.Equal(t, "salted-value", alerts.Decrypt(newKey, apiKey))
	assert.Equal(t, "salted-value", alerts.Decrypt(newKey, apiSecret))
}

func TestRun_InvalidDBPath(t *testing.T) {
	// sql.Open succeeds lazily; the error surfaces at query time as a logged
	// warning per table. run() itself doesn't return an error in that case
	// (matching main()'s original behavior of log.Printf per table).
	badPath := filepath.Join(t.TempDir(), "nonexistent", "deep", "test.db")
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	// Should not panic; errors are logged per-table.
	err = run(badPath, "old", "new", devNull)
	require.NoError(t, err)
}

func TestRun_BadSaltHex(t *testing.T) {
	dbPath := createOnDiskTestDB(t)

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	// Store invalid hex in salt.
	_, err = db.Exec(`INSERT INTO config (key, value) VALUES ('hkdf_salt', 'not-valid-hex!!!')`)
	require.NoError(t, err)
	db.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old", "new", devNull)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode stored salt")
}

func TestRun_EmptyTables(t *testing.T) {
	dbPath := createOnDiskTestDB(t)

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old", "new", devNull)
	require.NoError(t, err)
}

// ===========================================================================
// Error paths for 100% coverage
// ===========================================================================

// --- run() error paths: derive key failures ---

func TestRun_EmptyOldSecret(t *testing.T) {
	dbPath := createOnDiskTestDB(t)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "", "new-secret", devNull)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "derive old key")
}

func TestRun_EmptyNewSecret(t *testing.T) {
	dbPath := createOnDiskTestDB(t)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old-secret", "", devNull)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "derive new key")
}

// --- rotateTable error paths ---

func TestRotateTable_QueryError_BadTable(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Query a non-existent table to trigger the query error path.
	_, err = rotateTable(db, oldKey, newKey, "nonexistent_table", "pk", []string{"col1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query nonexistent_table")
}

func TestRotateTable_ClosedDB(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Close DB to trigger query error.
	db.Close()

	_, err = rotateTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	require.Error(t, err)
}

func TestRotateTable_ScanError_ColumnMismatch(t *testing.T) {
	// Create a table with fewer columns than rotateTable expects to scan.
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Create a minimal table with only a PK column (no data columns).
	_, err = db.Exec(`CREATE TABLE scan_test (pk TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO scan_test (pk) VALUES ('row1')`)
	require.NoError(t, err)

	// rotateTable will SELECT pk, col1, col2 but the table only has pk.
	// This triggers a scan error because the query fails (col1 doesn't exist).
	_, err = rotateTable(db, oldKey, newKey, "scan_test", "pk", []string{"col1", "col2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query scan_test")
}

// TestRotateTable_EncryptError triggers the encrypt failure path by passing
// a newKey with an invalid AES key length (not 16, 24, or 32 bytes).
func TestRotateTable_EncryptError(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)

	// Insert a row encrypted with the valid old key.
	enc, err := alerts.Encrypt(oldKey, "value")
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?, ?, ?, ?, ?)`,
		"user@enc.com", enc, "uid", "name", "2026-01-01T00:00:00Z",
	)
	require.NoError(t, err)

	// Use an invalid newKey (17 bytes — not a valid AES key length).
	badNewKey := []byte("17-bytes-bad-key!")
	require.Equal(t, 17, len(badNewKey))

	_, err = rotateTable(db, oldKey, badNewKey, "kite_tokens", "email", []string{"access_token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}

// TestRotateTable_UpdateError triggers the update error path by dropping the
// table after the SELECT has collected rows but before UPDATE runs. We achieve
// this by using a second connection to drop the table between calls by wrapping
// rotateTable with a table that has a trigger that fails on UPDATE.
func TestRotateTable_UpdateError(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Create a custom table with a CHECK constraint that will fail on UPDATE.
	// We insert data that satisfies the constraint, then try to UPDATE with
	// encrypted data that violates it.
	_, err = db.Exec(`CREATE TABLE update_fail (
		pk TEXT PRIMARY KEY,
		secret TEXT NOT NULL CHECK(length(secret) < 10)
	)`)
	require.NoError(t, err)
	// Insert a short value (satisfies CHECK).
	_, err = db.Exec(`INSERT INTO update_fail (pk, secret) VALUES ('row1', 'short')`)
	require.NoError(t, err)

	// rotateTable will: SELECT pk, secret -> decrypt "short" (plaintext fallback) ->
	// re-encrypt with newKey -> UPDATE with long hex string -> CHECK constraint fails.
	_, err = rotateTable(db, oldKey, newKey, "update_fail", "pk", []string{"secret"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update update_fail")
}

// TestRotateTable_RowsErrPath triggers the rows.Err() error path.
// This is difficult with SQLite in-memory, but we can trigger a scan error
// by having the table return rows that can't be scanned into strings.
// We use a table with a BLOB column containing invalid data for string scanning.
func TestRotateTable_ScanError_NullColumn(t *testing.T) {
	db := createTestDB(t)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Create table with nullable column, insert NULL.
	// Scanning NULL into *string will fail with modernc/sqlite.
	_, err = db.Exec(`CREATE TABLE null_test (pk TEXT PRIMARY KEY, col1 TEXT)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO null_test (pk, col1) VALUES ('row1', NULL)`)
	require.NoError(t, err)

	_, err = rotateTable(db, oldKey, newKey, "null_test", "pk", []string{"col1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan null_test")
}

// TestMain_MissingFlags tests the main() function with missing flags
// using os/exec to verify it exits with code 1.
func TestMain_MissingFlags(t *testing.T) {
	if os.Getenv("BE_MAIN_MISSING_FLAGS") == "1" {
		os.Args = []string{"rotate-key"}
		main()
		return
	}

	// Re-exec the test binary with the sentinel env var set.
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_MissingFlags")
	cmd.Env = append(os.Environ(), "BE_MAIN_MISSING_FLAGS=1")
	err := cmd.Run()
	require.Error(t, err)

	// Verify it exited with code 1.
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

// TestMain_RunError tests the main() function with a bad DB path
// to trigger the log.Fatal path.
func TestMain_RunError(t *testing.T) {
	if os.Getenv("BE_MAIN_RUN_ERROR") == "1" {
		dbPath := os.Getenv("TEST_DB_PATH")
		os.Args = []string{"rotate-key", "-db", dbPath, "-old-secret", "old", "-new-secret", "new"}
		main()
		return
	}

	// Create a DB with a bad salt in the parent process.
	dbPath := filepath.Join(t.TempDir(), "bad.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO config (key, value) VALUES ('hkdf_salt', 'not-valid-hex!!!')`)
	require.NoError(t, err)
	db.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_RunError")
	cmd.Env = append(os.Environ(), "BE_MAIN_RUN_ERROR=1", "TEST_DB_PATH="+dbPath)
	err = cmd.Run()
	require.Error(t, err)

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.NotEqual(t, 0, exitErr.ExitCode())
}

// TestMain_Success tests the main() function with valid args
// to verify it exits with code 0.
func TestMain_Success(t *testing.T) {
	if os.Getenv("BE_MAIN_SUCCESS") == "1" {
		dbPath := os.Getenv("TEST_DB_PATH")
		os.Args = []string{"rotate-key", "-db", dbPath, "-old-secret", "old", "-new-secret", "new"}
		main()
		return
	}

	// Create the DB in the parent process and pass the path via env.
	dbPath := filepath.Join(t.TempDir(), "success.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	ddl := `
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kite_tokens (email TEXT PRIMARY KEY, access_token TEXT NOT NULL, user_id TEXT NOT NULL, user_name TEXT NOT NULL, stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kite_credentials (email TEXT PRIMARY KEY, api_key TEXT NOT NULL, api_secret TEXT NOT NULL, stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, client_secret TEXT NOT NULL, redirect_uris TEXT NOT NULL, client_name TEXT NOT NULL, created_at TEXT NOT NULL, is_kite_key INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mcp_sessions (session_id TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT NOT NULL, terminated INTEGER NOT NULL DEFAULT 0, session_id_enc TEXT NOT NULL DEFAULT '');
`
	_, err = db.Exec(ddl)
	require.NoError(t, err)
	db.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Success")
	cmd.Env = append(os.Environ(), "BE_MAIN_SUCCESS=1", "TEST_DB_PATH="+dbPath)
	err = cmd.Run()
	// main() returns normally on success, test binary exits 0.
	require.NoError(t, err)
}

func TestRun_AllTables(t *testing.T) {
	dbPath := createOnDiskTestDB(t)

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	oldKey, err := alerts.DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)

	// Populate all 4 tables.
	e1, _ := alerts.Encrypt(oldKey, "tok")
	_, err = db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"u@t.com", e1, "uid", "n", "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	e2, _ := alerts.Encrypt(oldKey, "key")
	e3, _ := alerts.Encrypt(oldKey, "secret")
	_, err = db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?,?,?,?)`,
		"u@t.com", e2, e3, "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	e4, _ := alerts.Encrypt(oldKey, "csec")
	_, err = db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at) VALUES (?,?,?,?,?)`,
		"c1", e4, "http://localhost", "C1", "2026-01-01T00:00:00Z")
	require.NoError(t, err)

	e5, _ := alerts.Encrypt(oldKey, "sid")
	_, err = db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, session_id_enc) VALUES (?,?,?,?,?)`,
		"s1", "u@t.com", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", e5)
	require.NoError(t, err)
	db.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer devNull.Close()

	err = run(dbPath, "old", "new", devNull)
	require.NoError(t, err)

	// Verify with new key.
	db2, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db2.Close()

	newKey, err := alerts.DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	var v string
	db2.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "u@t.com").Scan(&v)
	assert.Equal(t, "tok", alerts.Decrypt(newKey, v))

	var k, s string
	db2.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "u@t.com").Scan(&k, &s)
	assert.Equal(t, "key", alerts.Decrypt(newKey, k))
	assert.Equal(t, "secret", alerts.Decrypt(newKey, s))

	db2.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "c1").Scan(&v)
	assert.Equal(t, "csec", alerts.Decrypt(newKey, v))

	db2.QueryRow(`SELECT session_id_enc FROM mcp_sessions WHERE session_id = ?`, "s1").Scan(&v)
	assert.Equal(t, "sid", alerts.Decrypt(newKey, v))
}
