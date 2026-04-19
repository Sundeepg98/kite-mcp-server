package alerts


import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// LoadTokens — empty
// ===========================================================================
func TestLoadTokens_Empty(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}



// ===========================================================================
// LoadTokens — bad stored_at (covers fallback to zero time)
// ===========================================================================
func TestLoadTokens_BadStoredAt(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"user@example.com", "tok1", "uid1", "User1", "bad-date")
	require.NoError(t, err)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.True(t, tokens[0].StoredAt.IsZero()) // fallback to zero time
}



// ===========================================================================
// SaveToken — duplicate key (upsert)
// ===========================================================================
func TestSaveToken_DuplicateKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	require.NoError(t, db.SaveToken("user@example.com", "token1", "uid1", "User1", now))
	require.NoError(t, db.SaveToken("user@example.com", "token2", "uid1", "User1", now))

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "token2", tokens[0].AccessToken)
}



// ===========================================================================
// DeleteToken — non-existent
// ===========================================================================
func TestDeleteToken_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.DeleteToken("nobody@example.com")
	assert.NoError(t, err)
}



// ===========================================================================
// SaveToken — with encryption
// ===========================================================================
func TestSaveToken_WithEncryption(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveToken("user@example.com", "my-token", "uid1", "User1", now))

	// Verify token is encrypted in raw DB
	var rawToken string
	row := db.db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "user@example.com")
	require.NoError(t, row.Scan(&rawToken))
	assert.NotEqual(t, "my-token", rawToken)

	// Load decrypts
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "my-token", tokens[0].AccessToken)
}


func TestLoadTokens_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	_, err := db.LoadTokens()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query tokens")
}


func TestSaveToken_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.SaveToken("user@example.com", "tok1", "uid1", "User1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save token")
}


func TestDeleteToken_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.DeleteToken("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete token")
}



// ===========================================================================
// SaveToken with encryption — covers encryption error path
// We can't easily force encrypt to fail, but covering the normal enc path helps
// ===========================================================================
func TestSaveToken_EncryptionDuplicateKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveToken("user@example.com", "tok1", "uid1", "User1", now))
	// Upsert with encryption
	require.NoError(t, db.SaveToken("user@example.com", "tok2", "uid1", "User1", now))

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "tok2", tokens[0].AccessToken)
}



// ===========================================================================
// Encryption-error paths in Save* functions (invalid key length).
// ===========================================================================
func TestSaveToken_EncryptError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad")) // invalid AES key length
	err := db.SaveToken("u@t.com", "tok", "uid", "name", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt access_token")
}
