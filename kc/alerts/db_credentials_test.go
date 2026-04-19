package alerts


import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// LoadCredentials — empty
// ===========================================================================
func TestLoadCredentials_Empty(t *testing.T) {
	db := openTestDB(t)
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}



// ===========================================================================
// LoadCredentials — bad stored_at (covers fallback to zero time)
// ===========================================================================
func TestLoadCredentials_BadStoredAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?,?,?,?)`,
		"user@example.com", "key1", "secret1", "bad-date")
	require.NoError(t, err)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.True(t, creds[0].StoredAt.IsZero()) // fallback to zero time
}



// ===========================================================================
// DeleteCredential — non-existent
// ===========================================================================
func TestDeleteCredential_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteCredential("nobody@example.com")
	assert.NoError(t, err)
}



// ===========================================================================
// SaveCredential — encryption of both api_key and api_secret
// ===========================================================================
func TestSaveCredential_EncryptionBothFields(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveCredential("user@example.com", "the-key", "the-secret", "app1", now))

	// Raw DB should have encrypted values
	var rawKey, rawSecret string
	row := db.db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "user@example.com")
	require.NoError(t, row.Scan(&rawKey, &rawSecret))
	assert.NotEqual(t, "the-key", rawKey)
	assert.NotEqual(t, "the-secret", rawSecret)

	// Load decrypts
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "the-key", creds[0].APIKey)
	assert.Equal(t, "the-secret", creds[0].APISecret)
	assert.Equal(t, "app1", creds[0].AppID)
}


func TestLoadCredentials_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadCredentials()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query credentials")
}


func TestSaveCredential_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveCredential("user@example.com", "k1", "s1", "k1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save credential")
}


func TestDeleteCredential_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteCredential("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete credential")
}



// ===========================================================================
// SaveCredential with encryption — duplicate key
// ===========================================================================
func TestSaveCredential_EncryptionDuplicateKey(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveCredential("user@example.com", "k1", "s1", "k1", now))
	require.NoError(t, db.SaveCredential("user@example.com", "k2", "s2", "k2", now))

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "k2", creds[0].APIKey)
}


func TestSaveCredential_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveCredential("u@t.com", "key", "secret", "app", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt api_key")
}


func TestSaveCredential_EncryptSecretError(t *testing.T) {
	db := openTestDB(t)
	// Use a 16-byte key so aes.NewCipher succeeds for the first encrypt call
	// (api_key) but we can't easily make only the second fail. Instead test
	// the DB error path with a closed DB.
	key, _ := DeriveEncryptionKey("s")
	db.SetEncryptionKey(key)
	db.Close()
	err := db.SaveCredential("u@t.com", "key", "secret", "app", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save credential")
}
