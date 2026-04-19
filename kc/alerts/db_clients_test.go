package alerts


import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// LoadClients — empty
// ===========================================================================
func TestLoadClients_Empty(t *testing.T) {
	db := openTestDB(t)
	clients, err := db.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}



// ===========================================================================
// LoadClients — bad created_at (covers fallback to zero time)
// ===========================================================================
func TestLoadClients_BadCreatedAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key) VALUES (?,?,?,?,?,?)`,
		"c1", "secret1", `["http://localhost"]`, "App1", "bad-date", 0)
	require.NoError(t, err)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.True(t, clients[0].CreatedAt.IsZero())
}



// ===========================================================================
// SaveClient — with IsKiteAPIKey=true
// ===========================================================================
func TestSaveClient_IsKiteKey(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	err := db.SaveClient("kite-key-1", "secret", `["http://localhost"]`, "KiteApp", now, true)
	require.NoError(t, err)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.True(t, clients[0].IsKiteAPIKey)
}



// ===========================================================================
// DeleteClient — non-existent
// ===========================================================================
func TestDeleteClient_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteClient("nonexistent-client")
	assert.NoError(t, err)
}



// ===========================================================================
// SaveClient — with encryption
// ===========================================================================
func TestSaveClient_WithEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveClient("c1", "client-secret", `["http://localhost"]`, "App1", now, false))

	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "c1")
	require.NoError(t, row.Scan(&rawSecret))
	assert.NotEqual(t, "client-secret", rawSecret)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "client-secret", clients[0].ClientSecret)
}


func TestLoadClients_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadClients()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query oauth clients")
}


func TestSaveClient_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveClient("c1", "secret", `["http://localhost"]`, "App1", time.Now(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save oauth client")
}


func TestDeleteClient_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteClient("c1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete oauth client")
}



// ===========================================================================
// SaveClient with encryption — duplicate key (covers encrypt on non-empty)
// ===========================================================================
func TestSaveClient_EncryptionDuplicateKey(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveClient("c1", "s1", `["http://localhost"]`, "App1", now, false))
	require.NoError(t, db.SaveClient("c1", "s2", `["http://localhost"]`, "App1", now, false))

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "s2", clients[0].ClientSecret)
}


func TestSaveClient_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveClient("cid", "csecret", `["http://localhost"]`, "name", time.Now(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt client_secret")
}
