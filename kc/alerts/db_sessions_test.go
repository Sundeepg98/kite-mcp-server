package alerts


import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// LoadSessions — empty
// ===========================================================================
func TestLoadSessions_Empty(t *testing.T) {
	db := openTestDB(t)
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}



// ===========================================================================
// LoadSessions — skip stale encrypted row (bad session_id_enc)
// ===========================================================================
func TestLoadSessions_SkipCorruptEncryptedRow(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Insert a row with valid hex but bad ciphertext (decryption will fail -> decrypt returns "" -> skip)
	hashedID := db.hashSessionID("test-session")
	// This is valid hex (long enough for GCM nonce) but will fail AES-GCM authentication
	badHexCiphertext := "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee0011223344"
	_, err = db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		hashedID, "user@example.com", now.Format(time.RFC3339), expires.Format(time.RFC3339), 0, badHexCiphertext)
	require.NoError(t, err)

	// Also insert a good row
	err = db.SaveSession("good-session", "user2@example.com", now, expires, false)
	require.NoError(t, err)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	// Only the good session should be loaded (corrupt one skipped)
	require.Len(t, sessions, 1)
	assert.Equal(t, "good-session", sessions[0].SessionID)
}



// ===========================================================================
// LoadSessions — bad created_at timestamp
// ===========================================================================
func TestLoadSessions_BadCreatedAt(t *testing.T) {
	db := openTestDB(t)
	// No encryption — session_id stored as-is
	_, err := db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		"sess1", "user@example.com", "not-a-date", time.Now().Add(time.Hour).Format(time.RFC3339), 0, "")
	require.NoError(t, err)

	_, err = db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse session created_at")
}


func TestLoadSessions_BadExpiresAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		"sess2", "user@example.com", time.Now().Format(time.RFC3339), "not-a-date", 0, "")
	require.NoError(t, err)

	_, err = db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse session expires_at")
}



// ===========================================================================
// DeleteSession — non-existent
// ===========================================================================
func TestDeleteSession_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteSession("nonexistent-session")
	assert.NoError(t, err)
}



// ===========================================================================
// SaveSession — with encryption (covers encrypt path for session_id_enc)
// ===========================================================================
func TestSaveSession_WithEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)
	require.NoError(t, db.SaveSession("my-session", "user@example.com", now, expires, true))

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "my-session", sessions[0].SessionID)
	assert.True(t, sessions[0].Terminated)
}


func TestLoadSessions_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query sessions")
}


func TestSaveSession_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveSession("s1", "user@example.com", time.Now(), time.Now().Add(time.Hour), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save session")
}


func TestDeleteSession_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteSession("s1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete session")
}



// ===========================================================================
// LoadSessions — cover session with terminated=1
// ===========================================================================
func TestLoadSessions_TerminatedSession(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	require.NoError(t, db.SaveSession("s-term", "user@example.com", now, expires, true))

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].Terminated)
}


func TestSaveSession_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveSession("sid", "u@t.com", time.Now(), time.Now().Add(time.Hour), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt session_id")
}
