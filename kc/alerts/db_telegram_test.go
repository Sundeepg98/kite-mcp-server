package alerts


import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// DeleteTelegramChatID — non-existent
// ===========================================================================
func TestDeleteTelegramChatID_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.DeleteTelegramChatID("nobody@example.com")
	assert.NoError(t, err)
}



// ===========================================================================
// LoadTelegramChatIDs — empty
// ===========================================================================
func TestLoadTelegramChatIDs_Empty(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Empty(t, ids)
}



// ===========================================================================
// SaveTelegramChatID — duplicate key (upsert)
// ===========================================================================
func TestSaveTelegramChatID_DuplicateKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 111))
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 222))

	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(222), ids["user@example.com"])
}


func TestDeleteTelegramChatID_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.DeleteTelegramChatID("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete telegram chat id")
}


func TestLoadTelegramChatIDs_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	_, err := db.LoadTelegramChatIDs()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query telegram chat ids")
}


func TestSaveTelegramChatID_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.SaveTelegramChatID("user@example.com", 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save telegram chat id")
}


func TestLoadTelegramChatIDs_ClosedDB_ErrorPath(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.Close()
	_, err := db.LoadTelegramChatIDs()
	require.Error(t, err)
}
