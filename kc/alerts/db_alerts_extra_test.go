package alerts


import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)



// ===========================================================================
// UpdateTriggered — non-existent ID
// ===========================================================================
func TestUpdateTriggered_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.UpdateTriggered("nonexistent", 100.0, time.Now())
	assert.NoError(t, err)
}


func TestUpdateTriggered_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.UpdateTriggered("id1", 100.0, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update triggered")
}
