package alerts


import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)



// ===========================================================================
// Merged from coverage_test.go
// ===========================================================================
func TestDB_RegistryCRUD_Extended(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-1 * time.Hour)

	entry := &RegistryDBEntry{
		ID:           "reg-001",
		APIKey:       "test-api-key",
		APISecret:    "test-api-secret",
		AssignedTo:   "user@example.com",
		Label:        "Test App",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "manual",
		LastUsedAt:   &lastUsed,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Save
	err := db.SaveRegistryEntry(entry)
	require.NoError(t, err)

	// Load
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "reg-001", entries["reg-001"].ID)
	assert.Equal(t, "test-api-key", entries["reg-001"].APIKey)
	assert.Equal(t, "user@example.com", entries["reg-001"].AssignedTo)
	assert.NotNil(t, entries["reg-001"].LastUsedAt)

	// Save without LastUsedAt
	entry2 := &RegistryDBEntry{
		ID:           "reg-002",
		APIKey:       "key2",
		APISecret:    "secret2",
		AssignedTo:   "user2@example.com",
		Label:        "App 2",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "api",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	err = db.SaveRegistryEntry(entry2)
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Delete
	err = db.DeleteRegistryEntry("reg-001")
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}


// ===========================================================================
// DB — Config get/set
// ===========================================================================
func TestDB_Config(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Get nonexistent — returns error (sql.ErrNoRows)
	val, err := db.GetConfig("nonexistent")
	assert.Error(t, err)
	assert.Empty(t, val)

	// Set
	err = db.SetConfig("test_key", "test_value")
	require.NoError(t, err)

	// Get
	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Overwrite
	err = db.SetConfig("test_key", "new_value")
	require.NoError(t, err)

	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "new_value", val)
}


// ===========================================================================
// TrailingStop — CancelByEmail with DB
// ===========================================================================

// ===========================================================================
// Merged from db_coverage_test.go
// ===========================================================================


// mockBrokerData implements BrokerDataProvider for testing.
type mockBrokerData struct {
	holdings     []kiteconnect.Holding
	holdingsErr  error
	positions    kiteconnect.Positions
	positionsErr error
	margins      kiteconnect.AllMargins
	marginsErr   error
	ltp          kiteconnect.QuoteLTP
	ltpErr       error
}

func (m *mockBrokerData) GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error) {
	return m.holdings, m.holdingsErr
}
func (m *mockBrokerData) GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error) {
	return m.positions, m.positionsErr
}
func (m *mockBrokerData) GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error) {
	return m.margins, m.marginsErr
}
func (m *mockBrokerData) GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error) {
	return m.ltp, m.ltpErr
}

// ===========================================================================
// OpenDB — test with temp directory (covers file-based path)
// ===========================================================================
func TestOpenDB_TempDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := OpenDB(path)
	require.NoError(t, err)
	defer db.Close()

	// Verify file was created
	_, err = os.Stat(path)
	require.NoError(t, err)

	// Verify tables exist by doing a basic operation
	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alerts)
}


func TestOpenDB_InvalidPath(t *testing.T) {
	// Invalid path that cannot be opened
	_, err := OpenDB("/nonexistent/deeply/nested/path/that/cannot/exist/test.db")
	require.Error(t, err)
}


func TestOpenDB_Idempotent(t *testing.T) {
	// Opening the same in-memory DB path twice should work (different connections)
	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent.db")

	db1, err := OpenDB(path)
	require.NoError(t, err)
	db1.Close()

	// Open again — all migrations should be idempotent
	db2, err := OpenDB(path)
	require.NoError(t, err)
	db2.Close()
}


// ===========================================================================
// OpenDB — error paths: ping fails, DDL fails
// ===========================================================================
func TestOpenDB_PingFail(t *testing.T) {
	// Use a path whose parent directory does not exist.
	// SQLite will not create intermediate directories, so Open/Ping fails
	// on both Windows and Linux.
	badPath := filepath.Join(t.TempDir(), "no_such_subdir", "deep", "test.db")
	_, err := OpenDB(badPath)
	require.Error(t, err)
}

// TestOpenDB_ForeignKeysEnabled pins the DB1 fix: modernc.org/sqlite defaults
// `foreign_keys` to OFF on every fresh connection, which would silently
// disable any ON DELETE/RESTRICT clauses in the schema. The DSN-level
// `_pragma=foreign_keys(1)` parameter is applied per-connection by the
// driver, so the PRAGMA must report 1 from any handle the pool hands out.
func TestOpenDB_ForeignKeysEnabled(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	var fk int
	err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	require.NoError(t, err)
	assert.Equal(t, 1, fk, "foreign_keys PRAGMA must be ON for ON DELETE/RESTRICT clauses to fire")
}

// TestDSNWithFKPragma covers the helper for both bare paths (which get a
// fresh `?` query) and pre-existing URIs with query params (which need an
// `&` separator).
func TestDSNWithFKPragma(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bare path", "foo.db", "foo.db?_pragma=foreign_keys(1)"},
		{"memory", ":memory:", ":memory:?_pragma=foreign_keys(1)"},
		{"file uri no query", "file:foo.db", "file:foo.db?_pragma=foreign_keys(1)"},
		{"file uri with query", "file:foo.db?cache=shared", "file:foo.db?cache=shared&_pragma=foreign_keys(1)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dsnWithFKPragma(tc.input))
		})
	}
}
