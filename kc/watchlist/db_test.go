package watchlist

import (
	"database/sql"
	"log/slog"
	"os"
	"testing"

	_ "modernc.org/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDB wraps a SQLite database implementing WatchlistDB for tests.
type testDB struct {
	db *sql.DB
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return &testDB{db: db}
}

func (d *testDB) ExecDDL(ddl string) error {
	_, err := d.db.Exec(ddl)
	return err
}

func (d *testDB) ExecInsert(query string, args ...any) error {
	_, err := d.db.Exec(query, args...)
	return err
}

func (d *testDB) RawQuery(query string, args ...any) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

func (d *testDB) QueryRow(query string, args ...any) *sql.Row {
	return d.db.QueryRow(query, args...)
}

func TestInitTables(t *testing.T) {
	db := newTestDB(t)
	err := InitTables(db)
	require.NoError(t, err)

	// Verify both tables exist by listing from sqlite_master.
	rows, err := db.RawQuery("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	require.NoError(t, err)
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	assert.Contains(t, tables, "watchlists")
	assert.Contains(t, tables, "watchlist_items")
}

func TestInitTables_Idempotent(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))
	require.NoError(t, InitTables(db), "InitTables should be idempotent")
}

func TestSetDB_And_Persistence(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	// Create store with DB.
	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	// Create watchlist — should persist.
	id, err := s.CreateWatchlist("alice@example.com", "Persisted WL")
	require.NoError(t, err)

	// Add item — should persist.
	err = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		InstrumentToken: 738561,
		Notes:           "Core holding",
		TargetEntry:     2400.0,
		TargetExit:      2800.0,
	})
	require.NoError(t, err)

	// Create a NEW store and load from DB.
	s2 := NewStore()
	s2.SetDB(db)
	err = s2.LoadFromDB()
	require.NoError(t, err)

	// Verify watchlist loaded.
	wls := s2.ListWatchlists("alice@example.com")
	require.Len(t, wls, 1)
	assert.Equal(t, "Persisted WL", wls[0].Name)
	assert.Equal(t, id, wls[0].ID)

	// Verify items loaded.
	items := s2.GetItems(id)
	require.Len(t, items, 1)
	assert.Equal(t, "RELIANCE", items[0].Tradingsymbol)
	assert.Equal(t, "Core holding", items[0].Notes)
	assert.Equal(t, 2400.0, items[0].TargetEntry)
	assert.Equal(t, 2800.0, items[0].TargetExit)
	assert.Equal(t, uint32(738561), items[0].InstrumentToken)
}

func TestDeleteWatchlist_Persistence(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id, _ := s.CreateWatchlist("alice@example.com", "To Delete")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY",
	})

	// Delete.
	err := s.DeleteWatchlist("alice@example.com", id)
	require.NoError(t, err)

	// Verify deleted from DB by loading into new store.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	assert.Len(t, s2.ListWatchlists("alice@example.com"), 0)
	assert.Len(t, s2.GetItems(id), 0)
}

func TestRemoveItem_Persistence(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id, _ := s.CreateWatchlist("alice@example.com", "Remove Test")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
	})
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY",
	})

	items := s.GetItems(id)
	require.Len(t, items, 2)

	// Remove first item.
	err := s.RemoveItem("alice@example.com", id, items[0].ID)
	require.NoError(t, err)

	// Verify in DB.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	loadedItems := s2.GetItems(id)
	assert.Len(t, loadedItems, 1)
}

func TestLoadFromDB_NilDB(t *testing.T) {
	s := NewStore()
	err := s.LoadFromDB()
	assert.NoError(t, err, "LoadFromDB with nil DB should be a no-op")
}

func TestDeleteByEmail_Persistence(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	s.CreateWatchlist("alice@example.com", "WL1")
	s.CreateWatchlist("alice@example.com", "WL2")
	s.CreateWatchlist("bob@example.com", "Bob WL")

	s.DeleteByEmail("alice@example.com")

	// Verify alice's data gone from DB.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	assert.Len(t, s2.ListWatchlists("alice@example.com"), 0)
	assert.Len(t, s2.ListWatchlists("bob@example.com"), 1)
}

func TestTimestampUpdate_Persistence(t *testing.T) {
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id, _ := s.CreateWatchlist("alice@example.com", "TS Test")

	// Add an item (which updates the watchlist timestamp).
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
	})

	// Load from DB and verify watchlist timestamp was persisted.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	wlAfter := s2.ListWatchlists("alice@example.com")
	require.Len(t, wlAfter, 1)
	assert.False(t, wlAfter[0].UpdatedAt.IsZero(), "UpdatedAt should be set")
	assert.False(t, wlAfter[0].CreatedAt.IsZero(), "CreatedAt should be set")
}
