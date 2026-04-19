package watchlist

import (
	"database/sql"
	"fmt"
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
	t.Parallel()
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
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))
	require.NoError(t, InitTables(db), "InitTables should be idempotent")
}

func TestSetDB_And_Persistence(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	s := NewStore()
	err := s.LoadFromDB()
	assert.NoError(t, err, "LoadFromDB with nil DB should be a no-op")
}

func TestDeleteByEmail_Persistence(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// ---------------------------------------------------------------------------
// Additional coverage: DB error paths, loadWatchlists/loadItems edge cases,
// DeleteByEmail with DB, RemoveItem with DB.
// ---------------------------------------------------------------------------

func TestLoadFromDB_EmptyTables(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	err := s.LoadFromDB()
	require.NoError(t, err)
	assert.Len(t, s.ListWatchlists("nobody@example.com"), 0)
}

func TestLoadFromDB_MultipleWatchlistsAndItems(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id1, _ := s.CreateWatchlist("alice@example.com", "WL1")
	id2, _ := s.CreateWatchlist("alice@example.com", "WL2")

	_ = s.AddItem("alice@example.com", id1, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "RELIANCE"})
	_ = s.AddItem("alice@example.com", id1, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "INFY"})
	_ = s.AddItem("alice@example.com", id2, &WatchlistItem{Exchange: "BSE", Tradingsymbol: "TCS"})

	// Reload into fresh store.
	s2 := NewStore()
	s2.SetDB(db)
	err := s2.LoadFromDB()
	require.NoError(t, err)

	wls := s2.ListWatchlists("alice@example.com")
	assert.Len(t, wls, 2)

	items1 := s2.GetItems(id1)
	assert.Len(t, items1, 2)

	items2 := s2.GetItems(id2)
	assert.Len(t, items2, 1)
	assert.Equal(t, "TCS", items2[0].Tradingsymbol)
}

func TestDeleteByEmail_Persistence_WithItems(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id, _ := s.CreateWatchlist("alice@example.com", "With Items")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "RELIANCE"})
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "INFY"})

	s.DeleteByEmail("alice@example.com")

	// Reload and verify.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	assert.Len(t, s2.ListWatchlists("alice@example.com"), 0)
	assert.Len(t, s2.GetItems(id), 0)
}

func TestRemoveItem_Persistence_Multiple(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	id, _ := s.CreateWatchlist("alice@example.com", "Multi Remove")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "A"})
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "B"})
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{Exchange: "NSE", Tradingsymbol: "C"})

	items := s.GetItems(id)
	require.Len(t, items, 3)

	// Remove middle item.
	err := s.RemoveItem("alice@example.com", id, items[1].ID)
	require.NoError(t, err)

	// Reload and verify.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	remaining := s2.GetItems(id)
	assert.Len(t, remaining, 2)
}

func TestCreateWatchlist_PersistenceMultiple(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	_, _ = s.CreateWatchlist("alice@example.com", "WL1")
	_, _ = s.CreateWatchlist("alice@example.com", "WL2")
	_, _ = s.CreateWatchlist("bob@example.com", "BobWL")

	// Reload.
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	assert.Len(t, s2.ListWatchlists("alice@example.com"), 2)
	assert.Len(t, s2.ListWatchlists("bob@example.com"), 1)
}

func TestDeleteWatchlist_NonExistentWatchlist(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)

	err := s.DeleteWatchlist("alice@example.com", "nonexistent")
	assert.Error(t, err)
}

func TestRemoveItem_WrongWatchlist(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	err := s.RemoveItem("alice@example.com", "nonexistent", "item1")
	assert.Error(t, err)
}

func TestAddItem_WrongWatchlist_DB(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	err := s.AddItem("alice@example.com", "nonexistent", &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "TCS",
	})
	assert.Error(t, err)
}

// errDB is a WatchlistDB that returns errors on all operations.
type errDB struct {
	loadOK bool // if true, allow RawQuery to succeed
}

func (d *errDB) ExecDDL(ddl string) error                               { return fmt.Errorf("db error") }
func (d *errDB) ExecInsert(query string, args ...any) error              { return fmt.Errorf("db error") }
func (d *errDB) RawQuery(query string, args ...any) (*sql.Rows, error) {
	return nil, fmt.Errorf("db error")
}
func (d *errDB) QueryRow(query string, args ...any) *sql.Row             { return nil }

func TestLoadFromDB_WatchlistsError(t *testing.T) {
	t.Parallel()
	s := NewStore()
	s.SetDB(&errDB{})
	err := s.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load watchlists")
}

// halfErrDB allows watchlists to load but items fail.
type halfErrDB struct {
	db     *testDB
	callNo int
}

func (d *halfErrDB) ExecDDL(ddl string) error                  { return d.db.ExecDDL(ddl) }
func (d *halfErrDB) ExecInsert(query string, args ...any) error { return d.db.ExecInsert(query, args...) }
func (d *halfErrDB) RawQuery(query string, args ...any) (*sql.Rows, error) {
	d.callNo++
	if d.callNo == 1 {
		// First call (loadWatchlists) succeeds.
		return d.db.RawQuery(query, args...)
	}
	// Second call (loadItems) fails.
	return nil, fmt.Errorf("items db error")
}
func (d *halfErrDB) QueryRow(query string, args ...any) *sql.Row { return d.db.QueryRow(query, args...) }

func TestLoadFromDB_ItemsError(t *testing.T) {
	t.Parallel()
	realDB := newTestDB(t)
	require.NoError(t, InitTables(realDB))

	// Create a watchlist in the real DB.
	s := NewStore()
	s.SetDB(realDB)
	s.CreateWatchlist("alice@example.com", "Test WL")

	// Now try loading with a DB that fails on items query.
	s2 := NewStore()
	s2.SetDB(&halfErrDB{db: realDB})
	err := s2.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load watchlist items")
}

func TestDeleteWatchlist_DBErrorOnItems(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	id, _ := s.CreateWatchlist("alice@example.com", "Test WL")

	// Now set a broken DB for the delete to trigger error logging.
	s.SetDB(&errDB{})
	err := s.DeleteWatchlist("alice@example.com", id)
	// The delete should succeed in-memory but log DB errors.
	require.NoError(t, err)
}

func TestCreateWatchlist_DBError(t *testing.T) {
	t.Parallel()
	s := NewStore()
	s.SetDB(&errDB{})
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	// Even though DB persist fails, in-memory creation succeeds.
	id, err := s.CreateWatchlist("alice@example.com", "Test WL")
	require.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestAddItem_DBError(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	id, _ := s.CreateWatchlist("alice@example.com", "Test WL")

	// Switch to error DB for the add.
	s.SetDB(&errDB{})
	err := s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
	})
	// In-memory add succeeds; DB error is logged.
	require.NoError(t, err)
}

func TestRemoveItem_DBError(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	id, _ := s.CreateWatchlist("alice@example.com", "Test WL")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
	})

	items := s.GetItems(id)
	require.Len(t, items, 1)

	// Switch to error DB for the remove.
	s.SetDB(&errDB{})
	err := s.RemoveItem("alice@example.com", id, items[0].ID)
	// In-memory remove succeeds; DB error is logged.
	require.NoError(t, err)
}

func TestDeleteByEmail_DBError(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	s.CreateWatchlist("alice@example.com", "WL1")

	// Switch to error DB for the delete.
	s.SetDB(&errDB{})
	// Should not panic — DB errors are logged.
	s.DeleteByEmail("alice@example.com")

	// In-memory delete should still have worked.
	assert.Len(t, s.ListWatchlists("alice@example.com"), 0)
}

// TestLoadWatchlists_ScanError triggers the rows.Scan error path (db.go:80-82)
// by dropping the real table and recreating it with all column names but NULL
// values in columns that Go Scan expects non-nil.
func TestLoadWatchlists_ScanError(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	// Drop and recreate with all 6 expected column names but no constraints.
	require.NoError(t, db.ExecDDL(`DROP TABLE watchlists`))
	require.NoError(t, db.ExecDDL(`CREATE TABLE watchlists (
		id TEXT, email TEXT, name TEXT, sort_order TEXT, created_at TEXT, updated_at TEXT
	)`))
	// Insert a row where sort_order is NULL (Scan into int fails).
	require.NoError(t, db.ExecInsert(
		`INSERT INTO watchlists (id, email, name) VALUES ('bad-wl', 'a@b.com', 'test')`))

	_, err := loadWatchlists(db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan watchlist")
}

// TestLoadItems_ScanError triggers the rows.Scan error path (db.go:122-126)
// by dropping the real table and recreating it with all column names but NULL
// values in columns that Go Scan expects non-nil.
func TestLoadItems_ScanError(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.NoError(t, InitTables(db))

	// Drop and recreate with all 11 expected column names but no constraints.
	require.NoError(t, db.ExecDDL(`DROP TABLE watchlist_items`))
	require.NoError(t, db.ExecDDL(`CREATE TABLE watchlist_items (
		id TEXT, watchlist_id TEXT, email TEXT, exchange TEXT, tradingsymbol TEXT,
		instrument_token TEXT, notes TEXT, target_entry TEXT, target_exit TEXT,
		sort_order TEXT, added_at TEXT
	)`))
	// Insert a row where instrument_token is NULL (Scan into uint32 fails).
	require.NoError(t, db.ExecInsert(
		`INSERT INTO watchlist_items (id, watchlist_id, email) VALUES ('bad-item', 'wl1', 'a@b.com')`))

	_, err := loadItems(db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan watchlist item")
}
