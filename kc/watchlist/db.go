package watchlist

import (
	"fmt"
	"time"
)

// InitTables creates the watchlist tables if they don't exist.
func InitTables(db WatchlistDB) error {
	ddl := `
CREATE TABLE IF NOT EXISTS watchlists (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    name       TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watchlists_email ON watchlists(email);

CREATE TABLE IF NOT EXISTS watchlist_items (
    id               TEXT PRIMARY KEY,
    watchlist_id     TEXT NOT NULL,
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    instrument_token INTEGER NOT NULL,
    notes            TEXT NOT NULL DEFAULT '',
    target_entry     REAL NOT NULL DEFAULT 0,
    target_exit      REAL NOT NULL DEFAULT 0,
    sort_order       INTEGER NOT NULL DEFAULT 0,
    added_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watchlist_items_wl ON watchlist_items(watchlist_id);
CREATE INDEX IF NOT EXISTS idx_watchlist_items_email ON watchlist_items(email);`

	return db.ExecDDL(ddl)
}

// saveWatchlist inserts or replaces a watchlist in the database.
func saveWatchlist(db WatchlistDB, w *Watchlist) error {
	return db.ExecInsert(`INSERT OR REPLACE INTO watchlists
		(id, email, name, sort_order, created_at, updated_at)
		VALUES (?,?,?,?,?,?)`,
		w.ID, w.Email, w.Name, w.SortOrder,
		w.CreatedAt.Format(time.RFC3339),
		w.UpdatedAt.Format(time.RFC3339))
}

// deleteWatchlist removes a watchlist and all its items from the database.
func deleteWatchlist(db WatchlistDB, email, watchlistID string) error {
	// Delete items first
	if err := db.ExecInsert(`DELETE FROM watchlist_items WHERE watchlist_id = ? AND email = ?`, watchlistID, email); err != nil {
		return fmt.Errorf("delete watchlist items: %w", err)
	}
	return db.ExecInsert(`DELETE FROM watchlists WHERE id = ? AND email = ?`, watchlistID, email)
}

// updateWatchlistTimestamp updates the updated_at field for a watchlist.
func updateWatchlistTimestamp(db WatchlistDB, watchlistID string, updatedAt time.Time) error {
	return db.ExecInsert(`UPDATE watchlists SET updated_at = ? WHERE id = ?`,
		updatedAt.Format(time.RFC3339), watchlistID)
}

// loadWatchlists reads all watchlists from the database.
func loadWatchlists(db WatchlistDB) ([]*Watchlist, error) {
	rows, err := db.RawQuery(`SELECT id, email, name, sort_order, created_at, updated_at FROM watchlists`)
	if err != nil {
		return nil, fmt.Errorf("query watchlists: %w", err)
	}
	defer rows.Close()

	var out []*Watchlist
	for rows.Next() {
		var (
			w          Watchlist
			createdAtS string
			updatedAtS string
		)
		if err := rows.Scan(&w.ID, &w.Email, &w.Name, &w.SortOrder, &createdAtS, &updatedAtS); err != nil {
			return nil, fmt.Errorf("scan watchlist: %w", err)
		}
		w.CreatedAt, _ = time.Parse(time.RFC3339, createdAtS)
		w.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtS)
		out = append(out, &w)
	}
	return out, rows.Err()
}

// saveItem inserts or replaces a watchlist item in the database.
func saveItem(db WatchlistDB, item *WatchlistItem) error {
	return db.ExecInsert(`INSERT OR REPLACE INTO watchlist_items
		(id, watchlist_id, email, exchange, tradingsymbol, instrument_token,
		 notes, target_entry, target_exit, sort_order, added_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		item.ID, item.WatchlistID, item.Email, item.Exchange, item.Tradingsymbol,
		item.InstrumentToken, item.Notes, item.TargetEntry, item.TargetExit,
		item.SortOrder, item.AddedAt.Format(time.RFC3339))
}

// deleteItem removes a watchlist item from the database.
func deleteItem(db WatchlistDB, email, itemID string) error {
	return db.ExecInsert(`DELETE FROM watchlist_items WHERE id = ? AND email = ?`, itemID, email)
}

// loadItems reads all watchlist items from the database.
func loadItems(db WatchlistDB) ([]*WatchlistItem, error) {
	rows, err := db.RawQuery(`SELECT id, watchlist_id, email, exchange, tradingsymbol,
		instrument_token, notes, target_entry, target_exit, sort_order, added_at
		FROM watchlist_items`)
	if err != nil {
		return nil, fmt.Errorf("query watchlist items: %w", err)
	}
	defer rows.Close()

	var out []*WatchlistItem
	for rows.Next() {
		var (
			item    WatchlistItem
			addedAt string
		)
		if err := rows.Scan(&item.ID, &item.WatchlistID, &item.Email, &item.Exchange,
			&item.Tradingsymbol, &item.InstrumentToken, &item.Notes,
			&item.TargetEntry, &item.TargetExit, &item.SortOrder, &addedAt); err != nil {
			return nil, fmt.Errorf("scan watchlist item: %w", err)
		}
		item.AddedAt, _ = time.Parse(time.RFC3339, addedAt)
		out = append(out, &item)
	}
	return out, rows.Err()
}
