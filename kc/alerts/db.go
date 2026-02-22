package alerts

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB provides SQLite persistence for alerts and Telegram chat IDs.
type DB struct {
	db *sql.DB
}

// OpenDB opens (or creates) the SQLite database at path and ensures tables exist.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("set wal mode: %w", err)
	}

	ddl := `
CREATE TABLE IF NOT EXISTS alerts (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    instrument_token INTEGER NOT NULL,
    target_price     REAL NOT NULL,
    direction        TEXT NOT NULL CHECK(direction IN ('above','below')),
    triggered        INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    triggered_at     TEXT,
    triggered_price  REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_email ON alerts(email);

CREATE TABLE IF NOT EXISTS telegram_chat_ids (
    email   TEXT PRIMARY KEY,
    chat_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kite_tokens (
    email        TEXT PRIMARY KEY,
    access_token TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    user_name    TEXT NOT NULL,
    stored_at    TEXT NOT NULL
);`
	if _, err := db.Exec(ddl); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}
	return &DB{db: db}, nil
}

// LoadAlerts reads all alerts from the database grouped by email.
func (d *DB) LoadAlerts() (map[string][]*Alert, error) {
	rows, err := d.db.Query(`SELECT id, email, tradingsymbol, exchange, instrument_token,
		target_price, direction, triggered, created_at, triggered_at, triggered_price FROM alerts`)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]*Alert)
	for rows.Next() {
		var (
			a           Alert
			dir         string
			triggeredI  int
			createdAtS  string
			triggeredAt sql.NullString
			trigPrice   sql.NullFloat64
		)
		if err := rows.Scan(&a.ID, &a.Email, &a.Tradingsymbol, &a.Exchange,
			&a.InstrumentToken, &a.TargetPrice, &dir, &triggeredI,
			&createdAtS, &triggeredAt, &trigPrice); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		a.Direction = Direction(dir)
		a.Triggered = triggeredI != 0
		a.CreatedAt, err = time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if triggeredAt.Valid {
			a.TriggeredAt, err = time.Parse(time.RFC3339, triggeredAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse triggered_at: %w", err)
			}
		}
		if trigPrice.Valid {
			a.TriggeredPrice = trigPrice.Float64
		}
		out[a.Email] = append(out[a.Email], &a)
	}
	return out, rows.Err()
}

// SaveAlert inserts or replaces an alert in the database.
func (d *DB) SaveAlert(alert *Alert) error {
	triggered := 0
	if alert.Triggered {
		triggered = 1
	}
	var triggeredAt sql.NullString
	if !alert.TriggeredAt.IsZero() {
		triggeredAt = sql.NullString{String: alert.TriggeredAt.Format(time.RFC3339), Valid: true}
	}
	var trigPrice sql.NullFloat64
	if alert.TriggeredPrice != 0 {
		trigPrice = sql.NullFloat64{Float64: alert.TriggeredPrice, Valid: true}
	}

	_, err := d.db.Exec(`INSERT OR REPLACE INTO alerts
		(id, email, tradingsymbol, exchange, instrument_token, target_price,
		 direction, triggered, created_at, triggered_at, triggered_price)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		alert.ID, alert.Email, alert.Tradingsymbol, alert.Exchange,
		alert.InstrumentToken, alert.TargetPrice, string(alert.Direction),
		triggered, alert.CreatedAt.Format(time.RFC3339),
		triggeredAt, trigPrice)
	if err != nil {
		return fmt.Errorf("save alert: %w", err)
	}
	return nil
}

// DeleteAlert removes an alert by ID for the given email.
func (d *DB) DeleteAlert(email, alertID string) error {
	_, err := d.db.Exec(`DELETE FROM alerts WHERE id = ? AND email = ?`, alertID, email)
	if err != nil {
		return fmt.Errorf("delete alert: %w", err)
	}
	return nil
}

// UpdateTriggered marks an alert as triggered with the given price and time.
func (d *DB) UpdateTriggered(alertID string, price float64, at time.Time) error {
	_, err := d.db.Exec(`UPDATE alerts SET triggered = 1, triggered_at = ?, triggered_price = ? WHERE id = ?`,
		at.Format(time.RFC3339), price, alertID)
	if err != nil {
		return fmt.Errorf("update triggered: %w", err)
	}
	return nil
}

// LoadTelegramChatIDs reads all email-to-chatID mappings.
func (d *DB) LoadTelegramChatIDs() (map[string]int64, error) {
	rows, err := d.db.Query(`SELECT email, chat_id FROM telegram_chat_ids`)
	if err != nil {
		return nil, fmt.Errorf("query telegram chat ids: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int64)
	for rows.Next() {
		var email string
		var chatID int64
		if err := rows.Scan(&email, &chatID); err != nil {
			return nil, fmt.Errorf("scan telegram chat id: %w", err)
		}
		out[email] = chatID
	}
	return out, rows.Err()
}

// SaveTelegramChatID stores or updates a Telegram chat ID for the given email.
func (d *DB) SaveTelegramChatID(email string, chatID int64) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO telegram_chat_ids (email, chat_id) VALUES (?, ?)`, email, chatID)
	if err != nil {
		return fmt.Errorf("save telegram chat id: %w", err)
	}
	return nil
}

// TokenEntry represents a Kite access token stored in the database.
type TokenEntry struct {
	Email       string
	AccessToken string
	UserID      string
	UserName    string
	StoredAt    time.Time
}

// LoadTokens reads all cached Kite tokens from the database.
func (d *DB) LoadTokens() ([]*TokenEntry, error) {
	rows, err := d.db.Query(`SELECT email, access_token, user_id, user_name, stored_at FROM kite_tokens`)
	if err != nil {
		return nil, fmt.Errorf("query tokens: %w", err)
	}
	defer rows.Close()

	var out []*TokenEntry
	for rows.Next() {
		var t TokenEntry
		var storedAtS string
		if err := rows.Scan(&t.Email, &t.AccessToken, &t.UserID, &t.UserName, &storedAtS); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		t.StoredAt, _ = time.Parse(time.RFC3339, storedAtS)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// SaveToken stores or updates a Kite token for the given email.
func (d *DB) SaveToken(email, accessToken, userID, userName string, storedAt time.Time) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		email, accessToken, userID, userName, storedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	return nil
}

// DeleteToken removes a cached token for the given email.
func (d *DB) DeleteToken(email string) error {
	_, err := d.db.Exec(`DELETE FROM kite_tokens WHERE email = ?`, email)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}
