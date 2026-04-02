package alerts

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB provides SQLite persistence for alerts and Telegram chat IDs.
type DB struct {
	db            *sql.DB
	encryptionKey []byte // AES-256 key for credential encryption (nil = no encryption)
}

// SetEncryptionKey sets the AES-256 key used to encrypt/decrypt credentials at rest.
// Derived from OAUTH_JWT_SECRET via HKDF. If not set, credentials are stored in plaintext.
func (d *DB) SetEncryptionKey(key []byte) {
	d.encryptionKey = key
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
	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	ddl := `
CREATE TABLE IF NOT EXISTS alerts (
    id                   TEXT PRIMARY KEY,
    email                TEXT NOT NULL,
    tradingsymbol        TEXT NOT NULL,
    exchange             TEXT NOT NULL,
    instrument_token     INTEGER NOT NULL,
    target_price         REAL NOT NULL,
    direction            TEXT NOT NULL CHECK(direction IN ('above','below','drop_pct','rise_pct')),
    triggered            INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    triggered_at         TEXT,
    triggered_price      REAL,
    reference_price      REAL,
    notification_sent_at TEXT
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
);

CREATE TABLE IF NOT EXISTS kite_credentials (
    email      TEXT PRIMARY KEY,
    api_key    TEXT NOT NULL,
    api_secret TEXT NOT NULL,
    stored_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    client_name   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    is_kite_key   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_sessions (
    session_id  TEXT PRIMARY KEY,
    email       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    terminated  INTEGER NOT NULL DEFAULT 0
);`
	if _, err := db.Exec(ddl); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}

	// Migrate existing databases: add reference_price column if missing.
	if err := migrateAlerts(db); err != nil {
		return nil, fmt.Errorf("migrate alerts: %w", err)
	}

	// Migrate kite_credentials: add app_id column if missing.
	db.Exec(`ALTER TABLE kite_credentials ADD COLUMN app_id TEXT DEFAULT ''`) //nolint:errcheck

	return &DB{db: db}, nil
}

// migrateAlerts applies incremental schema migrations to the alerts table.
func migrateAlerts(db *sql.DB) error {
	// Check if reference_price column exists.
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('alerts') WHERE name = 'reference_price'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check reference_price column: %w", err)
	}
	if count == 0 {
		if _, err := db.Exec(`ALTER TABLE alerts ADD COLUMN reference_price REAL`); err != nil {
			return fmt.Errorf("add reference_price column: %w", err)
		}
	}

	// Add notification_sent_at column if missing.
	// SQLite returns an error if the column already exists; ignore it.
	db.Exec(`ALTER TABLE alerts ADD COLUMN notification_sent_at TEXT`) //nolint:errcheck

	return nil
}

// LoadAlerts reads all alerts from the database grouped by email.
func (d *DB) LoadAlerts() (map[string][]*Alert, error) {
	rows, err := d.db.Query(`SELECT id, email, tradingsymbol, exchange, instrument_token,
		target_price, direction, triggered, created_at, triggered_at, triggered_price,
		reference_price, notification_sent_at FROM alerts`)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]*Alert)
	for rows.Next() {
		var (
			a                  Alert
			dir                string
			triggeredI         int
			createdAtS         string
			triggeredAt        sql.NullString
			trigPrice          sql.NullFloat64
			referencePrice     sql.NullFloat64
			notificationSentAt sql.NullString
		)
		if err := rows.Scan(&a.ID, &a.Email, &a.Tradingsymbol, &a.Exchange,
			&a.InstrumentToken, &a.TargetPrice, &dir, &triggeredI,
			&createdAtS, &triggeredAt, &trigPrice, &referencePrice,
			&notificationSentAt); err != nil {
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
		if referencePrice.Valid {
			a.ReferencePrice = referencePrice.Float64
		}
		if notificationSentAt.Valid {
			a.NotificationSentAt, _ = time.Parse(time.RFC3339, notificationSentAt.String)
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
	var refPrice sql.NullFloat64
	if alert.ReferencePrice != 0 {
		refPrice = sql.NullFloat64{Float64: alert.ReferencePrice, Valid: true}
	}
	var notifSentAt sql.NullString
	if !alert.NotificationSentAt.IsZero() {
		notifSentAt = sql.NullString{String: alert.NotificationSentAt.Format(time.RFC3339), Valid: true}
	}

	_, err := d.db.Exec(`INSERT OR REPLACE INTO alerts
		(id, email, tradingsymbol, exchange, instrument_token, target_price,
		 direction, triggered, created_at, triggered_at, triggered_price,
		 reference_price, notification_sent_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		alert.ID, alert.Email, alert.Tradingsymbol, alert.Exchange,
		alert.InstrumentToken, alert.TargetPrice, string(alert.Direction),
		triggered, alert.CreatedAt.Format(time.RFC3339),
		triggeredAt, trigPrice, refPrice, notifSentAt)
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

// UpdateAlertNotification records when a Telegram notification was sent for an alert.
func (d *DB) UpdateAlertNotification(alertID string, sentAt time.Time) error {
	_, err := d.db.Exec("UPDATE alerts SET notification_sent_at = ? WHERE id = ?",
		sentAt.Format(time.RFC3339), alertID)
	if err != nil {
		return fmt.Errorf("update notification_sent_at: %w", err)
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
// If an encryption key is set, access tokens are decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
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
		if d.encryptionKey != nil {
			t.AccessToken = decrypt(d.encryptionKey, t.AccessToken)
		}
		storedAt, err := time.Parse(time.RFC3339, storedAtS)
		if err != nil {
			storedAt = time.Time{}
		}
		t.StoredAt = storedAt
		out = append(out, &t)
	}
	return out, rows.Err()
}

// SaveToken stores or updates a Kite token for the given email.
// If an encryption key is set, the access token is encrypted at rest.
func (d *DB) SaveToken(email, accessToken, userID, userName string, storedAt time.Time) error {
	storeToken := accessToken
	if d.encryptionKey != nil {
		var err error
		storeToken, err = encrypt(d.encryptionKey, accessToken)
		if err != nil {
			return fmt.Errorf("encrypt access_token: %w", err)
		}
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		email, storeToken, userID, userName, storedAt.Format(time.RFC3339))
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

// CredentialEntry represents a user's Kite developer app credentials stored in the database.
type CredentialEntry struct {
	Email     string
	APIKey    string
	APISecret string
	AppID     string
	StoredAt  time.Time
}

// LoadCredentials reads all stored Kite credentials from the database.
// If an encryption key is set, api_key and api_secret are decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
func (d *DB) LoadCredentials() ([]*CredentialEntry, error) {
	rows, err := d.db.Query(`SELECT email, api_key, api_secret, stored_at, COALESCE(app_id, '') FROM kite_credentials`)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer rows.Close()

	var out []*CredentialEntry
	for rows.Next() {
		var c CredentialEntry
		var storedAtS string
		if err := rows.Scan(&c.Email, &c.APIKey, &c.APISecret, &storedAtS, &c.AppID); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		if d.encryptionKey != nil {
			c.APIKey = decrypt(d.encryptionKey, c.APIKey)
			c.APISecret = decrypt(d.encryptionKey, c.APISecret)
		}
		storedAt, err := time.Parse(time.RFC3339, storedAtS)
		if err != nil {
			storedAt = time.Time{}
		}
		c.StoredAt = storedAt
		out = append(out, &c)
	}
	return out, rows.Err()
}

// SaveCredential stores or updates Kite credentials for the given email.
// If an encryption key is set, api_key and api_secret are encrypted at rest.
func (d *DB) SaveCredential(email, apiKey, apiSecret, appID string, storedAt time.Time) error {
	storeKey, storeSecret := apiKey, apiSecret
	if d.encryptionKey != nil {
		var err error
		storeKey, err = encrypt(d.encryptionKey, apiKey)
		if err != nil {
			return fmt.Errorf("encrypt api_key: %w", err)
		}
		storeSecret, err = encrypt(d.encryptionKey, apiSecret)
		if err != nil {
			return fmt.Errorf("encrypt api_secret: %w", err)
		}
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO kite_credentials (email, api_key, api_secret, stored_at, app_id) VALUES (?,?,?,?,?)`,
		email, storeKey, storeSecret, storedAt.Format(time.RFC3339), appID)
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}
	return nil
}

// DeleteCredential removes Kite credentials for the given email.
func (d *DB) DeleteCredential(email string) error {
	_, err := d.db.Exec(`DELETE FROM kite_credentials WHERE email = ?`, email)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	return nil
}

// ClientDBEntry represents an OAuth client stored in the database.
type ClientDBEntry struct {
	ClientID     string
	ClientSecret string
	RedirectURIs string // JSON-encoded []string
	ClientName   string
	CreatedAt    time.Time
	IsKiteAPIKey bool
}

// LoadClients reads all OAuth clients from the database.
// If an encryption key is set, client_secret is decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
func (d *DB) LoadClients() ([]*ClientDBEntry, error) {
	rows, err := d.db.Query(`SELECT client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key FROM oauth_clients`)
	if err != nil {
		return nil, fmt.Errorf("query oauth clients: %w", err)
	}
	defer rows.Close()

	var out []*ClientDBEntry
	for rows.Next() {
		var c ClientDBEntry
		var createdAtS string
		var isKiteKey int
		if err := rows.Scan(&c.ClientID, &c.ClientSecret, &c.RedirectURIs, &c.ClientName, &createdAtS, &isKiteKey); err != nil {
			return nil, fmt.Errorf("scan oauth client: %w", err)
		}
		if d.encryptionKey != nil && c.ClientSecret != "" {
			c.ClientSecret = decrypt(d.encryptionKey, c.ClientSecret)
		}
		createdAt, err := time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			createdAt = time.Time{}
		}
		c.CreatedAt = createdAt
		c.IsKiteAPIKey = isKiteKey != 0
		out = append(out, &c)
	}
	return out, rows.Err()
}

// SaveClient stores or updates an OAuth client in the database.
// If an encryption key is set and client_secret is non-empty, it is encrypted at rest.
func (d *DB) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	isKiteKeyInt := 0
	if isKiteKey {
		isKiteKeyInt = 1
	}
	storeSecret := clientSecret
	if d.encryptionKey != nil && clientSecret != "" {
		var err error
		storeSecret, err = encrypt(d.encryptionKey, clientSecret)
		if err != nil {
			return fmt.Errorf("encrypt client_secret: %w", err)
		}
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key) VALUES (?,?,?,?,?,?)`,
		clientID, storeSecret, redirectURIsJSON, clientName, createdAt.Format(time.RFC3339), isKiteKeyInt)
	if err != nil {
		return fmt.Errorf("save oauth client: %w", err)
	}
	return nil
}

// DeleteClient removes an OAuth client by ID.
func (d *DB) DeleteClient(clientID string) error {
	_, err := d.db.Exec(`DELETE FROM oauth_clients WHERE client_id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("delete oauth client: %w", err)
	}
	return nil
}

// SessionDBEntry represents an MCP session stored in the database.
type SessionDBEntry struct {
	SessionID  string
	Email      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Terminated bool
}

// LoadSessions reads all MCP sessions from the database.
func (d *DB) LoadSessions() ([]*SessionDBEntry, error) {
	rows, err := d.db.Query(`SELECT session_id, email, created_at, expires_at, terminated FROM mcp_sessions`)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var out []*SessionDBEntry
	for rows.Next() {
		var s SessionDBEntry
		var createdAtS, expiresAtS string
		var terminatedI int
		if err := rows.Scan(&s.SessionID, &s.Email, &createdAtS, &expiresAtS, &terminatedI); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		createdAt, err := time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			return nil, fmt.Errorf("parse session created_at: %w", err)
		}
		expiresAt, err := time.Parse(time.RFC3339, expiresAtS)
		if err != nil {
			return nil, fmt.Errorf("parse session expires_at: %w", err)
		}
		s.CreatedAt = createdAt
		s.ExpiresAt = expiresAt
		s.Terminated = terminatedI != 0
		out = append(out, &s)
	}
	return out, rows.Err()
}

// SaveSession stores or updates an MCP session in the database.
func (d *DB) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	terminatedI := 0
	if terminated {
		terminatedI = 1
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO mcp_sessions (session_id, email, created_at, expires_at, terminated) VALUES (?,?,?,?,?)`,
		sessionID, email, createdAt.Format(time.RFC3339), expiresAt.Format(time.RFC3339), terminatedI)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// DeleteSession removes an MCP session by ID.
func (d *DB) DeleteSession(sessionID string) error {
	_, err := d.db.Exec(`DELETE FROM mcp_sessions WHERE session_id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Generic helpers for external packages that need raw SQL access.
// ---------------------------------------------------------------------------

// ExecDDL executes a DDL statement (CREATE TABLE, CREATE INDEX, etc.).
func (d *DB) ExecDDL(ddl string) error { _, err := d.db.Exec(ddl); return err }

// ExecInsert executes an INSERT (or similar DML) statement with arguments.
func (d *DB) ExecInsert(query string, args ...any) error { _, err := d.db.Exec(query, args...); return err }

// ExecResult executes a DML statement and returns the sql.Result for inspecting rows affected.
func (d *DB) ExecResult(query string, args ...any) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

// QueryRow executes a query expected to return at most one row.
func (d *DB) QueryRow(query string, args ...any) *sql.Row { return d.db.QueryRow(query, args...) }

// RawQuery executes a query that returns rows.
func (d *DB) RawQuery(query string, args ...any) (*sql.Rows, error) { return d.db.Query(query, args...) }

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}
