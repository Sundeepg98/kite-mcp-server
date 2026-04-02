package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
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
    session_id      TEXT PRIMARY KEY,
    email           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    terminated      INTEGER NOT NULL DEFAULT 0,
    session_id_enc  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trailing_stops (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    instrument_token INTEGER NOT NULL,
    order_id         TEXT NOT NULL,
    variety          TEXT NOT NULL DEFAULT 'regular',
    trail_amount     REAL NOT NULL DEFAULT 0,
    trail_pct        REAL NOT NULL DEFAULT 0,
    direction        TEXT NOT NULL CHECK(direction IN ('long','short')),
    high_water_mark  REAL NOT NULL,
    current_stop     REAL NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    deactivated_at   TEXT,
    modify_count     INTEGER NOT NULL DEFAULT 0,
    last_modified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_trailing_stops_email ON trailing_stops(email);
CREATE INDEX IF NOT EXISTS idx_trailing_stops_active ON trailing_stops(active);

CREATE TABLE IF NOT EXISTS daily_pnl (
    date           TEXT NOT NULL,
    email          TEXT NOT NULL,
    holdings_pnl   REAL NOT NULL DEFAULT 0,
    positions_pnl  REAL NOT NULL DEFAULT 0,
    net_pnl        REAL NOT NULL DEFAULT 0,
    holdings_count INTEGER NOT NULL DEFAULT 0,
    trades_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (date, email)
);
CREATE INDEX IF NOT EXISTS idx_daily_pnl_email ON daily_pnl(email);

CREATE TABLE IF NOT EXISTS app_registry (
    id            TEXT PRIMARY KEY,
    api_key       TEXT NOT NULL,
    api_secret    TEXT NOT NULL,
    assigned_to   TEXT NOT NULL DEFAULT '',
    label         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','invalid','replaced')),
    registered_by TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'admin',
    last_used_at  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_app_registry_assigned ON app_registry(assigned_to);
CREATE INDEX IF NOT EXISTS idx_app_registry_api_key ON app_registry(api_key);`
	if _, err := db.Exec(ddl); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}

	// Migrate existing databases: add reference_price column if missing.
	if err := migrateAlerts(db); err != nil {
		return nil, fmt.Errorf("migrate alerts: %w", err)
	}

	// Migrate kite_credentials: add app_id column if missing.
	db.Exec(`ALTER TABLE kite_credentials ADD COLUMN app_id TEXT DEFAULT ''`) //nolint:errcheck

	// Migrate app_registry: add source and last_used_at columns if missing.
	db.Exec(`ALTER TABLE app_registry ADD COLUMN source TEXT DEFAULT 'admin'`)         //nolint:errcheck
	db.Exec(`ALTER TABLE app_registry ADD COLUMN last_used_at TEXT DEFAULT ''`)         //nolint:errcheck

	// Migrate app_registry: relax CHECK constraint to allow 'invalid' and 'replaced' statuses.
	// SQLite cannot ALTER CHECK constraints, so we recreate the table.
	if err := migrateRegistryCheckConstraint(db); err != nil {
		return nil, fmt.Errorf("migrate registry check constraint: %w", err)
	}

	// Migrate mcp_sessions: add session_id_enc column for encrypted session ID recovery.
	// If the column doesn't exist, add it and clear existing rows (they stored plaintext IDs).
	var hasEncCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('mcp_sessions') WHERE name = 'session_id_enc'`).Scan(&hasEncCol); err == nil && hasEncCol == 0 {
		db.Exec(`ALTER TABLE mcp_sessions ADD COLUMN session_id_enc TEXT DEFAULT ''`) //nolint:errcheck
		// Clear existing sessions — they have plaintext session IDs as PKs, which are
		// incompatible with the new HMAC-hashed PK scheme. 12h expiry makes this acceptable.
		db.Exec(`DELETE FROM mcp_sessions`)                                           //nolint:errcheck
	}

	return &DB{db: db}, nil
}

// migrateRegistryCheckConstraint recreates the app_registry table with an expanded
// CHECK constraint that includes 'invalid' and 'replaced' statuses. This is needed
// because SQLite does not support ALTER CHECK.
func migrateRegistryCheckConstraint(db *sql.DB) error {
	// Check if the migration is needed by looking at the current table SQL.
	var tableSql string
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='app_registry'`).Scan(&tableSql)
	if err != nil {
		return nil // table doesn't exist yet (will be created by DDL), nothing to migrate
	}
	// If the table already supports 'invalid', no migration needed.
	if strings.Contains(tableSql, "'invalid'") {
		return nil
	}

	// Recreate: new table → copy data → drop old → rename
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin registry migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`CREATE TABLE app_registry_new (
		id            TEXT PRIMARY KEY,
		api_key       TEXT NOT NULL,
		api_secret    TEXT NOT NULL,
		assigned_to   TEXT NOT NULL DEFAULT '',
		label         TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','invalid','replaced')),
		registered_by TEXT NOT NULL DEFAULT '',
		source        TEXT NOT NULL DEFAULT 'admin',
		last_used_at  TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create registry_new: %w", err)
	}

	// Copy existing data. Use COALESCE for new columns that may not exist yet in the source.
	if _, err := tx.Exec(`INSERT INTO app_registry_new (id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at)
		SELECT id, api_key, api_secret, assigned_to, label, status, registered_by,
			COALESCE(source, 'admin'), COALESCE(last_used_at, ''), created_at, updated_at
		FROM app_registry`); err != nil {
		return fmt.Errorf("copy registry data: %w", err)
	}

	if _, err := tx.Exec(`DROP TABLE app_registry`); err != nil {
		return fmt.Errorf("drop old registry: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE app_registry_new RENAME TO app_registry`); err != nil {
		return fmt.Errorf("rename registry: %w", err)
	}
	// Recreate indexes
	tx.Exec(`CREATE INDEX IF NOT EXISTS idx_app_registry_assigned ON app_registry(assigned_to)`) //nolint:errcheck
	tx.Exec(`CREATE INDEX IF NOT EXISTS idx_app_registry_api_key ON app_registry(api_key)`)     //nolint:errcheck

	return tx.Commit()
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

// hashSessionID returns HMAC-SHA256(encryptionKey, sessionID) as a hex string.
// If no encryption key is configured, the session ID is returned as-is (fallback).
func (d *DB) hashSessionID(sessionID string) string {
	if d.encryptionKey == nil {
		return sessionID
	}
	mac := hmac.New(sha256.New, d.encryptionKey)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
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
// When encryption is enabled, session_id (PK) is an HMAC hash and the original
// session ID is recovered by decrypting session_id_enc. Rows without a valid
// encrypted ID are skipped (stale pre-migration data).
func (d *DB) LoadSessions() ([]*SessionDBEntry, error) {
	rows, err := d.db.Query(`SELECT session_id, email, created_at, expires_at, terminated, COALESCE(session_id_enc, '') FROM mcp_sessions`)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var out []*SessionDBEntry
	for rows.Next() {
		var s SessionDBEntry
		var createdAtS, expiresAtS, sessionIDEnc string
		var terminatedI int
		if err := rows.Scan(&s.SessionID, &s.Email, &createdAtS, &expiresAtS, &terminatedI, &sessionIDEnc); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}

		// If encryption is enabled, the PK is a hash — recover original ID from encrypted column.
		if d.encryptionKey != nil && sessionIDEnc != "" {
			decrypted := decrypt(d.encryptionKey, sessionIDEnc)
			if decrypted != "" {
				s.SessionID = decrypted
			} else {
				// Decryption failed — skip this row (stale/corrupt data)
				continue
			}
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
// The session_id PK is stored as HMAC-SHA256(key, sessionID) so the original
// session ID never appears in plaintext in the database. The original ID is
// stored encrypted in session_id_enc for recovery on restart.
func (d *DB) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	terminatedI := 0
	if terminated {
		terminatedI = 1
	}
	hashedID := d.hashSessionID(sessionID)
	var sessionIDEnc string
	if d.encryptionKey != nil {
		var err error
		sessionIDEnc, err = encrypt(d.encryptionKey, sessionID)
		if err != nil {
			return fmt.Errorf("encrypt session_id: %w", err)
		}
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		hashedID, email, createdAt.Format(time.RFC3339), expiresAt.Format(time.RFC3339), terminatedI, sessionIDEnc)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// DeleteSession removes an MCP session by ID.
// The session_id is hashed before lookup to match the HMAC-hashed PK in the database.
func (d *DB) DeleteSession(sessionID string) error {
	hashedID := d.hashSessionID(sessionID)
	_, err := d.db.Exec(`DELETE FROM mcp_sessions WHERE session_id = ?`, hashedID)
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

// GetConfig retrieves a value from the config table by key.
// Returns ("", sql.ErrNoRows) if the key does not exist.
func (d *DB) GetConfig(key string) (string, error) {
	var value string
	err := d.db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetConfig stores or updates a key-value pair in the config table.
func (d *DB) SetConfig(key, value string) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, value)
	if err != nil {
		return fmt.Errorf("set config %s: %w", key, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Trailing Stop persistence
// ---------------------------------------------------------------------------

// SaveTrailingStop inserts or replaces a trailing stop in the database.
func (d *DB) SaveTrailingStop(ts *TrailingStop) error {
	active := 0
	if ts.Active {
		active = 1
	}
	var deactivatedAt, lastModifiedAt sql.NullString
	if !ts.DeactivatedAt.IsZero() {
		deactivatedAt = sql.NullString{String: ts.DeactivatedAt.Format(time.RFC3339), Valid: true}
	}
	if !ts.LastModifiedAt.IsZero() {
		lastModifiedAt = sql.NullString{String: ts.LastModifiedAt.Format(time.RFC3339), Valid: true}
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO trailing_stops
		(id, email, exchange, tradingsymbol, instrument_token, order_id, variety,
		 trail_amount, trail_pct, direction, high_water_mark, current_stop,
		 active, created_at, deactivated_at, modify_count, last_modified_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts.ID, ts.Email, ts.Exchange, ts.Tradingsymbol, ts.InstrumentToken,
		ts.OrderID, ts.Variety, ts.TrailAmount, ts.TrailPct, ts.Direction,
		ts.HighWaterMark, ts.CurrentStop, active,
		ts.CreatedAt.Format(time.RFC3339), deactivatedAt, ts.ModifyCount, lastModifiedAt)
	if err != nil {
		return fmt.Errorf("save trailing stop: %w", err)
	}
	return nil
}

// LoadTrailingStops reads all active trailing stops from the database.
func (d *DB) LoadTrailingStops() ([]*TrailingStop, error) {
	rows, err := d.db.Query(`SELECT id, email, exchange, tradingsymbol, instrument_token,
		order_id, variety, trail_amount, trail_pct, direction,
		high_water_mark, current_stop, active, created_at, deactivated_at,
		modify_count, last_modified_at
		FROM trailing_stops WHERE active = 1`)
	if err != nil {
		return nil, fmt.Errorf("query trailing stops: %w", err)
	}
	defer rows.Close()

	var out []*TrailingStop
	for rows.Next() {
		var (
			ts             TrailingStop
			activeI        int
			createdAtS     string
			deactivatedAt  sql.NullString
			lastModifiedAt sql.NullString
		)
		if err := rows.Scan(&ts.ID, &ts.Email, &ts.Exchange, &ts.Tradingsymbol,
			&ts.InstrumentToken, &ts.OrderID, &ts.Variety,
			&ts.TrailAmount, &ts.TrailPct, &ts.Direction,
			&ts.HighWaterMark, &ts.CurrentStop, &activeI,
			&createdAtS, &deactivatedAt, &ts.ModifyCount, &lastModifiedAt); err != nil {
			return nil, fmt.Errorf("scan trailing stop: %w", err)
		}
		ts.Active = activeI != 0
		ts.CreatedAt, _ = time.Parse(time.RFC3339, createdAtS)
		if deactivatedAt.Valid {
			ts.DeactivatedAt, _ = time.Parse(time.RFC3339, deactivatedAt.String)
		}
		if lastModifiedAt.Valid {
			ts.LastModifiedAt, _ = time.Parse(time.RFC3339, lastModifiedAt.String)
		}
		out = append(out, &ts)
	}
	return out, rows.Err()
}

// DeactivateTrailingStop marks a trailing stop as inactive.
func (d *DB) DeactivateTrailingStop(id string) error {
	_, err := d.db.Exec(`UPDATE trailing_stops SET active = 0, deactivated_at = ? WHERE id = ?`,
		time.Now().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("deactivate trailing stop: %w", err)
	}
	return nil
}

// UpdateTrailingStop updates the high water mark, current stop, and modify count.
func (d *DB) UpdateTrailingStop(id string, hwm, currentStop float64, modifyCount int) error {
	_, err := d.db.Exec(`UPDATE trailing_stops SET high_water_mark = ?, current_stop = ?, modify_count = ?, last_modified_at = ? WHERE id = ?`,
		hwm, currentStop, modifyCount, time.Now().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("update trailing stop: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Daily P&L persistence
// ---------------------------------------------------------------------------

// DailyPnLEntry represents a single day's P&L snapshot.
type DailyPnLEntry struct {
	Date          string  `json:"date"`
	Email         string  `json:"email"`
	HoldingsPnL   float64 `json:"holdings_pnl"`
	PositionsPnL  float64 `json:"positions_pnl"`
	NetPnL        float64 `json:"net_pnl"`
	HoldingsCount int     `json:"holdings_count"`
	TradesCount   int     `json:"trades_count"`
}

// SaveDailyPnL inserts or replaces a daily P&L entry.
func (d *DB) SaveDailyPnL(entry *DailyPnLEntry) error {
	_, err := d.db.Exec(`INSERT OR REPLACE INTO daily_pnl
		(date, email, holdings_pnl, positions_pnl, net_pnl, holdings_count, trades_count)
		VALUES (?,?,?,?,?,?,?)`,
		entry.Date, entry.Email, entry.HoldingsPnL, entry.PositionsPnL,
		entry.NetPnL, entry.HoldingsCount, entry.TradesCount)
	if err != nil {
		return fmt.Errorf("save daily pnl: %w", err)
	}
	return nil
}

// LoadDailyPnL reads daily P&L entries for a user within a date range (inclusive).
// Dates are in "2006-01-02" format.
func (d *DB) LoadDailyPnL(email, fromDate, toDate string) ([]*DailyPnLEntry, error) {
	rows, err := d.db.Query(`SELECT date, email, holdings_pnl, positions_pnl, net_pnl,
		holdings_count, trades_count
		FROM daily_pnl WHERE email = ? AND date >= ? AND date <= ?
		ORDER BY date ASC`, email, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("query daily pnl: %w", err)
	}
	defer rows.Close()

	var out []*DailyPnLEntry
	for rows.Next() {
		var e DailyPnLEntry
		if err := rows.Scan(&e.Date, &e.Email, &e.HoldingsPnL, &e.PositionsPnL,
			&e.NetPnL, &e.HoldingsCount, &e.TradesCount); err != nil {
			return nil, fmt.Errorf("scan daily pnl: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// --- App Registry (Key Registry for zero-config onboarding) ---

// RegistryDBEntry represents an app registration stored in the database.
type RegistryDBEntry struct {
	ID           string
	APIKey       string
	APISecret    string
	AssignedTo   string
	Label        string
	Status       string
	RegisteredBy string
	Source       string
	LastUsedAt   *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LoadRegistryEntries reads all app registrations from the database.
// If an encryption key is set, api_secret is decrypted transparently.
func (d *DB) LoadRegistryEntries() (map[string]*RegistryDBEntry, error) {
	rows, err := d.db.Query(`SELECT id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at FROM app_registry`)
	if err != nil {
		return nil, fmt.Errorf("query app_registry: %w", err)
	}
	defer rows.Close()

	out := make(map[string]*RegistryDBEntry)
	for rows.Next() {
		var e RegistryDBEntry
		var source, lastUsedAtS, createdAtS, updatedAtS string
		if err := rows.Scan(&e.ID, &e.APIKey, &e.APISecret, &e.AssignedTo, &e.Label, &e.Status, &e.RegisteredBy, &source, &lastUsedAtS, &createdAtS, &updatedAtS); err != nil {
			return nil, fmt.Errorf("scan app_registry: %w", err)
		}
		if d.encryptionKey != nil {
			e.APIKey = decrypt(d.encryptionKey, e.APIKey)
			e.APISecret = decrypt(d.encryptionKey, e.APISecret)
		}
		e.Source = source
		if lastUsedAtS != "" {
			if t, err := time.Parse(time.RFC3339, lastUsedAtS); err == nil {
				e.LastUsedAt = &t
			}
		}
		if t, err := time.Parse(time.RFC3339, createdAtS); err == nil {
			e.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtS); err == nil {
			e.UpdatedAt = t
		}
		out[e.ID] = &e
	}
	return out, rows.Err()
}

// SaveRegistryEntry stores or updates an app registration.
// If an encryption key is set, api_key and api_secret are encrypted at rest.
func (d *DB) SaveRegistryEntry(e *RegistryDBEntry) error {
	storeKey, storeSecret := e.APIKey, e.APISecret
	if d.encryptionKey != nil {
		var err error
		storeKey, err = encrypt(d.encryptionKey, e.APIKey)
		if err != nil {
			return fmt.Errorf("encrypt registry api_key: %w", err)
		}
		storeSecret, err = encrypt(d.encryptionKey, e.APISecret)
		if err != nil {
			return fmt.Errorf("encrypt registry api_secret: %w", err)
		}
	}
	lastUsedAtS := ""
	if e.LastUsedAt != nil {
		lastUsedAtS = e.LastUsedAt.Format(time.RFC3339)
	}
	_, err := d.db.Exec(`INSERT OR REPLACE INTO app_registry (id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, storeKey, storeSecret, e.AssignedTo, e.Label, e.Status, e.RegisteredBy, e.Source, lastUsedAtS,
		e.CreatedAt.Format(time.RFC3339), e.UpdatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("save registry entry: %w", err)
	}
	return nil
}

// DeleteRegistryEntry removes an app registration by ID.
func (d *DB) DeleteRegistryEntry(id string) error {
	_, err := d.db.Exec(`DELETE FROM app_registry WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete registry entry: %w", err)
	}
	return nil
}
