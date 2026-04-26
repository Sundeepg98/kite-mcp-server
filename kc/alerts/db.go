package alerts

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLDB is the dialect-portable surface that *DB exposes. Captures the
// driver-level operations callers consume (ExecDDL/ExecInsert/ExecResult/
// QueryRow/RawQuery/Close/Ping/SetEncryptionKey) without coupling to the
// SQLite-specific helpers (GetConfig/SetConfig use INSERT OR REPLACE,
// which is SQLite-only — those stay on *DB and would have a Postgres-
// flavored sibling on a hypothetical PostgresDB).
//
// Postgres-readiness contract: a future Postgres adapter ships as a
// new struct (e.g. PostgresDB) implementing this interface plus its own
// dialect-specific helpers. Schema files in kc/alerts/db.go's DDL block
// use SQLite-flavored syntax; a Postgres port would need a parallel DDL
// pass (different INTEGER PRIMARY KEY semantics, no INSERT OR REPLACE,
// JSONB instead of TEXT for conditions_json, etc.) — but the
// driver-level method surface stays identical.
//
// This interface exists to make the readiness explicit (compile-time
// assertion at db_test.go) without inventing a real Postgres adapter
// today (per .research/path-to-100-per-class-deep-dive.md Class 3:
// "interface-only proof, real adapter scale-gated").
type SQLDB interface {
	ExecDDL(ddl string) error
	ExecInsert(query string, args ...any) error
	ExecResult(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	RawQuery(query string, args ...any) (*sql.Rows, error)
	Close() error
	Ping() error
	SetEncryptionKey(key []byte)
}

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

// Ping verifies the SQLite connection is alive by issuing a no-op query.
// Used by /healthz?probe=deep to surface DB-side outages (file deleted,
// disk full, locked) that the in-process state alone cannot detect.
//
// We use a simple SELECT 1 rather than db.Ping() because modernc.org/sqlite
// returns nil from Ping even on detached file handles in some scenarios;
// a real round-trip query catches more failure modes.
func (d *DB) Ping() error {
	if d == nil || d.db == nil {
		return fmt.Errorf("db: nil connection")
	}
	var v int
	if err := d.db.QueryRow("SELECT 1").Scan(&v); err != nil {
		return fmt.Errorf("db: ping query failed: %w", err)
	}
	if v != 1 {
		return fmt.Errorf("db: ping returned unexpected value %d", v)
	}
	return nil
}

// OpenDB opens (or creates) the SQLite database at path and ensures tables exist.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite is single-writer by design — pinning the pool to one
	// connection eliminates the modernc/sqlite ":memory:" gotcha where
	// each pool connection gets its own in-memory database. For file-
	// backed DBs the cap matches SQLite's actual concurrency. Without
	// this, async writers (event outbox pump, audit buffer flush) can
	// race-spawn fresh connections that don't see other goroutines'
	// schema changes.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil { // COVERAGE: unreachable — SQLite Open succeeds implies Ping succeeds
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil { // COVERAGE: unreachable — PRAGMA always succeeds on valid connection
		return nil, fmt.Errorf("set wal mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil { // COVERAGE: unreachable — PRAGMA always succeeds on valid connection
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	ddl := `
CREATE TABLE IF NOT EXISTS alerts (
    id                   TEXT PRIMARY KEY,
    email                TEXT NOT NULL,
    tradingsymbol        TEXT NOT NULL,
    exchange             TEXT NOT NULL,
    instrument_token     INTEGER NOT NULL,
    target_price         REAL NOT NULL DEFAULT 0,
    direction            TEXT NOT NULL DEFAULT 'above',
    triggered            INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    triggered_at         TEXT,
    triggered_price      REAL,
    reference_price      REAL,
    notification_sent_at TEXT,
    alert_type           TEXT NOT NULL DEFAULT 'single',
    composite_logic      TEXT,
    composite_name       TEXT,
    conditions_json      TEXT
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
	db.Exec(`ALTER TABLE kite_credentials ADD COLUMN app_id TEXT DEFAULT ''`) // #nosec G104 -- idempotent migration

	// Migrate app_registry: add source and last_used_at columns if missing.
	db.Exec(`ALTER TABLE app_registry ADD COLUMN source TEXT DEFAULT 'admin'`)         // #nosec G104 -- idempotent migration
	db.Exec(`ALTER TABLE app_registry ADD COLUMN last_used_at TEXT DEFAULT ''`)         // #nosec G104 -- idempotent migration

	// Migrate app_registry: relax CHECK constraint to allow 'invalid' and 'replaced' statuses.
	// SQLite cannot ALTER CHECK constraints, so we recreate the table.
	if err := migrateRegistryCheckConstraint(db); err != nil {
		return nil, fmt.Errorf("migrate registry check constraint: %w", err)
	}

	// Migrate mcp_sessions: add session_id_enc column for encrypted session ID recovery.
	// If the column doesn't exist, add it and clear existing rows (they stored plaintext IDs).
	var hasEncCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('mcp_sessions') WHERE name = 'session_id_enc'`).Scan(&hasEncCol); err == nil && hasEncCol == 0 {
		db.Exec(`ALTER TABLE mcp_sessions ADD COLUMN session_id_enc TEXT DEFAULT ''`) // #nosec G104 -- idempotent migration
		// Clear existing sessions — they have plaintext session IDs as PKs, which are
		// incompatible with the new HMAC-hashed PK scheme. 12h expiry makes this acceptable.
		db.Exec(`DELETE FROM mcp_sessions`) // #nosec G104 -- idempotent migration cleanup
	}

	return &DB{db: db}, nil
}

// TokenEntry represents a Kite access token stored in the database.
type TokenEntry struct {
	Email       string
	AccessToken string
	UserID      string
	UserName    string
	StoredAt    time.Time
}

// CredentialEntry represents a user's Kite developer app credentials stored in the database.
type CredentialEntry struct {
	Email     string
	APIKey    string
	APISecret string
	AppID     string
	StoredAt  time.Time
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

// SessionDBEntry represents an MCP session stored in the database.
type SessionDBEntry struct {
	SessionID  string
	Email      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Terminated bool
}

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
