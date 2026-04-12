// Package audit provides SQLite-backed persistence for MCP tool call audit records.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// ToolCall represents a single MCP tool invocation record.
type ToolCall struct {
	ID            int64     `json:"id"`
	CallID        string    `json:"call_id"`
	Email         string    `json:"email"`
	SessionID     string    `json:"session_id"`
	ToolName      string    `json:"tool_name"`
	ToolCategory  string    `json:"tool_category"`
	InputParams   string    `json:"input_params"` // JSON-encoded parameters
	InputSummary  string    `json:"input_summary"`
	OutputSummary string    `json:"output_summary"`
	OutputSize    int       `json:"output_size"`
	IsError       bool      `json:"is_error"`
	ErrorMessage  string    `json:"error_message"`
	ErrorType     string    `json:"error_type"`
	OrderID       string    `json:"order_id,omitempty"` // extracted from place_order/place_gtt_order responses
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	DurationMs    int64     `json:"duration_ms"`
	PrevHash      string    `json:"prev_hash,omitempty"`
	EntryHash     string    `json:"entry_hash,omitempty"`
}

// ListOptions controls filtering and pagination for List queries.
type ListOptions struct {
	Limit      int
	Offset     int
	Category   string
	OnlyErrors bool
	Since      time.Time
	Until      time.Time
}

const auditBufferSize = 1000

// Store provides audit trail persistence backed by SQLite via alerts.DB.
type Store struct {
	db            *alerts.DB
	writeCh       chan *ToolCall
	done          chan struct{}
	logger        *slog.Logger
	encryptionKey []byte // AES-256 key for email encryption + HMAC email hashing
	lastHash      string // last entry_hash in the chain
	hashKey       []byte // HMAC key for hash chaining
	chainMu       sync.Mutex

	// droppedCount tracks audit entries that could not be persisted
	// (buffer full or synchronous fallback failed). Exposed via DroppedCount
	// for monitoring — non-zero means compliance gaps exist.
	droppedMu    sync.Mutex
	droppedCount int64

	listenerMu        sync.RWMutex
	activityListeners map[string]chan *ToolCall
}

// DroppedCount returns the number of audit entries that have been dropped
// since process start. Used by ops endpoints and alerting.
func (s *Store) DroppedCount() int64 {
	s.droppedMu.Lock()
	defer s.droppedMu.Unlock()
	return s.droppedCount
}

func (s *Store) incDropped() {
	s.droppedMu.Lock()
	s.droppedCount++
	s.droppedMu.Unlock()
}

// New creates a new audit Store using the given database handle.
func New(db *alerts.DB) *Store {
	return &Store{db: db}
}

// SetLogger assigns a structured logger for background worker diagnostics.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// SetEncryptionKey configures the key used for HMAC email hashing, AES-GCM
// email encryption, and HMAC hash chaining. Call this before StartWorker.
func (s *Store) SetEncryptionKey(key []byte) {
	s.encryptionKey = key
	// Derive a separate key for hash chaining using HMAC to provide domain separation.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("audit-chain-key-v1"))
	s.hashKey = mac.Sum(nil)
}

// hmacEmail returns the hex-encoded HMAC-SHA256 of the email using the
// encryption key. If no key is set or email is empty, returns the email as-is.
func (s *Store) hmacEmail(email string) string {
	if s.encryptionKey == nil || email == "" {
		return email
	}
	mac := hmac.New(sha256.New, s.encryptionKey)
	mac.Write([]byte(email))
	return hex.EncodeToString(mac.Sum(nil))
}

// SeedChain reads the last entry_hash from the database to resume the hash
// chain after a restart. Must be called after InitTable and SetEncryptionKey.
func (s *Store) SeedChain() {
	if s.hashKey == nil {
		return
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	row := s.db.QueryRow("SELECT entry_hash FROM tool_calls ORDER BY id DESC LIMIT 1")
	var hash sql.NullString
	if row.Scan(&hash) == nil && hash.Valid && hash.String != "" {
		s.lastHash = hash.String
	} else {
		// Genesis: no prior entries, compute a deterministic seed.
		mac := hmac.New(sha256.New, s.hashKey)
		mac.Write([]byte("genesis-v1"))
		s.lastHash = hex.EncodeToString(mac.Sum(nil))
	}
}

// InitTable creates the tool_calls table and indexes if they do not exist.
func (s *Store) InitTable() error {
	ddl := `
CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id         TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    session_id      TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    tool_category   TEXT NOT NULL DEFAULT '',
    input_params    TEXT,
    input_summary   TEXT,
    output_summary  TEXT,
    output_size     INTEGER NOT NULL DEFAULT 0,
    is_error        INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    error_type      TEXT,
    order_id        TEXT,
    email_hash      TEXT,
    email_encrypted TEXT,
    prev_hash       TEXT DEFAULT '',
    entry_hash      TEXT DEFAULT '',
    started_at      TEXT NOT NULL,
    completed_at    TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tc_email_time ON tool_calls(email, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_tool_time ON tool_calls(tool_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_category ON tool_calls(tool_category, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_error ON tool_calls(is_error) WHERE is_error = 1;`
	if err := s.db.ExecDDL(ddl); err != nil {
		return fmt.Errorf("audit: create tool_calls table: %w", err)
	}

	// Migrate existing databases: add columns if missing.
	// SQLite returns an error if the column already exists; ignore it.
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN order_id TEXT`)
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN email_hash TEXT`)
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN email_encrypted TEXT`)
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN prev_hash TEXT DEFAULT ''`)
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN entry_hash TEXT DEFAULT ''`)

	// Create index on email_hash AFTER migration ensures the column exists
	_ = s.db.ExecDDL(`CREATE INDEX IF NOT EXISTS idx_tc_email_hash ON tool_calls(email_hash, started_at DESC)`)

	return nil
}
