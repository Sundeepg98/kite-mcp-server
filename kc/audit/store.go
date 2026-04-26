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
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// ToolCall represents a single MCP tool invocation record.
//
// IPAddress + UserAgent are populated from the originating HTTP request
// (X-Forwarded-For preferred; falls back to RemoteAddr) so the audit
// trail satisfies SEBI Annexure-I compliance: every order-placing tool
// invocation must carry a verifiable client identifier. Empty strings
// indicate either a non-HTTP transport (stdio MCP) or an upstream that
// didn't propagate the client IP.
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
	IPAddress     string    `json:"ip_address,omitempty"` // SEBI Annexure-I — client IP at tool-call time
	UserAgent     string    `json:"user_agent,omitempty"` // SEBI Annexure-I — client UA at tool-call time
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

	// stopOnce guards Stop() so the write channel is only closed once even
	// when multiple graceful-shutdown paths (signal handler + test teardown)
	// both invoke Stop on the same Store instance. Without this, the second
	// close of s.writeCh would panic with "close of closed channel".
	stopOnce sync.Once

	// statsCache backs UserOrderStats with a 15-minute TTL to avoid
	// re-running the 30-day scan on every place_order. See anomaly_cache.go
	// for the eviction policy and invalidation hooks.
	statsCache *statsCache

	// Retention worker shutdown coordination. retentionStop is closed by
	// StopRetentionWorker to signal the goroutine to exit; retentionDone is
	// closed by the goroutine on exit so StopRetentionWorker can block until
	// shutdown is complete. retentionMu guards state transitions.
	retentionMu   sync.Mutex
	retentionStop chan struct{}
	retentionDone chan struct{}
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

// statsCacheTTL is the freshness window for the UserOrderStats cache.
// Kept as a package var (not const) so tests can shrink it if ever needed,
// though current tests drive the cache directly via newStatsCache.
var statsCacheTTL = 15 * time.Minute

// New creates a new audit Store using the given database handle. The
// in-memory UserOrderStats cache is initialised here with the default
// 15-minute TTL.
func New(db *alerts.DB) *Store {
	return &Store{
		db:         db,
		statsCache: newStatsCache(statsCacheTTL),
	}
}

// StatsCacheHitRate exposes the UserOrderStats cache hit ratio for
// monitoring endpoints. Returns 0 before any queries have been made.
func (s *Store) StatsCacheHitRate() float64 {
	return s.statsCache.cacheHitRate()
}

// InvalidateStatsCache drops cached UserOrderStats entries for the given
// email. Called automatically on Record() for order-writing tools, but
// exposed publicly for tests and callers that bypass Record().
func (s *Store) InvalidateStatsCache(email string) {
	s.statsCache.Invalidate(email)
}

// SetAnomalyCacheEventDispatcher wires the domain event dispatcher into
// the in-memory UserOrderStats cache so every baseline snapshot,
// user-scoped invalidation, and per-entry eviction is published as a
// typed domain.AnomalyCache*Event. Pure plumbing — the Store does not
// itself subscribe to these events. app/wire.go calls this once at
// startup; passing nil restores the legacy no-dispatch behaviour.
func (s *Store) SetAnomalyCacheEventDispatcher(d *domain.EventDispatcher) {
	s.statsCache.SetEventDispatcher(d)
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
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    ip_address      TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT ''
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
	// PR-C: SEBI Annexure-I — IP + UA on every tool call.
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''`)
	_ = s.db.ExecDDL(`ALTER TABLE tool_calls ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`)

	// Create index on email_hash AFTER migration ensures the column exists
	_ = s.db.ExecDDL(`CREATE INDEX IF NOT EXISTS idx_tc_email_hash ON tool_calls(email_hash, started_at DESC)`)

	return nil
}
