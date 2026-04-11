// Package audit provides SQLite-backed persistence for MCP tool call audit records.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	InputParams   string    `json:"input_params"`   // JSON-encoded parameters
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

	listenerMu        sync.RWMutex
	activityListeners map[string]chan *ToolCall
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

// StartWorker starts a background goroutine that drains the write channel.
// Call Stop() to gracefully drain and close.
func (s *Store) StartWorker() {
	s.writeCh = make(chan *ToolCall, auditBufferSize)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for entry := range s.writeCh {
			// Compute hash chain link (sequential in worker goroutine).
			s.computeChainLink(entry)
			if err := s.Record(entry); err != nil {
				if s.logger != nil {
					s.logger.Error("Audit write failed", "error", err, "call_id", entry.CallID)
				}
			} else {
				// Broadcast to SSE listeners after successful write.
				s.broadcastToListeners(entry)
			}
		}
	}()
}

// computeChainLink sets PrevHash and EntryHash on the entry using the HMAC
// hash chain. Must be called sequentially (worker goroutine or under chainMu).
func (s *Store) computeChainLink(entry *ToolCall) {
	if s.hashKey == nil {
		return
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	entry.PrevHash = s.lastHash
	mac := hmac.New(sha256.New, s.hashKey)
	mac.Write([]byte(entry.PrevHash + entry.CallID + entry.Email + entry.ToolName + entry.StartedAt.Format(time.RFC3339Nano)))
	entry.EntryHash = hex.EncodeToString(mac.Sum(nil))
	s.lastHash = entry.EntryHash
}

// Enqueue adds a tool call to the write buffer. Non-blocking; drops if buffer full.
func (s *Store) Enqueue(entry *ToolCall) {
	if s.writeCh == nil {
		// Worker not started — fall back to synchronous write.
		_ = s.Record(entry)
		return
	}
	select {
	case s.writeCh <- entry:
	default:
		if s.logger != nil {
			s.logger.Warn("Audit buffer full, dropping entry", "call_id", entry.CallID)
		}
	}
}

// Stop gracefully drains the buffer and waits for completion.
func (s *Store) Stop() {
	if s.writeCh != nil {
		close(s.writeCh)
		<-s.done
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

// Record inserts a tool call entry into the audit log.
// Duplicate call_ids are silently ignored (INSERT OR IGNORE).
// When an encryption key is set, the email column stores the HMAC hash
// (for queryable lookups) and email_encrypted stores the AES-GCM ciphertext
// (for display/export). Legacy rows without encryption store plaintext.
func (s *Store) Record(entry *ToolCall) error {
	isErr := 0
	if entry.IsError {
		isErr = 1
	}

	// Email encryption: HMAC for queries, AES-GCM for display.
	emailForDB := entry.Email
	emailHash := ""
	emailEncrypted := ""
	if s.encryptionKey != nil && entry.Email != "" {
		emailHash = s.hmacEmail(entry.Email)
		enc, err := alerts.Encrypt(s.encryptionKey, entry.Email)
		if err == nil {
			emailEncrypted = enc
		}
		emailForDB = emailHash // store hash in email column for backward-compat queries
	}

	query := `INSERT OR IGNORE INTO tool_calls
		(call_id, email, session_id, tool_name, tool_category,
		 input_params, input_summary, output_summary, output_size,
		 is_error, error_message, error_type, order_id,
		 email_hash, email_encrypted, prev_hash, entry_hash,
		 started_at, completed_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	err := s.db.ExecInsert(query,
		entry.CallID,
		emailForDB,
		entry.SessionID,
		entry.ToolName,
		entry.ToolCategory,
		entry.InputParams,
		entry.InputSummary,
		entry.OutputSummary,
		entry.OutputSize,
		isErr,
		entry.ErrorMessage,
		entry.ErrorType,
		entry.OrderID,
		emailHash,
		emailEncrypted,
		entry.PrevHash,
		entry.EntryHash,
		entry.StartedAt.Format(time.RFC3339Nano),
		entry.CompletedAt.Format(time.RFC3339Nano),
		entry.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("audit: record tool call: %w", err)
	}
	return nil
}

// List retrieves tool call records for a given email, filtered and paginated
// according to opts. It returns the matching entries, the total count of
// matching records (ignoring limit/offset), and any error.
func (s *Store) List(email string, opts ListOptions) ([]*ToolCall, int, error) {
	// Build the WHERE clause dynamically.
	var where []string
	var args []any

	queryEmail := s.hmacEmail(email)
	where = append(where, "email = ?")
	args = append(args, queryEmail)

	if opts.Category != "" {
		where = append(where, "tool_category = ?")
		args = append(args, opts.Category)
	}
	if opts.OnlyErrors {
		where = append(where, "is_error = 1")
	}
	if !opts.Since.IsZero() {
		where = append(where, "started_at >= ?")
		args = append(args, opts.Since.Format(time.RFC3339Nano))
	}
	if !opts.Until.IsZero() {
		where = append(where, "started_at <= ?")
		args = append(args, opts.Until.Format(time.RFC3339Nano))
	}

	whereClause := strings.Join(where, " AND ")

	// Total count.
	countQuery := "SELECT COUNT(*) FROM tool_calls WHERE " + whereClause
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("audit: count tool calls: %w", err)
	}

	// Fetch rows with ordering and pagination.
	dataQuery := "SELECT id, call_id, email, session_id, tool_name, tool_category, " +
		"input_params, input_summary, output_summary, output_size, " +
		"is_error, error_message, error_type, order_id, " +
		"email_encrypted, prev_hash, entry_hash, " +
		"started_at, completed_at, duration_ms " +
		"FROM tool_calls WHERE " + whereClause + " ORDER BY started_at DESC"

	if opts.Limit > 0 {
		dataQuery += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		dataQuery += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.RawQuery(dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: list tool calls: %w", err)
	}
	defer rows.Close()

	var results []*ToolCall
	for rows.Next() {
		tc, err := scanToolCall(rows, s.encryptionKey)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return results, total, nil
}

// scanToolCall scans a single row into a ToolCall struct.
// When encKey is non-nil and email_encrypted is populated, the email field
// is decrypted for display. Otherwise the raw email column value is used
// (legacy plaintext rows).
func scanToolCall(rows *sql.Rows, encKey []byte) (*ToolCall, error) {
	var tc ToolCall
	var (
		isErr                                              int
		inputParams, inputSummary, outputSummary           sql.NullString
		errorMessage, errorType, orderID                   sql.NullString
		emailEncrypted, prevHash, entryHash                sql.NullString
		startedAtS, completedAtS                           string
	)
	if err := rows.Scan(
		&tc.ID, &tc.CallID, &tc.Email, &tc.SessionID,
		&tc.ToolName, &tc.ToolCategory,
		&inputParams, &inputSummary, &outputSummary, &tc.OutputSize,
		&isErr, &errorMessage, &errorType, &orderID,
		&emailEncrypted, &prevHash, &entryHash,
		&startedAtS, &completedAtS, &tc.DurationMs,
	); err != nil { // COVERAGE: unreachable — SQLite driver returns correct column count for well-formed SELECT
		return nil, fmt.Errorf("audit: scan tool call: %w", err)
	}

	tc.IsError = isErr != 0
	tc.InputParams = inputParams.String
	tc.InputSummary = inputSummary.String
	tc.OutputSummary = outputSummary.String
	tc.ErrorMessage = errorMessage.String
	tc.ErrorType = errorType.String
	tc.OrderID = orderID.String
	tc.PrevHash = prevHash.String
	tc.EntryHash = entryHash.String

	// Decrypt email for display if encrypted form is available.
	if encKey != nil && emailEncrypted.Valid && emailEncrypted.String != "" {
		decrypted := alerts.Decrypt(encKey, emailEncrypted.String)
		if decrypted != "" {
			tc.Email = decrypted
		}
	}

	var err error
	tc.StartedAt, err = time.Parse(time.RFC3339Nano, startedAtS)
	if err != nil {
		return nil, fmt.Errorf("audit: parse started_at: %w", err)
	}
	tc.CompletedAt, err = time.Parse(time.RFC3339Nano, completedAtS)
	if err != nil {
		return nil, fmt.Errorf("audit: parse completed_at: %w", err)
	}

	return &tc, nil
}

// ListOrders returns tool calls with order IDs for the given email.
func (s *Store) ListOrders(email string, since time.Time) ([]*ToolCall, error) {
	queryEmail := s.hmacEmail(email)
	query := `SELECT id, call_id, email, session_id, tool_name, tool_category,
		input_params, input_summary, output_summary, output_size,
		is_error, error_message, error_type, order_id,
		email_encrypted, prev_hash, entry_hash,
		started_at, completed_at, duration_ms
		FROM tool_calls
		WHERE email = ? AND order_id IS NOT NULL AND order_id != '' AND started_at >= ?
		ORDER BY started_at DESC LIMIT 100`

	rows, err := s.db.RawQuery(query, queryEmail, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("audit: list orders: %w", err)
	}
	defer rows.Close()

	var results []*ToolCall
	for rows.Next() {
		tc, err := scanToolCall(rows, s.encryptionKey)
		if err != nil {
			return nil, err
		}
		results = append(results, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate order rows: %w", err)
	}
	return results, nil
}

// GetOrderAttribution returns the tool call that placed the given order and
// all other tool calls from the same session in the 60 seconds before the order,
// providing a decision trace that shows how the AI arrived at the trade.
func (s *Store) GetOrderAttribution(email, orderID string) ([]*ToolCall, error) {
	queryEmail := s.hmacEmail(email)

	// Step 1: find the tool call with this order_id
	orderQuery := `SELECT session_id, started_at
		FROM tool_calls
		WHERE email = ? AND order_id = ?
		LIMIT 1`
	var sessionID, startedAtS string
	err := s.db.QueryRow(orderQuery, queryEmail, orderID).Scan(&sessionID, &startedAtS)
	if err != nil {
		return nil, fmt.Errorf("audit: order %s not found: %w", orderID, err)
	}

	orderTime, err := time.Parse(time.RFC3339Nano, startedAtS)
	if err != nil {
		return nil, fmt.Errorf("audit: parse order time: %w", err)
	}

	// Step 2: find all tool calls from the same session in the 60s before the order (inclusive)
	windowStart := orderTime.Add(-60 * time.Second)
	traceQuery := `SELECT id, call_id, email, session_id, tool_name, tool_category,
		input_params, input_summary, output_summary, output_size,
		is_error, error_message, error_type, order_id,
		email_encrypted, prev_hash, entry_hash,
		started_at, completed_at, duration_ms
		FROM tool_calls
		WHERE email = ? AND session_id = ? AND started_at >= ? AND started_at <= ?
		ORDER BY started_at ASC
		LIMIT 50`

	rows, err := s.db.RawQuery(traceQuery, queryEmail, sessionID,
		windowStart.Format(time.RFC3339Nano), orderTime.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("audit: get order attribution: %w", err)
	}
	defer rows.Close()

	var results []*ToolCall
	for rows.Next() {
		tc, err := scanToolCall(rows, s.encryptionKey)
		if err != nil {
			return nil, err
		}
		results = append(results, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate attribution rows: %w", err)
	}
	return results, nil
}

// DeleteOlderThan removes tool_calls older than the given time.
// If hash chaining is active, a chain-break marker is inserted before the
// deletion to preserve chain continuity for verification.
// Returns the number of rows deleted (excluding the marker).
func (s *Store) DeleteOlderThan(before time.Time) (int64, error) {
	// Capture the hash of the last entry being deleted so the marker can reference it.
	var lastDeletedHash string
	if s.hashKey != nil {
		_ = s.db.QueryRow(
			"SELECT entry_hash FROM tool_calls WHERE started_at < ? ORDER BY id DESC LIMIT 1",
			before.Format(time.RFC3339Nano),
		).Scan(&lastDeletedHash)
	}

	result, err := s.db.ExecResult("DELETE FROM tool_calls WHERE started_at < ?", before.Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("audit: delete older than %s: %w", before.Format(time.RFC3339), err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	// Insert a chain-break marker so VerifyChain knows about the gap.
	if deleted > 0 && lastDeletedHash != "" && s.hashKey != nil {
		now := time.Now().UTC()
		marker := &ToolCall{
			CallID:       uuid.New().String(),
			ToolName:     "__chain_break",
			ToolCategory: "system",
			InputSummary: fmt.Sprintf("Retention cleanup: deleted %d entries before %s", deleted, before.Format(time.RFC3339)),
			StartedAt:    now,
			CompletedAt:  now,
		}
		// Set PrevHash to the last deleted entry's hash.
		marker.PrevHash = lastDeletedHash
		// Compute this marker's own hash.
		mac := hmac.New(sha256.New, s.hashKey)
		mac.Write([]byte(marker.PrevHash + marker.CallID + marker.Email + marker.ToolName + marker.StartedAt.Format(time.RFC3339Nano)))
		marker.EntryHash = hex.EncodeToString(mac.Sum(nil))

		// Update chain state under lock.
		s.chainMu.Lock()
		s.lastHash = marker.EntryHash
		s.chainMu.Unlock()

		if recErr := s.Record(marker); recErr != nil {
			if s.logger != nil {
				s.logger.Error("Failed to insert chain-break marker", "error", recErr)
			}
		}
	}

	return deleted, nil
}

// Stats holds aggregate metrics for a set of audit trail entries.
type Stats struct {
	TotalCalls   int     `json:"total_calls"`
	ErrorCount   int     `json:"error_count"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	TopTool      string  `json:"top_tool"`
	TopToolCount int     `json:"top_tool_count"`
}

// GetStats returns aggregate stats for a given email since the given time.
// If since is zero, all records are included. Optional category and errorsOnly
// filters scope the stats to match the user's active filters.
func (s *Store) GetStats(email string, since time.Time, category string, errorsOnly bool) (*Stats, error) {
	var where []string
	var args []any

	queryEmail := s.hmacEmail(email)
	where = append(where, "email = ?")
	args = append(args, queryEmail)

	if !since.IsZero() {
		where = append(where, "started_at >= ?")
		args = append(args, since.Format(time.RFC3339Nano))
	}
	if category != "" {
		where = append(where, "tool_category = ?")
		args = append(args, category)
	}
	if errorsOnly {
		where = append(where, "is_error = 1")
	}

	whereClause := strings.Join(where, " AND ")

	// Aggregate: total, error count, avg latency
	aggQuery := "SELECT COUNT(*), COALESCE(SUM(is_error), 0), COALESCE(AVG(duration_ms), 0) FROM tool_calls WHERE " + whereClause
	var totalCalls, errorCount int
	var avgLatency float64
	if err := s.db.QueryRow(aggQuery, args...).Scan(&totalCalls, &errorCount, &avgLatency); err != nil {
		return nil, fmt.Errorf("audit: stats aggregate: %w", err)
	}

	// Top tool by count
	topQuery := "SELECT tool_name, COUNT(*) AS cnt FROM tool_calls WHERE " + whereClause +
		" GROUP BY tool_name ORDER BY cnt DESC LIMIT 1"
	var topTool string
	var topToolCount int
	row := s.db.QueryRow(topQuery, args...)
	if err := row.Scan(&topTool, &topToolCount); err != nil {
		if err == sql.ErrNoRows {
			topTool = ""
			topToolCount = 0
		} else {
			return nil, fmt.Errorf("audit: stats top tool: %w", err)
		}
	}

	return &Stats{
		TotalCalls:   totalCalls,
		ErrorCount:   errorCount,
		AvgLatencyMs: avgLatency,
		TopTool:      topTool,
		TopToolCount: topToolCount,
	}, nil
}

// GetToolCounts returns tool_name -> count for the given email since the given time.
// Results are ordered by count descending, limited to the top 20 tools.
// Optional category and errorsOnly filters scope results to match the user's active filters.
func (s *Store) GetToolCounts(email string, since time.Time, category string, errorsOnly bool) (map[string]int, error) {
	var where []string
	var args []any

	queryEmail := s.hmacEmail(email)
	where = append(where, "email = ?")
	args = append(args, queryEmail)

	if !since.IsZero() {
		where = append(where, "started_at >= ?")
		args = append(args, since.Format(time.RFC3339Nano))
	}
	if category != "" {
		where = append(where, "tool_category = ?")
		args = append(args, category)
	}
	if errorsOnly {
		where = append(where, "is_error = 1")
	}

	whereClause := strings.Join(where, " AND ")
	query := "SELECT tool_name, COUNT(*) AS cnt FROM tool_calls WHERE " + whereClause +
		" GROUP BY tool_name ORDER BY cnt DESC LIMIT 20"

	rows, err := s.db.RawQuery(query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: get tool counts: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, fmt.Errorf("audit: scan tool count: %w", err)
		}
		result[name] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate tool counts: %w", err)
	}
	return result, nil
}

// ToolMetric holds per-tool aggregate metrics for observability.
type ToolMetric struct {
	ToolName   string  `json:"tool_name"`
	CallCount  int     `json:"call_count"`
	AvgMs      float64 `json:"avg_ms"`
	MaxMs      int64   `json:"max_ms"`
	ErrorCount int     `json:"error_count"`
}

// GetToolMetrics returns per-tool aggregate metrics (call count, avg/max latency,
// error count) for all tool calls since the given time. Results are ordered by
// call count descending, limited to the top 50 tools.
func (s *Store) GetToolMetrics(since time.Time) ([]ToolMetric, error) {
	query := `SELECT tool_name,
		COUNT(*) AS calls,
		COALESCE(AVG(duration_ms), 0) AS avg_ms,
		COALESCE(MAX(duration_ms), 0) AS max_ms,
		COALESCE(SUM(CASE WHEN is_error = 1 THEN 1 ELSE 0 END), 0) AS errors
		FROM tool_calls
		WHERE started_at > ? AND tool_name != '__chain_break'
		GROUP BY tool_name
		ORDER BY calls DESC
		LIMIT 50`

	rows, err := s.db.RawQuery(query, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("audit: get tool metrics: %w", err)
	}
	defer rows.Close()

	var results []ToolMetric
	for rows.Next() {
		var m ToolMetric
		if err := rows.Scan(&m.ToolName, &m.CallCount, &m.AvgMs, &m.MaxMs, &m.ErrorCount); err != nil {
			return nil, fmt.Errorf("audit: scan tool metric: %w", err)
		}
		results = append(results, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate tool metrics: %w", err)
	}
	return results, nil
}

// GetGlobalStats returns aggregate stats across all users since the given time.
func (s *Store) GetGlobalStats(since time.Time) (*Stats, error) {
	sinceStr := since.Format(time.RFC3339Nano)

	aggQuery := "SELECT COUNT(*), COALESCE(SUM(is_error), 0), COALESCE(AVG(duration_ms), 0) FROM tool_calls WHERE started_at >= ? AND tool_name != '__chain_break'"
	var totalCalls, errorCount int
	var avgLatency float64
	if err := s.db.QueryRow(aggQuery, sinceStr).Scan(&totalCalls, &errorCount, &avgLatency); err != nil {
		return nil, fmt.Errorf("audit: global stats aggregate: %w", err)
	}

	topQuery := "SELECT tool_name, COUNT(*) AS cnt FROM tool_calls WHERE started_at >= ? AND tool_name != '__chain_break' GROUP BY tool_name ORDER BY cnt DESC LIMIT 1"
	var topTool string
	var topToolCount int
	row := s.db.QueryRow(topQuery, sinceStr)
	if err := row.Scan(&topTool, &topToolCount); err != nil {
		if err == sql.ErrNoRows {
			topTool = ""
			topToolCount = 0
		} else {
			return nil, fmt.Errorf("audit: global stats top tool: %w", err)
		}
	}

	return &Stats{
		TotalCalls:   totalCalls,
		ErrorCount:   errorCount,
		AvgLatencyMs: avgLatency,
		TopTool:      topTool,
		TopToolCount: topToolCount,
	}, nil
}

// UserErrorCount holds a per-user error count.
type UserErrorCount struct {
	Email      string `json:"email"`
	ErrorCount int    `json:"error_count"`
}

// GetTopErrorUsers returns the top N users with the most errors since the given time.
// Email values are decrypted if an encryption key is configured.
func (s *Store) GetTopErrorUsers(since time.Time, limit int) ([]UserErrorCount, error) {
	if limit <= 0 {
		limit = 5
	}
	sinceStr := since.Format(time.RFC3339Nano)

	// Query groups by email column (which may be HMAC-hashed).
	// We also grab email_encrypted so we can decrypt for display.
	query := `SELECT email, COALESCE(email_encrypted, '') AS enc, COUNT(*) AS error_count
		FROM tool_calls
		WHERE is_error = 1 AND started_at >= ? AND tool_name != '__chain_break'
		GROUP BY email
		ORDER BY error_count DESC
		LIMIT ?`

	rows, err := s.db.RawQuery(query, sinceStr, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: get top error users: %w", err)
	}
	defer rows.Close()

	var results []UserErrorCount
	for rows.Next() {
		var emailRaw, emailEnc string
		var count int
		if err := rows.Scan(&emailRaw, &emailEnc, &count); err != nil {
			return nil, fmt.Errorf("audit: scan top error user: %w", err)
		}
		// Decrypt email for display if possible.
		displayEmail := emailRaw
		if s.encryptionKey != nil && emailEnc != "" {
			if decrypted := alerts.Decrypt(s.encryptionKey, emailEnc); decrypted != "" {
				displayEmail = decrypted
			}
		}
		results = append(results, UserErrorCount{Email: displayEmail, ErrorCount: count})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate top error users: %w", err)
	}
	return results, nil
}

// --- SSE Listener support for real-time activity streaming ---

// AddActivityListener registers a buffered channel that receives new ToolCall entries as they are recorded.
func (s *Store) AddActivityListener(id string) chan *ToolCall {
	ch := make(chan *ToolCall, 100)
	s.listenerMu.Lock()
	if s.activityListeners == nil {
		s.activityListeners = make(map[string]chan *ToolCall)
	}
	s.activityListeners[id] = ch
	s.listenerMu.Unlock()
	return ch
}

// RemoveActivityListener unregisters a listener by id and closes its channel.
func (s *Store) RemoveActivityListener(id string) {
	s.listenerMu.Lock()
	ch, exists := s.activityListeners[id]
	delete(s.activityListeners, id)
	s.listenerMu.Unlock()
	if exists {
		close(ch)
	}
}

// broadcastToListeners fans out a tool call entry to all registered activity listeners.
func (s *Store) broadcastToListeners(entry *ToolCall) {
	s.listenerMu.RLock()
	for _, ch := range s.activityListeners {
		select {
		case ch <- entry:
		default:
		}
	}
	s.listenerMu.RUnlock()
}

// ChainVerification holds the result of VerifyChain.
type ChainVerification struct {
	Valid      bool   `json:"valid"`
	BrokenAt  int64  `json:"broken_at_id,omitempty"` // ID of the first entry with a mismatched hash
	Total     int    `json:"total_entries"`
	Verified  int    `json:"verified_entries"`
	Message   string `json:"message"`
}

// VerifyChain walks every entry in id order, recomputes HMAC hashes, and
// compares them with the stored entry_hash. Chain-break markers
// (tool_name = "__chain_break") are expected discontinuities and reset the
// expected prev_hash.
func (s *Store) VerifyChain() (*ChainVerification, error) {
	if s.hashKey == nil {
		return &ChainVerification{Valid: false, Message: "hash chaining not configured (no encryption key)"}, nil
	}

	rows, err := s.db.RawQuery(
		"SELECT id, call_id, email, tool_name, started_at, prev_hash, entry_hash FROM tool_calls ORDER BY id ASC",
	)
	if err != nil {
		return nil, fmt.Errorf("audit: verify chain query: %w", err)
	}
	defer rows.Close()

	var (
		expectedPrev string
		total        int
		verified     int
		first        = true
	)

	for rows.Next() {
		var (
			id                                    int64
			callID, email, toolName, startedAtStr string
			prevHash, entryHash                   sql.NullString
		)
		if err := rows.Scan(&id, &callID, &email, &toolName, &startedAtStr, &prevHash, &entryHash); err != nil {
			return nil, fmt.Errorf("audit: verify chain scan: %w", err)
		}
		total++

		storedPrev := prevHash.String
		storedHash := entryHash.String

		// Legacy rows without hashes — skip but count.
		if storedHash == "" {
			// Reset chain expectation; the next hashed entry becomes a new anchor.
			expectedPrev = ""
			continue
		}

		// Chain-break marker: accept any prev_hash and reset the chain.
		if toolName == "__chain_break" {
			// Recompute and verify the marker's own hash.
			startedAt, _ := time.Parse(time.RFC3339Nano, startedAtStr)
			mac := hmac.New(sha256.New, s.hashKey)
			mac.Write([]byte(storedPrev + callID + email + toolName + startedAt.Format(time.RFC3339Nano)))
			recomputed := hex.EncodeToString(mac.Sum(nil))
			if recomputed != storedHash {
				return &ChainVerification{
					Valid:    false,
					BrokenAt: id,
					Total:    total,
					Verified: verified,
					Message:  fmt.Sprintf("chain-break marker at id %d has tampered entry_hash", id),
				}, nil
			}
			expectedPrev = storedHash
			verified++
			continue
		}

		// Normal entry: verify prev_hash matches expected.
		if !first && expectedPrev != "" && storedPrev != expectedPrev {
			return &ChainVerification{
				Valid:    false,
				BrokenAt: id,
				Total:    total,
				Verified: verified,
				Message:  fmt.Sprintf("prev_hash mismatch at id %d", id),
			}, nil
		}

		// Recompute entry_hash.
		startedAt, _ := time.Parse(time.RFC3339Nano, startedAtStr)
		mac := hmac.New(sha256.New, s.hashKey)
		mac.Write([]byte(storedPrev + callID + email + toolName + startedAt.Format(time.RFC3339Nano)))
		recomputed := hex.EncodeToString(mac.Sum(nil))
		if recomputed != storedHash {
			return &ChainVerification{
				Valid:    false,
				BrokenAt: id,
				Total:    total,
				Verified: verified,
				Message:  fmt.Sprintf("entry_hash mismatch at id %d (tampered data)", id),
			}, nil
		}

		expectedPrev = storedHash
		verified++
		first = false
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify chain iterate: %w", err)
	}

	return &ChainVerification{
		Valid:    true,
		Total:    total,
		Verified: verified,
		Message:  "chain integrity verified",
	}, nil
}
