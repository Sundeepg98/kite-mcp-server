// Package audit provides SQLite-backed persistence for MCP tool call audit records.
package audit

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
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
	InputParams   string    `json:"input_params"`   // JSON-encoded parameters
	InputSummary  string    `json:"input_summary"`
	OutputSummary string    `json:"output_summary"`
	OutputSize    int       `json:"output_size"`
	IsError       bool      `json:"is_error"`
	ErrorMessage  string    `json:"error_message"`
	ErrorType     string    `json:"error_type"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	DurationMs    int64     `json:"duration_ms"`
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
	db      *alerts.DB
	writeCh chan *ToolCall
	done    chan struct{}
	logger  *slog.Logger
}

// New creates a new audit Store using the given database handle.
func New(db *alerts.DB) *Store {
	return &Store{db: db}
}

// SetLogger assigns a structured logger for background worker diagnostics.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// StartWorker starts a background goroutine that drains the write channel.
// Call Stop() to gracefully drain and close.
func (s *Store) StartWorker() {
	s.writeCh = make(chan *ToolCall, auditBufferSize)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for entry := range s.writeCh {
			if err := s.Record(entry); err != nil {
				if s.logger != nil {
					s.logger.Error("Audit write failed", "error", err, "call_id", entry.CallID)
				}
			}
		}
	}()
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
	return nil
}

// Record inserts a tool call entry into the audit log.
// Duplicate call_ids are silently ignored (INSERT OR IGNORE).
func (s *Store) Record(entry *ToolCall) error {
	isErr := 0
	if entry.IsError {
		isErr = 1
	}
	query := `INSERT OR IGNORE INTO tool_calls
		(call_id, email, session_id, tool_name, tool_category,
		 input_params, input_summary, output_summary, output_size,
		 is_error, error_message, error_type,
		 started_at, completed_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	err := s.db.ExecInsert(query,
		entry.CallID,
		entry.Email,
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

	where = append(where, "email = ?")
	args = append(args, email)

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
		"is_error, error_message, error_type, started_at, completed_at, duration_ms " +
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
		tc, err := scanToolCall(rows)
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
func scanToolCall(rows *sql.Rows) (*ToolCall, error) {
	var tc ToolCall
	var (
		isErr                                              int
		inputParams, inputSummary, outputSummary           sql.NullString
		errorMessage, errorType                            sql.NullString
		startedAtS, completedAtS                           string
	)
	if err := rows.Scan(
		&tc.ID, &tc.CallID, &tc.Email, &tc.SessionID,
		&tc.ToolName, &tc.ToolCategory,
		&inputParams, &inputSummary, &outputSummary, &tc.OutputSize,
		&isErr, &errorMessage, &errorType,
		&startedAtS, &completedAtS, &tc.DurationMs,
	); err != nil {
		return nil, fmt.Errorf("audit: scan tool call: %w", err)
	}

	tc.IsError = isErr != 0
	tc.InputParams = inputParams.String
	tc.InputSummary = inputSummary.String
	tc.OutputSummary = outputSummary.String
	tc.ErrorMessage = errorMessage.String
	tc.ErrorType = errorType.String

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

// DeleteOlderThan removes tool_calls older than the given time.
// Returns the number of rows deleted.
func (s *Store) DeleteOlderThan(before time.Time) (int64, error) {
	result, err := s.db.ExecResult("DELETE FROM tool_calls WHERE started_at < ?", before.Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("audit: delete older than %s: %w", before.Format(time.RFC3339), err)
	}
	return result.RowsAffected()
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
// If since is zero, all records are included.
func (s *Store) GetStats(email string, since time.Time) (*Stats, error) {
	var where []string
	var args []any

	where = append(where, "email = ?")
	args = append(args, email)

	if !since.IsZero() {
		where = append(where, "started_at >= ?")
		args = append(args, since.Format(time.RFC3339Nano))
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
