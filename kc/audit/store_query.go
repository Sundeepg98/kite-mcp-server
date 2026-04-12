package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

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
		isErr                                    int
		inputParams, inputSummary, outputSummary sql.NullString
		errorMessage, errorType, orderID         sql.NullString
		emailEncrypted, prevHash, entryHash      sql.NullString
		startedAtS, completedAtS                 string
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

// ChainVerification holds the result of VerifyChain.
type ChainVerification struct {
	Valid    bool   `json:"valid"`
	BrokenAt int64  `json:"broken_at_id,omitempty"` // ID of the first entry with a mismatched hash
	Total    int    `json:"total_entries"`
	Verified int    `json:"verified_entries"`
	Message  string `json:"message"`
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
