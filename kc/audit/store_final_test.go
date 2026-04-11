package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// -----------------------------------------------------------------------
// Closed-DB mid-iteration tests (rows.Err paths)
// -----------------------------------------------------------------------

// closedAuditStore creates a Store backed by a DB that is then closed,
// but still has seeded data to trigger rows.Err on iteration.
func closedAuditStore(t *testing.T) *Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	s := New(db)
	require.NoError(t, s.InitTable())

	// Seed some data so queries will attempt row iteration.
	for i := 0; i < 3; i++ {
		entry := makeEntry("call-"+string(rune('A'+i)), "user@test.com", "tool_a", "trading", false, time.Now())
		require.NoError(t, s.Record(entry))
	}

	// Close the underlying DB so iterating rows will fail.
	db.Close()
	return s
}

func TestList_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	_, _, err := s.List("user@test.com", ListOptions{Limit: 10})
	assert.Error(t, err)
}

func TestListOrders_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.ListOrders("user@test.com", time.Time{})
	assert.Error(t, err)
}

func TestGetOrderAttribution_ClosedDB_Final(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetOrderAttribution("user@test.com", "ORD-001")
	assert.Error(t, err)
}

func TestDeleteOlderThan_ClosedDB_Final(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.DeleteOlderThan(time.Now())
	assert.Error(t, err)
}

func TestGetStats_ClosedDB_TopToolErr(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetStats("user@test.com", time.Time{}, "", false)
	assert.Error(t, err)
}

func TestGetToolCounts_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetToolCounts("user@test.com", time.Time{}, "", false)
	assert.Error(t, err)
}

func TestGetToolMetrics_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetToolMetrics(time.Time{})
	assert.Error(t, err)
}

func TestGetGlobalStats_ClosedDB_Final(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetGlobalStats(time.Time{})
	assert.Error(t, err)
}

func TestGetTopErrorUsers_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	_, err := s.GetTopErrorUsers(time.Time{}, 5)
	assert.Error(t, err)
}

func TestVerifyChain_ClosedDB_RowsErr(t *testing.T) {
	s := closedAuditStore(t)
	s.SetEncryptionKey([]byte("test-key-for-chain-verify-32byte"))
	_, err := s.VerifyChain()
	assert.Error(t, err)
}

// -----------------------------------------------------------------------
// scanToolCall error paths
// -----------------------------------------------------------------------

func TestList_ScanToolCallError_BadTimestamp(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	s := New(db)
	require.NoError(t, s.InitTable())

	// Insert a row with an invalid started_at timestamp directly.
	_, err = db.ExecResult(`INSERT INTO tool_calls (call_id, email, session_id, tool_name, tool_category,
		input_params, input_summary, output_summary, output_size,
		is_error, error_message, error_type, order_id,
		email_encrypted, prev_hash, entry_hash,
		started_at, completed_at, duration_ms)
		VALUES ('bad-ts', 'user@test.com', 'sess', 'tool', 'cat',
		'', '', '', 0,
		0, '', '', '',
		'', '', '',
		'NOT-A-TIMESTAMP', '2026-01-01T00:00:00Z', 0)`)
	require.NoError(t, err)

	_, _, err = s.List("user@test.com", ListOptions{Limit: 10})
	assert.Error(t, err, "should fail on bad started_at")
	assert.Contains(t, err.Error(), "parse started_at")
}

func TestList_ScanToolCallError_BadCompletedAt(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	s := New(db)
	require.NoError(t, s.InitTable())

	_, err = db.ExecResult(`INSERT INTO tool_calls (call_id, email, session_id, tool_name, tool_category,
		input_params, input_summary, output_summary, output_size,
		is_error, error_message, error_type, order_id,
		email_encrypted, prev_hash, entry_hash,
		started_at, completed_at, duration_ms)
		VALUES ('bad-ct', 'user@test.com', 'sess', 'tool', 'cat',
		'', '', '', 0,
		0, '', '', '',
		'', '', '',
		'2026-01-01T00:00:00Z', 'NOT-A-TIMESTAMP', 0)`)
	require.NoError(t, err)

	_, _, err = s.List("user@test.com", ListOptions{Limit: 10})
	assert.Error(t, err, "should fail on bad completed_at")
	assert.Contains(t, err.Error(), "parse completed_at")
}

// -----------------------------------------------------------------------
// DeleteOlderThan: Record error for chain-break marker
// -----------------------------------------------------------------------

func TestDeleteOlderThan_ChainBreakRecordError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	s := New(db)
	require.NoError(t, s.InitTable())
	s.SetEncryptionKey([]byte("test-key-for-chain-verify-32byte"))
	s.SeedChain()

	// Seed an entry in the past.
	entry := makeEntry("old-1", "user@test.com", "tool_a", "trading", false, time.Now().Add(-24*time.Hour))
	require.NoError(t, s.Record(entry))

	// Close the DB so the Record call for the chain-break marker fails.
	db.Close()

	// DeleteOlderThan will try to delete + insert a chain-break marker and fail.
	_, err = s.DeleteOlderThan(time.Now())
	assert.Error(t, err)
}

// -----------------------------------------------------------------------
// GetOrderAttribution: parse time error
// -----------------------------------------------------------------------

func TestGetOrderAttribution_BadTimestamp(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	s := New(db)
	require.NoError(t, s.InitTable())

	// Insert an order with a bad started_at.
	_, err = db.ExecResult(`INSERT INTO tool_calls (call_id, email, session_id, tool_name, tool_category,
		input_params, input_summary, output_summary, output_size,
		is_error, error_message, error_type, order_id,
		email_encrypted, prev_hash, entry_hash,
		started_at, completed_at, duration_ms)
		VALUES ('ord-ts', 'user@test.com', 'sess', 'place_order', 'trading',
		'', '', '', 0,
		0, '', '', 'ORD-BAD',
		'', '', '',
		'NOT-A-TIMESTAMP', '2026-01-01T00:00:00Z', 0)`)
	require.NoError(t, err)

	_, err = s.GetOrderAttribution("user@test.com", "ORD-BAD")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse order time")
}
