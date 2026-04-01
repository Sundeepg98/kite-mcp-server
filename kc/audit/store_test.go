package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// openTestStore creates an in-memory SQLite DB, initialises the audit table,
// and returns a ready-to-use *Store. It registers cleanup automatically.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	s := New(db)
	require.NoError(t, s.InitTable())
	return s
}

// makeEntry is a helper that creates a ToolCall with sensible defaults.
// Callers can override fields after calling this.
func makeEntry(callID, email, toolName, category string, isError bool, startedAt time.Time) *ToolCall {
	dur := 42 * time.Millisecond
	return &ToolCall{
		CallID:        callID,
		Email:         email,
		SessionID:     "sess-001",
		ToolName:      toolName,
		ToolCategory:  category,
		InputParams:   `{"symbol":"INFY"}`,
		InputSummary:  "place order INFY",
		OutputSummary: "order placed",
		OutputSize:    128,
		IsError:       isError,
		ErrorMessage:  "",
		ErrorType:     "",
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(dur),
		DurationMs:    dur.Milliseconds(),
	}
}

func TestStore_RecordAndList(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("call-001", "alice@example.com", "place_order", "order", false, now)
	entry.InputParams = `{"exchange":"NSE","symbol":"INFY","qty":10}`
	entry.InputSummary = "BUY INFY x10"
	entry.OutputSummary = "Order 12345 placed"
	entry.OutputSize = 256
	entry.ErrorMessage = ""
	entry.ErrorType = ""

	// Record
	err := s.Record(entry)
	require.NoError(t, err)

	// List
	results, total, err := s.List("alice@example.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)

	got := results[0]
	assert.Equal(t, "call-001", got.CallID)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "sess-001", got.SessionID)
	assert.Equal(t, "place_order", got.ToolName)
	assert.Equal(t, "order", got.ToolCategory)
	assert.Equal(t, `{"exchange":"NSE","symbol":"INFY","qty":10}`, got.InputParams)
	assert.Equal(t, "BUY INFY x10", got.InputSummary)
	assert.Equal(t, "Order 12345 placed", got.OutputSummary)
	assert.Equal(t, 256, got.OutputSize)
	assert.False(t, got.IsError)
	assert.Equal(t, "", got.ErrorMessage)
	assert.Equal(t, "", got.ErrorType)
	assert.Equal(t, now, got.StartedAt)
	assert.Equal(t, now.Add(42*time.Millisecond), got.CompletedAt)
	assert.Equal(t, int64(42), got.DurationMs)
	assert.True(t, got.ID > 0, "auto-increment ID should be positive")
}

func TestStore_ListWithFilters(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "bob@example.com"
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

	// Insert 5 entries:
	//   0: order, no error, T+0min
	//   1: order, no error, T+1min
	//   2: order, no error, T+2min
	//   3: query, no error, T+3min
	//   4: order, error,    T+4min
	entries := []*ToolCall{
		makeEntry("c-0", email, "place_order", "order", false, base),
		makeEntry("c-1", email, "modify_order", "order", false, base.Add(1*time.Minute)),
		makeEntry("c-2", email, "cancel_order", "order", false, base.Add(2*time.Minute)),
		makeEntry("c-3", email, "get_positions", "query", false, base.Add(3*time.Minute)),
		makeEntry("c-4", email, "place_order", "order", true, base.Add(4*time.Minute)),
	}
	entries[4].ErrorMessage = "insufficient funds"
	entries[4].ErrorType = "validation"

	for _, e := range entries {
		require.NoError(t, s.Record(e))
	}

	// --- Filter by category "order" ---
	results, total, err := s.List(email, ListOptions{Category: "order"})
	require.NoError(t, err)
	assert.Equal(t, 4, total, "4 entries in category 'order'")
	assert.Len(t, results, 4)

	// --- Filter errors only ---
	results, total, err = s.List(email, ListOptions{OnlyErrors: true})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "1 error entry")
	require.Len(t, results, 1)
	assert.Equal(t, "c-4", results[0].CallID)
	assert.True(t, results[0].IsError)
	assert.Equal(t, "insufficient funds", results[0].ErrorMessage)
	assert.Equal(t, "validation", results[0].ErrorType)

	// --- Filter by time range [T+1min, T+3min] ---
	results, total, err = s.List(email, ListOptions{
		Since: base.Add(1 * time.Minute),
		Until: base.Add(3 * time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "entries at T+1, T+2, T+3")
	assert.Len(t, results, 3)

	// --- Pagination: limit 2, offset 0 ---
	results, total, err = s.List(email, ListOptions{Limit: 2, Offset: 0})
	require.NoError(t, err)
	assert.Equal(t, 5, total, "total should be all 5 regardless of limit")
	assert.Len(t, results, 2, "limited to 2 results")
	// Results are ordered by started_at DESC, so the newest first.
	assert.Equal(t, "c-4", results[0].CallID)
	assert.Equal(t, "c-3", results[1].CallID)

	// --- Pagination: limit 2, offset 2 ---
	results, total, err = s.List(email, ListOptions{Limit: 2, Offset: 2})
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, results, 2)
	assert.Equal(t, "c-2", results[0].CallID)
	assert.Equal(t, "c-1", results[1].CallID)

	// --- Different user sees nothing ---
	results, total, err = s.List("stranger@example.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)
}

func TestStore_GetStats(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "stats@example.com"
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

	// Insert entries with varying tools, durations, and error states.
	entries := []*ToolCall{
		makeEntry("s-0", email, "get_holdings", "query", false, base),
		makeEntry("s-1", email, "get_holdings", "query", false, base.Add(1*time.Minute)),
		makeEntry("s-2", email, "place_order", "order", false, base.Add(2*time.Minute)),
		makeEntry("s-3", email, "get_ltp", "market_data", true, base.Add(3*time.Minute)),
		makeEntry("s-4", email, "get_holdings", "query", false, base.Add(4*time.Minute)),
	}
	// Customize durations.
	entries[0].DurationMs = 100
	entries[1].DurationMs = 200
	entries[2].DurationMs = 300
	entries[3].DurationMs = 50
	entries[3].ErrorMessage = "token expired"
	entries[4].DurationMs = 150

	for _, e := range entries {
		require.NoError(t, s.Record(e))
	}

	// Stats for all entries.
	stats, err := s.GetStats(email, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 5, stats.TotalCalls)
	assert.Equal(t, 1, stats.ErrorCount)
	assert.InDelta(t, 160.0, stats.AvgLatencyMs, 0.5) // (100+200+300+50+150)/5 = 160
	assert.Equal(t, "get_holdings", stats.TopTool)
	assert.Equal(t, 3, stats.TopToolCount)

	// Stats with a since filter (only entries at T+2min and later).
	stats, err = s.GetStats(email, base.Add(2*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalCalls)
	assert.Equal(t, 1, stats.ErrorCount)

	// Stats for a different user — empty.
	stats, err = s.GetStats("nobody@example.com", time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalCalls)
	assert.Equal(t, 0, stats.ErrorCount)
	assert.Equal(t, "", stats.TopTool)
}

func TestStore_EnqueueAndWorker(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.StartWorker()

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("enq-001", "worker@example.com", "get_ltp", "market_data", false, now)

	s.Enqueue(entry)

	// Stop drains the buffer and waits for completion.
	s.Stop()

	// Verify the entry was written.
	results, total, err := s.List("worker@example.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "enq-001", results[0].CallID)
}

func TestStore_EnqueueWithoutWorker(t *testing.T) {
	// When StartWorker is not called, Enqueue falls back to synchronous write.
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("sync-001", "sync@example.com", "get_ltp", "market_data", false, now)

	s.Enqueue(entry)

	results, total, err := s.List("sync@example.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "sync-001", results[0].CallID)
}

func TestStore_DeleteOlderThan(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Insert old and new entries
	oldEntry := makeEntry("old-001", "retention@test.com", "get_ltp", "market_data", false, now.Add(-100*24*time.Hour))
	newEntry := makeEntry("new-001", "retention@test.com", "get_ltp", "market_data", false, now)

	require.NoError(t, s.Record(oldEntry))
	require.NoError(t, s.Record(newEntry))

	// Verify both exist
	results, total, err := s.List("retention@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, results, 2)

	// Delete entries older than 50 days ago
	cutoff := now.Add(-50 * 24 * time.Hour)
	deleted, err := s.DeleteOlderThan(cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "expected 1 row deleted")

	// Verify only the new entry remains
	results, total, err = s.List("retention@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "expected 1 remaining")
	require.Len(t, results, 1)
	assert.Equal(t, "new-001", results[0].CallID)
}

func TestStore_DeleteOlderThan_NoRows(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	// Nothing to delete on an empty table
	deleted, err := s.DeleteOlderThan(time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestStore_RecordDuplicate(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("dup-001", "carol@example.com", "get_ltp", "query", false, now)

	// First insert.
	err := s.Record(entry)
	require.NoError(t, err)

	// Second insert with the same call_id should not error (INSERT OR IGNORE).
	entry2 := makeEntry("dup-001", "carol@example.com", "get_ltp", "query", false, now.Add(time.Second))
	err = s.Record(entry2)
	require.NoError(t, err, "duplicate call_id should not cause an error")

	// Only one row should exist.
	results, total, err := s.List("carol@example.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	// The first insert's data should be preserved (IGNORE means the second is dropped).
	assert.Equal(t, now, results[0].StartedAt)
}
