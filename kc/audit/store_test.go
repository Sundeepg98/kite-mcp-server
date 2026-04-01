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
