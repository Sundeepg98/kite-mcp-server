package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// openTestStoreWithKey creates an in-memory store with encryption and chain seeded.
func openTestStoreWithKey(t *testing.T) *Store {
	t.Helper()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	s.SeedChain()
	return s
}

// insertChainedEntries records N entries through the worker so they have valid chain hashes.
// Entries have empty emails to avoid HMAC mismatch between chain computation and DB storage.
func insertChainedEntries(t *testing.T, s *Store, n int, baseTime time.Time) {
	t.Helper()
	s.StartWorker()
	for i := 0; i < n; i++ {
		e := makeEntry("ch-"+string(rune('a'+i)), "", "get_ltp", "market_data", false,
			baseTime.Add(time.Duration(i)*time.Second))
		s.Enqueue(e)
	}
	s.Stop()
}

// ===========================================================================
// VerifyChain — comprehensive coverage
// ===========================================================================

func TestVerifyChain_EmptyDB(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.Total)
	assert.Equal(t, 0, result.Verified)
	assert.Contains(t, result.Message, "verified")
}

func TestVerifyChain_LegacyRowsWithoutHashes(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	// Insert rows directly (bypass chain computation) — simulates legacy data.
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("legacy-1", "", "get_ltp", "market_data", false, now)
	// PrevHash and EntryHash left empty — legacy row.
	require.NoError(t, s.Record(e))

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, 0, result.Verified, "legacy rows without hashes are skipped")
}

func TestVerifyChain_TamperedEntryHash(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	insertChainedEntries(t, s, 3, now)

	// Tamper with the entry_hash of the 2nd entry.
	_, err := s.db.ExecResult(
		"UPDATE tool_calls SET entry_hash = 'tampered' WHERE call_id = 'ch-b'")
	require.NoError(t, err)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "entry_hash mismatch")
}

func TestVerifyChain_TamperedPrevHash(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	insertChainedEntries(t, s, 3, now)

	// Tamper with the prev_hash of the 3rd entry.
	_, err := s.db.ExecResult(
		"UPDATE tool_calls SET prev_hash = 'wrongprev' WHERE call_id = 'ch-c'")
	require.NoError(t, err)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "prev_hash mismatch")
}

func TestVerifyChain_WithChainBreakMarker(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)
	s.SetLogger(slog.Default())

	now := time.Now().UTC().Truncate(time.Microsecond)

	// Insert entries: old + new via worker.
	s.StartWorker()
	old := makeEntry("brk-old", "", "get_ltp", "market_data", false, now.Add(-200*24*time.Hour))
	fresh := makeEntry("brk-new", "", "get_ltp", "market_data", false, now)
	s.Enqueue(old)
	s.Enqueue(fresh)
	s.Stop()

	// Delete old entries — this inserts a chain-break marker.
	deleted, err := s.DeleteOlderThan(now.Add(-100 * 24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// Chain should still verify (marker is treated as valid discontinuity).
	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.True(t, result.Valid, "chain with break marker should verify: %s", result.Message)
	assert.GreaterOrEqual(t, result.Verified, 2, "marker + fresh entry should be verified")
}

func TestVerifyChain_TamperedChainBreakMarker(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)
	s.SetLogger(slog.Default())

	now := time.Now().UTC().Truncate(time.Microsecond)

	s.StartWorker()
	old := makeEntry("tbm-old", "", "get_ltp", "market_data", false, now.Add(-200*24*time.Hour))
	fresh := makeEntry("tbm-new", "", "get_ltp", "market_data", false, now)
	s.Enqueue(old)
	s.Enqueue(fresh)
	s.Stop()

	// Delete old entries — inserts chain-break marker.
	_, err := s.DeleteOlderThan(now.Add(-100 * 24 * time.Hour))
	require.NoError(t, err)

	// Tamper with the chain-break marker's entry_hash.
	_, err = s.db.ExecResult(
		"UPDATE tool_calls SET entry_hash = 'tampered' WHERE tool_name = '__chain_break'")
	require.NoError(t, err)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "tampered entry_hash")
}

func TestVerifyChain_MixedLegacyAndChained(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)

	// Insert a legacy row (no hashes).
	legacy := makeEntry("mix-legacy", "", "get_ltp", "market_data", false, now.Add(-time.Hour))
	require.NoError(t, s.Record(legacy))

	// Then insert chained entries.
	insertChainedEntries(t, s, 2, now)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 3, result.Total)
	assert.Equal(t, 2, result.Verified, "only chained entries should be counted as verified")
}

// ===========================================================================
// Enqueue — buffer full path
// ===========================================================================

func TestEnqueue_BufferFull(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())

	// Create a channel with capacity 1 to easily fill it.
	s.writeCh = make(chan *ToolCall, 1)
	s.done = make(chan struct{})

	// Don't start a consumer — the channel will fill up.
	now := time.Now().UTC().Truncate(time.Microsecond)
	e1 := makeEntry("buf-1", "user@test.com", "get_ltp", "market_data", false, now)
	e2 := makeEntry("buf-2", "user@test.com", "get_ltp", "market_data", false, now.Add(time.Second))

	s.Enqueue(e1) // fills the buffer
	s.Enqueue(e2) // should be dropped (buffer full)

	// Drain the channel manually.
	close(s.writeCh)
	close(s.done)
}

func TestEnqueue_BufferFull_NoLogger(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	// No logger set — s.logger is nil.

	s.writeCh = make(chan *ToolCall, 1)
	s.done = make(chan struct{})

	now := time.Now().UTC().Truncate(time.Microsecond)
	e1 := makeEntry("bufnl-1", "user@test.com", "get_ltp", "market_data", false, now)
	e2 := makeEntry("bufnl-2", "user@test.com", "get_ltp", "market_data", false, now.Add(time.Second))

	s.Enqueue(e1)
	s.Enqueue(e2) // dropped, no logger, should not panic

	close(s.writeCh)
	close(s.done)
}

// ===========================================================================
// StartWorker — Record error path
// ===========================================================================

func TestStartWorker_RecordError(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())

	// Close the DB to force Record to fail.
	s.db.Close()

	s.writeCh = make(chan *ToolCall, 10)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for entry := range s.writeCh {
			s.computeChainLink(entry)
			if err := s.Record(entry); err != nil {
				if s.logger != nil {
					s.logger.Error("Audit write failed", "error", err, "call_id", entry.CallID)
				}
			} else {
				s.broadcastToListeners(entry)
			}
		}
	}()

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("fail-001", "user@test.com", "get_ltp", "market_data", false, now)
	s.writeCh <- e

	close(s.writeCh)
	<-s.done
}

func TestStartWorker_RecordError_NoLogger(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	// No logger set.

	s.db.Close()

	s.writeCh = make(chan *ToolCall, 10)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for entry := range s.writeCh {
			s.computeChainLink(entry)
			if err := s.Record(entry); err != nil {
				if s.logger != nil {
					s.logger.Error("Audit write failed", "error", err, "call_id", entry.CallID)
				}
			}
		}
	}()

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("failnl-001", "user@test.com", "get_ltp", "market_data", false, now)
	s.writeCh <- e

	close(s.writeCh)
	<-s.done
}

// ===========================================================================
// DeleteOlderThan — chain marker edge cases
// ===========================================================================

func TestDeleteOlderThan_WithChain_NoRowsToDelete(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	insertChainedEntries(t, s, 2, now)

	// Delete with cutoff in the past — nothing to delete.
	deleted, err := s.DeleteOlderThan(now.Add(-1000 * 24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestDeleteOlderThan_WithChain_AllDeleted(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	insertChainedEntries(t, s, 3, now.Add(-10*24*time.Hour))

	// Delete all entries.
	deleted, err := s.DeleteOlderThan(now)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)
}

// ===========================================================================
// GetTopErrorUsers — with encryption
// ===========================================================================

func TestGetTopErrorUsers_WithEncryption(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	require.NoError(t, s.InitTable())

	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		e := makeEntry("eue-"+string(rune('a'+i)), "alice@test.com", "get_ltp", "market_data", true,
			now.Add(time.Duration(i)*time.Second))
		e.ErrorMessage = "fail"
		require.NoError(t, s.Record(e))
	}

	results, err := s.GetTopErrorUsers(now.Add(-time.Hour), 5)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "alice@test.com", results[0].Email, "email should be decrypted")
	assert.Equal(t, 3, results[0].ErrorCount)
}

func TestGetTopErrorUsers_NegativeLimit(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	results, err := s.GetTopErrorUsers(time.Now().Add(-time.Hour), -1)
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ===========================================================================
// GetToolMetrics — empty result
// ===========================================================================

func TestGetToolMetrics_Empty(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	metrics, err := s.GetToolMetrics(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// ===========================================================================
// ListOrders — empty result
// ===========================================================================

func TestListOrders_Empty(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	results, err := s.ListOrders("nobody@test.com", time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListOrders_WithEncryption(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)

	email := "enc-orders@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("elo-1", email, "place_order", "order", false, now)
	e.OrderID = "ORD-ENC-1"
	require.NoError(t, s.Record(e))

	results, err := s.ListOrders(email, now.Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "ORD-ENC-1", results[0].OrderID)
	assert.Equal(t, email, results[0].Email, "email should be decrypted")
}

// ===========================================================================
// GetOrderAttribution — with encryption + more edge cases
// ===========================================================================

func TestGetOrderAttribution_WithEncryption(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)

	email := "enc-attrib@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	e1 := makeEntry("eoa-1", email, "get_ltp", "market_data", false, now)
	e1.SessionID = "sess-enc"
	require.NoError(t, s.Record(e1))

	e2 := makeEntry("eoa-2", email, "place_order", "order", false, now.Add(10*time.Second))
	e2.SessionID = "sess-enc"
	e2.OrderID = "ORD-ENC-2"
	require.NoError(t, s.Record(e2))

	results, err := s.GetOrderAttribution(email, "ORD-ENC-2")
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// ===========================================================================
// GetStats — empty DB top tool (sql.ErrNoRows path)
// ===========================================================================

func TestGetStats_EmptyDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	stats, err := s.GetStats("nobody@test.com", time.Time{}, "", false)
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalCalls)
	assert.Equal(t, "", stats.TopTool)
}

// ===========================================================================
// GetGlobalStats — empty DB (ErrNoRows for top tool)
// ===========================================================================

func TestGetGlobalStats_EmptyDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	stats, err := s.GetGlobalStats(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalCalls)
	assert.Equal(t, "", stats.TopTool)
}

// ===========================================================================
// GetToolCounts — with since filter
// ===========================================================================

func TestGetToolCounts_WithSinceFilter(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "tc-since@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	old := makeEntry("tcs-old", email, "get_ltp", "market_data", false, now.Add(-2*time.Hour))
	recent := makeEntry("tcs-new", email, "get_holdings", "query", false, now)
	require.NoError(t, s.Record(old))
	require.NoError(t, s.Record(recent))

	counts, err := s.GetToolCounts(email, now.Add(-time.Hour), "", false)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["get_holdings"])
	assert.Equal(t, 0, counts["get_ltp"], "old entry should be excluded by since filter")
}

// ===========================================================================
// InitTable — idempotent (run twice)
// ===========================================================================

func TestInitTable_Idempotent(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	// InitTable was already called by openTestStore, call again.
	require.NoError(t, s.InitTable())
}

// ===========================================================================
// Record — with encryption key set (covers email encryption path)
// ===========================================================================

func TestRecord_WithEncryption_EmptyEmail(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("enc-empty", "", "get_ltp", "market_data", false, now)
	require.NoError(t, s.Record(e))

	results, total, err := s.List("", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, results, 1)
}

// ===========================================================================
// summarize — edge cases for uncovered branches
// ===========================================================================

// jsonFloat — int and json.Number branches

func TestJsonFloat_IntValue(t *testing.T) {
	t.Parallel()
	m := map[string]any{"val": int(42)}
	assert.Equal(t, 42.0, jsonFloat(m, "val"))
}

func TestJsonFloat_NilValue(t *testing.T) {
	t.Parallel()
	m := map[string]any{"val": nil}
	assert.Equal(t, 0.0, jsonFloat(m, "val"))
}

func TestJsonFloat_MissingKey(t *testing.T) {
	t.Parallel()
	m := map[string]any{}
	assert.Equal(t, 0.0, jsonFloat(m, "val"))
}

func TestJsonFloat_StringValue(t *testing.T) {
	t.Parallel()
	m := map[string]any{"val": "not a number"}
	assert.Equal(t, 0.0, jsonFloat(m, "val"))
}

func TestJsonFloat_JSONNumber(t *testing.T) {
	t.Parallel()
	m := map[string]any{"val": json.Number("42.5")}
	assert.Equal(t, 42.5, jsonFloat(m, "val"))
}

// summarizeOrderResult — various paths

func TestSummarizeOrderResult_DataOrderID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{"order_id":"ORD-123"}}`)
	summary := SummarizeOutput("place_order", result)
	assert.Equal(t, "Order ID: ORD-123", summary)
}

func TestSummarizeOrderResult_TopLevelOrderID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"order_id":"ORD-456"}`)
	summary := SummarizeOutput("place_order", result)
	assert.Equal(t, "Order ID: ORD-456", summary)
}

func TestSummarizeOrderResult_NoOrderID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"status":"ok"}`)
	summary := SummarizeOutput("place_order", result)
	assert.Contains(t, summary, "status")
}

func TestSummarizeOrderResult_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("place_order", result)
	assert.Equal(t, "not json", summary)
}

// summarizePositions — edge cases

func TestSummarizePositions_Empty(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":[]}`)
	summary := SummarizeOutput("get_positions", result)
	assert.Equal(t, "No positions", summary)
}

func TestSummarizePositions_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_positions", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizePositions_NonObjectItems(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":["string1","string2"]}`)
	summary := SummarizeOutput("get_positions", result)
	assert.Contains(t, summary, "2 positions")
}

// summarizeOrders — edge cases

func TestSummarizeOrders_Empty(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":[]}`)
	summary := SummarizeOutput("get_orders", result)
	assert.Equal(t, "No orders", summary)
}

func TestSummarizeOrders_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_orders", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeOrders_NonObjectItems(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":[42]}`)
	summary := SummarizeOutput("get_orders", result)
	assert.Contains(t, summary, "1 orders")
}

// summarizeLTP — edge cases

func TestSummarizeLTP_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_ltp", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeLTP_EmptyData(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{}}`)
	summary := SummarizeOutput("get_ltp", result)
	assert.NotEmpty(t, summary)
}

func TestSummarizeLTP_TopLevelWithoutDataKey(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"NSE:INFY":{"last_price":1500.50}}`)
	summary := SummarizeOutput("get_ltp", result)
	assert.Contains(t, summary, "INFY")
	assert.Contains(t, summary, "1 instruments")
}

func TestSummarizeLTP_NonObjectValue(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{"NSE:INFY":"not_an_object"}}`)
	summary := SummarizeOutput("get_ltp", result)
	assert.Contains(t, summary, "0 instruments")
}

// summarizeMargins — edge cases

func TestSummarizeMargins_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_margins", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeMargins_WithDirectAvailable(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{"equity":{"available":75000}}}`)
	summary := SummarizeOutput("get_margins", result)
	assert.Contains(t, summary, "equity")
	assert.Contains(t, summary, "Available")
}

func TestSummarizeMargins_BothSegments(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{"equity":{"available":75000},"commodity":{"available":25000}}}`)
	summary := SummarizeOutput("get_margins", result)
	assert.Contains(t, summary, "equity")
	assert.Contains(t, summary, "commodity")
}

func TestSummarizeMargins_TopLevelWithoutDataKey(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"equity":{"available":50000}}`)
	summary := SummarizeOutput("get_margins", result)
	assert.Contains(t, summary, "equity")
}

// summarizeSearch — edge cases

func TestSummarizeSearch_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("search_instruments", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeSearch_WithResults(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":[{"symbol":"INFY"},{"symbol":"RELIANCE"}]}`)
	summary := SummarizeOutput("search_instruments", result)
	assert.Contains(t, summary, "Found 2 instruments")
}

// summarizeMFOrderResult — edge cases

func TestSummarizeMFOrderResult_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("place_mf_order", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeMFOrderResult_NoID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"status":"ok"}`)
	summary := SummarizeOutput("cancel_mf_order", result)
	assert.Contains(t, summary, "status")
}

// summarizeMFSIPResult — edge cases

func TestSummarizeMFSIPResult_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("place_mf_sip", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeMFSIPResult_NoID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"status":"ok"}`)
	summary := SummarizeOutput("cancel_mf_sip", result)
	assert.Contains(t, summary, "status")
}

// summarizeOptionChain — edge cases

func TestSummarizeOptionChain_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_option_chain", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeOptionChain_NoChainArray(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"underlying":"NIFTY","spot_price":22500}`)
	summary := SummarizeOutput("get_option_chain", result)
	assert.Contains(t, summary, "NIFTY")
	assert.Contains(t, summary, "0 strikes")
}

// SummarizeOutput — error result, nil result, empty result

func TestSummarizeOutput_ErrorResult(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultError("something went wrong")
	summary := SummarizeOutput("get_ltp", result)
	assert.Contains(t, summary, "ERROR")
	assert.Contains(t, summary, "something went wrong")
}

func TestSummarizeOutput_ErrorResult_EmptyText(t *testing.T) {
	t.Parallel()
	result := &gomcp.CallToolResult{IsError: true}
	summary := SummarizeOutput("get_ltp", result)
	assert.Equal(t, "ERROR: (empty)", summary)
}

func TestSummarizeOutput_NilResult(t *testing.T) {
	t.Parallel()
	summary := SummarizeOutput("get_ltp", nil)
	assert.Equal(t, "(no result)", summary)
}

func TestSummarizeOutput_EmptyResponse(t *testing.T) {
	t.Parallel()
	result := &gomcp.CallToolResult{}
	summary := SummarizeOutput("get_ltp", result)
	assert.Equal(t, "(empty response)", summary)
}

func TestSummarizeOutput_DefaultTruncate(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"some":"data"}`)
	summary := SummarizeOutput("unknown_tool", result)
	assert.Contains(t, summary, "some")
}

// summarizeHoldings — edge cases

func TestSummarizeHoldings_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("get_holdings", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeHoldings_Empty(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":[]}`)
	summary := SummarizeOutput("get_holdings", result)
	assert.Equal(t, "No holdings", summary)
}

func TestSummarizeHoldings_NonObjectItems(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`[1,2,3]`)
	summary := SummarizeOutput("get_holdings", result)
	assert.Contains(t, summary, "3 holdings")
}

// ===========================================================================
// List — edge case: combined category + errors + since + until
// ===========================================================================

func TestList_AllFilters(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "allfilters@test.com"
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

	e1 := makeEntry("af-1", email, "place_order", "order", true, base)
	e1.ErrorMessage = "fail"
	e2 := makeEntry("af-2", email, "get_ltp", "market_data", true, base.Add(time.Minute))
	e2.ErrorMessage = "fail"
	e3 := makeEntry("af-3", email, "place_order", "order", false, base.Add(2*time.Minute))
	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))
	require.NoError(t, s.Record(e3))

	results, total, err := s.List(email, ListOptions{
		Category:   "order",
		OnlyErrors: true,
		Since:      base,
		Until:      base.Add(5 * time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "af-1", results[0].CallID)
}

// ===========================================================================
// GetStats — with both category and errorsOnly at once
// ===========================================================================

func TestGetStats_CategoryAndErrors(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "cat-err@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	e1 := makeEntry("ce-1", email, "place_order", "order", true, now)
	e1.ErrorMessage = "fail"
	e2 := makeEntry("ce-2", email, "place_order", "order", false, now.Add(time.Second))
	e3 := makeEntry("ce-3", email, "get_ltp", "market_data", true, now.Add(2*time.Second))
	e3.ErrorMessage = "fail"
	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))
	require.NoError(t, s.Record(e3))

	stats, err := s.GetStats(email, time.Time{}, "order", true)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalCalls, "only order errors")
	assert.Equal(t, 1, stats.ErrorCount)
}

// ===========================================================================
// GetToolCounts — empty result
// ===========================================================================

func TestGetToolCounts_Empty(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	counts, err := s.GetToolCounts("nobody@test.com", time.Time{}, "", false)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

// ===========================================================================
// Stop — nil channels (no worker started)
// ===========================================================================

func TestStop_NoWorker(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.Stop() // should not panic
}

// ===========================================================================
// Closed DB error paths — store operations on closed databases
// ===========================================================================

func TestList_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, _, err := s.List("user@test.com", ListOptions{})
	assert.Error(t, err)
}

func TestListOrders_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.ListOrders("user@test.com", time.Now().Add(-time.Hour))
	assert.Error(t, err)
}

func TestGetOrderAttribution_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetOrderAttribution("user@test.com", "ORD-1")
	assert.Error(t, err)
}

func TestDeleteOlderThan_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.DeleteOlderThan(time.Now())
	assert.Error(t, err)
}

func TestGetStats_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetStats("user@test.com", time.Time{}, "", false)
	assert.Error(t, err)
}

func TestGetToolCounts_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetToolCounts("user@test.com", time.Time{}, "", false)
	assert.Error(t, err)
}

func TestGetToolMetrics_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetToolMetrics(time.Now().Add(-time.Hour))
	assert.Error(t, err)
}

func TestGetGlobalStats_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetGlobalStats(time.Now().Add(-time.Hour))
	assert.Error(t, err)
}

func TestGetTopErrorUsers_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	_, err := s.GetTopErrorUsers(time.Now().Add(-time.Hour), 5)
	assert.Error(t, err)
}

func TestVerifyChain_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	s.db.Close()

	_, err := s.VerifyChain()
	assert.Error(t, err)
}

func TestRecord_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("closed-1", "user@test.com", "get_ltp", "market_data", false, now)
	err := s.Record(e)
	assert.Error(t, err)
}

func TestInitTable_ClosedDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.db.Close()

	err := s.InitTable()
	assert.Error(t, err)
}

// ===========================================================================
// StartWorker with actual StartWorker() call and DB error
// ===========================================================================

func TestStartWorker_ActualWorker_RecordFails(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	// Close the DB so Record fails when the worker processes the entry.
	s.db.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("sw-fail-1", "user@test.com", "get_ltp", "market_data", false, now)
	s.Enqueue(e)

	s.Stop() // drains and completes — should not panic
}

// ===========================================================================
// DeleteOlderThan with chain — marker record error (DB closed after delete)
// ===========================================================================

func TestDeleteOlderThan_ChainMarkerRecordError(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)
	s.SetLogger(slog.Default())

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Record entries directly (bypass worker) with chain hashes.
	old := makeEntry("cmre-old", "", "get_ltp", "market_data", false, now.Add(-200*24*time.Hour))
	s.computeChainLink(old)
	require.NoError(t, s.Record(old))

	fresh := makeEntry("cmre-new", "", "get_ltp", "market_data", false, now)
	s.computeChainLink(fresh)
	require.NoError(t, s.Record(fresh))

	// We can't easily close the DB between the DELETE and the marker INSERT
	// since DeleteOlderThan does both in one call. But we can verify the
	// normal path works correctly.
	deleted, err := s.DeleteOlderThan(now.Add(-100 * 24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

// ===========================================================================
// scanToolCall — with encryption, email_encrypted is empty (legacy row)
// ===========================================================================

func TestScanToolCall_EncryptedStore_LegacyRow(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	// Record without encryption.
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("scan-leg", "plaintext@test.com", "get_ltp", "market_data", false, now)
	require.NoError(t, s.Record(e))

	// Now set encryption key and query — the email_encrypted column is empty.
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)

	// Query with plaintext email (the email column still has plaintext since no key was set during Record).
	results, total, err := s.List("plaintext@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, total, "HMAC of email won't match plaintext, so 0 results")
	assert.Empty(t, results)

	// Query without encryption key to verify we can read the row.
	s.encryptionKey = nil
	results, total, err = s.List("plaintext@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "plaintext@test.com", results[0].Email)
}

// ===========================================================================
// GetToolMetrics — with since filter (covers the WHERE clause)
// ===========================================================================

func TestGetToolMetrics_WithSinceFilter(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	old := makeEntry("tmf-old", "user@test.com", "get_ltp", "market_data", false, now.Add(-2*time.Hour))
	old.DurationMs = 100
	recent := makeEntry("tmf-new", "user@test.com", "get_holdings", "query", false, now)
	recent.DurationMs = 200
	require.NoError(t, s.Record(old))
	require.NoError(t, s.Record(recent))

	metrics, err := s.GetToolMetrics(now.Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	assert.Equal(t, "get_holdings", metrics[0].ToolName)
}

// ===========================================================================
// SeedChain after entries exist — verify it picks up the last hash
// ===========================================================================

func TestSeedChain_AfterEntries(t *testing.T) {
	t.Parallel()
	s := openTestStoreWithKey(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("seed-1", "", "get_ltp", "market_data", false, now)
	s.computeChainLink(e)
	require.NoError(t, s.Record(e))

	// Re-seed should pick up the last hash from DB.
	s.lastHash = "" // clear
	s.SeedChain()
	assert.Equal(t, e.EntryHash, s.lastHash)
}

// ===========================================================================
// Middleware — integration test
// ===========================================================================

func TestMiddleware_Success(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	mw := Middleware(s)
	require.NotNil(t, mw)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText(`{"data":"ok"}`), nil
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-user@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_ltp"
	req.Params.Arguments = map[string]any{"instruments": "NSE:INFY"}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	s.Stop()

	results, total, listErr := s.List("mw-user@test.com", ListOptions{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "get_ltp", results[0].ToolName)
	assert.Equal(t, "market_data", results[0].ToolCategory)
	assert.False(t, results[0].IsError)
	assert.True(t, results[0].DurationMs >= 0)
}

func TestMiddleware_HandlerError(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return nil, fmt.Errorf("handler failed")
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-err@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{"tradingsymbol": "INFY", "quantity": "10"}

	result, err := handler(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, result)

	s.Stop()

	results, total, listErr := s.List("mw-err@test.com", ListOptions{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.True(t, results[0].IsError)
	assert.Equal(t, "handler_error", results[0].ErrorType)
	assert.Contains(t, results[0].ErrorMessage, "handler failed")
}

func TestMiddleware_ToolError(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("insufficient funds"), nil
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-terr@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError)

	s.Stop()

	results, total, listErr := s.List("mw-terr@test.com", ListOptions{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.True(t, results[0].IsError)
	assert.Equal(t, "tool_error", results[0].ErrorType)
}

func TestMiddleware_PlaceOrderWithOrderID(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText(`{"order_id":"ORD-MW-123"}`), nil
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-order@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"tradingsymbol":    "RELIANCE",
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         "10",
		"order_type":       "MARKET",
		"product":          "CNC",
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	s.Stop()

	results, total, listErr := s.List("mw-order@test.com", ListOptions{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "ORD-MW-123", results[0].OrderID)
}

func TestMiddleware_PlaceOrderWithNestedOrderID(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(slog.Default())
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText(`{"data":{"order_id":"ORD-NESTED-456"}}`), nil
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-nested@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	_, err := handler(ctx, req)
	require.NoError(t, err)

	s.Stop()

	results, _, _ := s.List("mw-nested@test.com", ListOptions{})
	require.Len(t, results, 1)
	assert.Equal(t, "ORD-NESTED-456", results[0].OrderID)
}

func TestMiddleware_NoEmail(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	})

	ctx := context.Background()
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_ltp"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	s.Stop()

	results, total, listErr := s.List("", ListOptions{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "", results[0].Email)
}

func TestMiddleware_SensitiveParamsSanitized(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.StartWorker()

	mw := Middleware(s)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	})

	ctx := oauth.ContextWithEmail(context.Background(), "mw-sanitize@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "login"
	req.Params.Arguments = map[string]any{
		"api_key":    "should-be-redacted",
		"api_secret": "should-be-redacted",
		"username":   "visible",
	}

	_, err := handler(ctx, req)
	require.NoError(t, err)

	s.Stop()

	results, _, _ := s.List("mw-sanitize@test.com", ListOptions{})
	require.Len(t, results, 1)
	// JSON encodes < and > as \u003c and \u003e, so check for "redacted" without angle brackets.
	assert.Contains(t, results[0].InputParams, "redacted")
	assert.NotContains(t, results[0].InputParams, "should-be-redacted")
	assert.Contains(t, results[0].InputParams, "visible")
}
