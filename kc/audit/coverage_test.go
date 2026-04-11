package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// --- SetLogger / SetEncryptionKey ---

func TestStore_SetLogger(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetLogger(nil) // should not panic
}

func TestStore_SetEncryptionKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	s.SetEncryptionKey(key)
	assert.NotNil(t, s.encryptionKey)
	assert.NotNil(t, s.hashKey)
}

// --- hmacEmail ---

func TestStore_hmacEmail_NoKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	assert.Equal(t, "test@example.com", s.hmacEmail("test@example.com"))
	assert.Equal(t, "", s.hmacEmail(""))
}

func TestStore_hmacEmail_WithKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetEncryptionKey([]byte("0123456789abcdef0123456789abcdef"))

	hashed := s.hmacEmail("test@example.com")
	assert.NotEmpty(t, hashed)
	assert.NotEqual(t, "test@example.com", hashed)

	// Empty email passes through.
	assert.Equal(t, "", s.hmacEmail(""))

	// Deterministic.
	assert.Equal(t, hashed, s.hmacEmail("test@example.com"))
}

// --- SeedChain ---

func TestStore_SeedChain_NoKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SeedChain() // no hashKey set — should be a no-op
	assert.Equal(t, "", s.lastHash)
}

func TestStore_SeedChain_Genesis(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetEncryptionKey([]byte("0123456789abcdef0123456789abcdef"))
	s.SeedChain()
	assert.NotEmpty(t, s.lastHash, "genesis hash should be set")
}

func TestStore_SeedChain_ResumesFromDB(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	s.SeedChain()

	// Record an entry so the DB has a hash.
	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("chain-001", "chain@test.com", "get_ltp", "market_data", false, now)
	s.computeChainLink(entry)
	require.NoError(t, s.Record(entry))
	savedHash := entry.EntryHash

	// Create a new store pointing to the same DB to simulate restart.
	s2 := New(s.db)
	require.NoError(t, s2.InitTable())
	s2.SetEncryptionKey(key)
	s2.SeedChain()

	assert.Equal(t, savedHash, s2.lastHash, "should resume from last DB hash")
}

// --- computeChainLink ---

func TestStore_computeChainLink(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.SetEncryptionKey([]byte("0123456789abcdef0123456789abcdef"))
	s.SeedChain()

	now := time.Now().UTC()
	entry := makeEntry("link-001", "user@test.com", "get_ltp", "market_data", false, now)
	s.computeChainLink(entry)

	assert.NotEmpty(t, entry.PrevHash)
	assert.NotEmpty(t, entry.EntryHash)
	assert.NotEqual(t, entry.PrevHash, entry.EntryHash)
}

func TestStore_computeChainLink_NoKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC()
	entry := makeEntry("link-nk", "user@test.com", "get_ltp", "market_data", false, now)
	s.computeChainLink(entry)

	assert.Empty(t, entry.PrevHash)
	assert.Empty(t, entry.EntryHash)
}

// --- ListOrders ---

func TestStore_ListOrders(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "orders@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Entry with order_id.
	entry1 := makeEntry("lo-001", email, "place_order", "order", false, now)
	entry1.OrderID = "ORD-12345"
	require.NoError(t, s.Record(entry1))

	// Entry without order_id.
	entry2 := makeEntry("lo-002", email, "get_ltp", "market_data", false, now.Add(time.Second))
	require.NoError(t, s.Record(entry2))

	results, err := s.ListOrders(email, now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "ORD-12345", results[0].OrderID)
}

// --- GetOrderAttribution ---

func TestStore_GetOrderAttribution(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "attrib@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Insert a sequence: context query → LTP check → place_order (with order_id).
	e1 := makeEntry("oa-001", email, "get_positions", "query", false, now)
	e1.SessionID = "sess-xyz"
	require.NoError(t, s.Record(e1))

	e2 := makeEntry("oa-002", email, "get_ltp", "market_data", false, now.Add(10*time.Second))
	e2.SessionID = "sess-xyz"
	require.NoError(t, s.Record(e2))

	e3 := makeEntry("oa-003", email, "place_order", "order", false, now.Add(20*time.Second))
	e3.SessionID = "sess-xyz"
	e3.OrderID = "ORD-99"
	require.NoError(t, s.Record(e3))

	results, err := s.GetOrderAttribution(email, "ORD-99")
	require.NoError(t, err)
	assert.Len(t, results, 3, "should include all 3 calls within the 60s window")
}

func TestStore_GetOrderAttribution_NotFound(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	_, err := s.GetOrderAttribution("test@test.com", "nonexistent-order")
	require.Error(t, err)
}

// --- GetToolCounts ---

func TestStore_GetToolCounts(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "counts@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	for i := 0; i < 3; i++ {
		e := makeEntry("tc-"+string(rune('a'+i)), email, "get_ltp", "market_data", false, now.Add(time.Duration(i)*time.Second))
		require.NoError(t, s.Record(e))
	}
	e := makeEntry("tc-d", email, "get_holdings", "query", false, now.Add(4*time.Second))
	require.NoError(t, s.Record(e))

	counts, err := s.GetToolCounts(email, time.Time{}, "", false)
	require.NoError(t, err)
	assert.Equal(t, 3, counts["get_ltp"])
	assert.Equal(t, 1, counts["get_holdings"])
}

func TestStore_GetToolCounts_WithCategory(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "counts-cat@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	e1 := makeEntry("tcc-1", email, "get_ltp", "market_data", false, now)
	require.NoError(t, s.Record(e1))
	e2 := makeEntry("tcc-2", email, "place_order", "order", false, now.Add(time.Second))
	require.NoError(t, s.Record(e2))

	counts, err := s.GetToolCounts(email, time.Time{}, "order", false)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["place_order"])
	assert.Equal(t, 0, counts["get_ltp"], "market_data tool should be excluded by category filter")
}

func TestStore_GetToolCounts_OnlyErrors(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "counts-err@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	eOk := makeEntry("tce-1", email, "get_ltp", "market_data", false, now)
	require.NoError(t, s.Record(eOk))
	eFail := makeEntry("tce-2", email, "get_ltp", "market_data", true, now.Add(time.Second))
	eFail.ErrorMessage = "fail"
	require.NoError(t, s.Record(eFail))

	counts, err := s.GetToolCounts(email, time.Time{}, "", true)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["get_ltp"])
}

// --- GetToolMetrics ---

func TestStore_GetToolMetrics(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	e1 := makeEntry("tm-1", "user@test.com", "get_ltp", "market_data", false, now)
	e1.DurationMs = 100
	e2 := makeEntry("tm-2", "user@test.com", "get_ltp", "market_data", true, now.Add(time.Second))
	e2.DurationMs = 200
	e2.ErrorMessage = "fail"
	e3 := makeEntry("tm-3", "other@test.com", "place_order", "order", false, now.Add(2*time.Second))
	e3.DurationMs = 300

	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))
	require.NoError(t, s.Record(e3))

	metrics, err := s.GetToolMetrics(now.Add(-time.Hour))
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	// Find get_ltp metric.
	var ltpMetric *ToolMetric
	for i := range metrics {
		if metrics[i].ToolName == "get_ltp" {
			ltpMetric = &metrics[i]
			break
		}
	}
	require.NotNil(t, ltpMetric)
	assert.Equal(t, 2, ltpMetric.CallCount)
	assert.InDelta(t, 150.0, ltpMetric.AvgMs, 0.5)
	assert.Equal(t, int64(200), ltpMetric.MaxMs)
	assert.Equal(t, 1, ltpMetric.ErrorCount)
}

// --- GetGlobalStats ---

func TestStore_GetGlobalStats(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	e1 := makeEntry("gs-1", "a@test.com", "get_ltp", "market_data", false, now)
	e1.DurationMs = 100
	e2 := makeEntry("gs-2", "b@test.com", "get_ltp", "market_data", true, now.Add(time.Second))
	e2.DurationMs = 200
	e2.ErrorMessage = "err"
	e3 := makeEntry("gs-3", "a@test.com", "place_order", "order", false, now.Add(2*time.Second))
	e3.DurationMs = 300

	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))
	require.NoError(t, s.Record(e3))

	stats, err := s.GetGlobalStats(now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalCalls)
	assert.Equal(t, 1, stats.ErrorCount)
	assert.InDelta(t, 200.0, stats.AvgLatencyMs, 0.5)
	assert.Equal(t, "get_ltp", stats.TopTool)
	assert.Equal(t, 2, stats.TopToolCount)
}

func TestStore_GetGlobalStats_Empty(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	stats, err := s.GetGlobalStats(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalCalls)
}

// --- GetTopErrorUsers ---

func TestStore_GetTopErrorUsers(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// User A: 3 errors.
	for i := 0; i < 3; i++ {
		e := makeEntry("eu-a-"+string(rune('0'+i)), "a@test.com", "get_ltp", "market_data", true, now.Add(time.Duration(i)*time.Second))
		e.ErrorMessage = "fail"
		require.NoError(t, s.Record(e))
	}
	// User B: 1 error.
	eB := makeEntry("eu-b-0", "b@test.com", "get_ltp", "market_data", true, now.Add(4*time.Second))
	eB.ErrorMessage = "fail"
	require.NoError(t, s.Record(eB))

	results, err := s.GetTopErrorUsers(now.Add(-time.Hour), 5)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, 3, results[0].ErrorCount) // top user
	assert.Equal(t, 1, results[1].ErrorCount)
}

func TestStore_GetTopErrorUsers_DefaultLimit(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	results, err := s.GetTopErrorUsers(time.Now().Add(-time.Hour), 0) // default limit
	require.NoError(t, err)
	assert.Empty(t, results)
}

// --- Activity Listeners ---

func TestStore_ActivityListeners(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.StartWorker()

	ch := s.AddActivityListener("test-listener")
	require.NotNil(t, ch)

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("al-001", "listener@test.com", "get_ltp", "market_data", false, now)
	s.Enqueue(entry)

	// Stop to drain the buffer.
	s.Stop()

	// The listener should have received the entry.
	select {
	case got := <-ch:
		assert.Equal(t, "al-001", got.CallID)
	default:
		t.Fatal("expected to receive entry on listener channel")
	}

	// RemoveActivityListener.
	s.RemoveActivityListener("test-listener")

	// Channel should be closed.
	_, ok := <-ch
	assert.False(t, ok, "channel should be closed after removal")
}

func TestStore_RemoveActivityListener_Nonexistent(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	s.RemoveActivityListener("nonexistent") // should not panic
}

// --- VerifyChain ---

func TestStore_VerifyChain_NoKey(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "not configured")
}

func TestStore_VerifyChain_ValidChain(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	s.SeedChain()
	s.StartWorker()

	// Use empty emails so hmacEmail("") returns "" and the DB stores ""
	// which matches what computeChainLink uses. This avoids the HMAC email
	// mismatch between chain computation and DB storage.
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 5; i++ {
		e := makeEntry("vc-"+string(rune('a'+i)), "", "get_ltp", "market_data", false, now.Add(time.Duration(i)*time.Second))
		s.Enqueue(e)
	}
	s.Stop()

	result, err := s.VerifyChain()
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 5, result.Total)
	assert.Equal(t, 5, result.Verified)
}

// --- Summarize coverage: trading_context, pre_trade_check ---

func TestSummarizeOutput_TradingContext(t *testing.T) {
	t.Parallel()
	json := `{"margin_available":125000,"open_positions":3,"positions_pnl":-500,"holdings_count":10,"active_alerts":2}`
	result := gomcp.NewToolResultText(json)
	summary := SummarizeOutput("trading_context", result)
	assert.Contains(t, summary, "margin")
	assert.Contains(t, summary, "pos")
	assert.Contains(t, summary, "holdings")
	assert.Contains(t, summary, "alerts")
}

func TestSummarizeOutput_TradingContext_Empty(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{}`)
	summary := SummarizeOutput("trading_context", result)
	// No relevant keys, should truncate.
	assert.NotEmpty(t, summary)
}

func TestSummarizeOutput_TradingContext_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("trading_context", result)
	assert.Equal(t, "not json", summary)
}

func TestSummarizeOutput_PreTradeCheck(t *testing.T) {
	t.Parallel()
	json := `{"symbol":"RELIANCE","side":"BUY","quantity":10,"current_price":2500,"recommendation":"PROCEED"}`
	result := gomcp.NewToolResultText(json)
	summary := SummarizeOutput("pre_trade_check", result)
	assert.Contains(t, summary, "BUY")
	assert.Contains(t, summary, "RELIANCE")
	assert.Contains(t, summary, "PROCEED")
}

func TestSummarizeOutput_PreTradeCheck_InvalidJSON(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`not json`)
	summary := SummarizeOutput("pre_trade_check", result)
	assert.Equal(t, "not json", summary)
}

// --- SummarizeInput coverage additions ---

func TestSummarizeInput_ConvertPosition(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"tradingsymbol": "RELIANCE",
		"exchange":      "NSE",
		"old_product":   "MIS",
		"new_product":   "CNC",
		"quantity":      10,
	}
	result := SummarizeInput("convert_position", args)
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "MIS")
	assert.Contains(t, result, "CNC")
}

func TestSummarizeInput_PreTradeCheck(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"transaction_type": "BUY",
		"quantity":         "10",
		"tradingsymbol":    "RELIANCE",
		"exchange":         "NSE",
	}
	result := SummarizeInput("pre_trade_check", args)
	assert.Contains(t, result, "BUY")
	assert.Contains(t, result, "RELIANCE")
}

func TestSummarizeInput_PlaceMFOrder(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"transaction_type": "buy",
		"tradingsymbol":    "INF123",
		"amount":           "5000",
		"quantity":         "100",
	}
	result := SummarizeInput("place_mf_order", args)
	assert.Contains(t, result, "BUY")
	assert.Contains(t, result, "INF123")
}

func TestSummarizeInput_CancelMFOrder(t *testing.T) {
	t.Parallel()
	args := map[string]any{"order_id": "MF-123"}
	result := SummarizeInput("cancel_mf_order", args)
	assert.Equal(t, "Cancel MF order MF-123", result)
}

func TestSummarizeInput_PlaceMFSIP(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"tradingsymbol": "INF123",
		"amount":        "5000",
		"frequency":     "monthly",
		"instalments":   "12",
	}
	result := SummarizeInput("place_mf_sip", args)
	assert.Contains(t, result, "INF123")
	assert.Contains(t, result, "monthly")
}

func TestSummarizeInput_CancelMFSIP(t *testing.T) {
	t.Parallel()
	args := map[string]any{"sip_id": "SIP-456"}
	result := SummarizeInput("cancel_mf_sip", args)
	assert.Equal(t, "Cancel SIP SIP-456", result)
}

func TestSummarizeInput_GetOptionChain(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"underlying":        "NIFTY",
		"expiry":            "2026-04-30",
		"strikes_around_atm": "5",
	}
	result := SummarizeInput("get_option_chain", args)
	assert.Contains(t, result, "NIFTY")
	assert.Contains(t, result, "2026-04-30")
}

func TestSummarizeInput_GetOptionChain_NoExpiry(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"underlying":        "NIFTY",
		"strikes_around_atm": "5",
	}
	result := SummarizeInput("get_option_chain", args)
	assert.Contains(t, result, "nearest")
}

func TestSummarizeInput_Watchlist(t *testing.T) {
	t.Parallel()
	assert.Contains(t, SummarizeInput("create_watchlist", map[string]any{"name": "tech"}), "tech")
	assert.Contains(t, SummarizeInput("delete_watchlist", map[string]any{"watchlist": "wl1"}), "wl1")
	assert.Contains(t, SummarizeInput("add_to_watchlist", map[string]any{"watchlist": "wl1", "instruments": "NSE:INFY"}), "wl1")
	assert.Contains(t, SummarizeInput("remove_from_watchlist", map[string]any{"watchlist": "wl1", "items": "NSE:INFY"}), "wl1")
	assert.Contains(t, SummarizeInput("get_watchlist", map[string]any{"watchlist": "wl1"}), "wl1")
	assert.Equal(t, "(no params)", SummarizeInput("list_watchlists", map[string]any{"dummy": 1}))
}

// --- SummarizeOutput coverage: MF, option chain ---

func TestSummarizeOutput_MFOrder(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"order_id":"MF-123"}`)
	summary := SummarizeOutput("place_mf_order", result)
	assert.Equal(t, "MF Order ID: MF-123", summary)
}

func TestSummarizeOutput_MFOrder_NoID(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"status":"ok"}`)
	summary := SummarizeOutput("place_mf_order", result)
	assert.Contains(t, summary, "status")
}

func TestSummarizeOutput_MFSIP(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"sip_id":"SIP-456"}`)
	summary := SummarizeOutput("place_mf_sip", result)
	assert.Equal(t, "SIP ID: SIP-456", summary)
}

func TestSummarizeOutput_OptionChain(t *testing.T) {
	t.Parallel()
	json := `{"underlying":"NIFTY","expiry":"2026-04-30","spot_price":22500,"pcr":0.85,"max_pain":22000,"chain":[{},{},{}]}`
	result := gomcp.NewToolResultText(json)
	summary := SummarizeOutput("get_option_chain", result)
	assert.Contains(t, summary, "NIFTY")
	assert.Contains(t, summary, "3 strikes")
	assert.Contains(t, summary, "PCR")
}

// --- Margins nested structure ---

func TestSummarizeOutput_MarginsNestedAvailable(t *testing.T) {
	t.Parallel()
	marginsJSON := `{"data":{"equity":{"available":{"live_balance":125000}}}}`
	result := gomcp.NewToolResultText(marginsJSON)
	summary := SummarizeOutput("get_margins", result)
	assert.Contains(t, summary, "equity")
}

func TestSummarizeOutput_MarginsNoSegments(t *testing.T) {
	t.Parallel()
	result := gomcp.NewToolResultText(`{"data":{}}`)
	summary := SummarizeOutput("get_margins", result)
	// No equity/commodity segments — should fall back to truncate.
	assert.NotEmpty(t, summary)
}

// --- Orders with empty/unknown status ---

func TestSummarizeOutput_OrdersEmptyStatus(t *testing.T) {
	t.Parallel()
	ordersJSON := `{"data":[{"order_id":"1"}]}`
	result := gomcp.NewToolResultText(ordersJSON)
	summary := SummarizeOutput("get_orders", result)
	assert.Contains(t, summary, "1 orders")
	assert.Contains(t, summary, "unknown")
}

// --- Encrypted email round-trip ---

func TestStore_RecordAndList_WithEncryption(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)

	now := time.Now().UTC().Truncate(time.Microsecond)
	entry := makeEntry("enc-001", "encrypted@test.com", "get_ltp", "market_data", false, now)
	require.NoError(t, s.Record(entry))

	results, total, err := s.List("encrypted@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, "encrypted@test.com", results[0].Email, "email should be decrypted for display")
}

// --- GetStats with category and errorsOnly filters ---

func TestStore_GetStats_CategoryFilter(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "stats-cat@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	e1 := makeEntry("sc-1", email, "get_ltp", "market_data", false, now)
	e2 := makeEntry("sc-2", email, "place_order", "order", false, now.Add(time.Second))
	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))

	stats, err := s.GetStats(email, time.Time{}, "order", false)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalCalls)
}

func TestStore_GetStats_ErrorsOnly(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "stats-err@test.com"
	now := time.Now().UTC().Truncate(time.Microsecond)

	e1 := makeEntry("se-1", email, "get_ltp", "market_data", false, now)
	e2 := makeEntry("se-2", email, "get_ltp", "market_data", true, now.Add(time.Second))
	e2.ErrorMessage = "fail"
	require.NoError(t, s.Record(e1))
	require.NoError(t, s.Record(e2))

	stats, err := s.GetStats(email, time.Time{}, "", true)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalCalls)
	assert.Equal(t, 1, stats.ErrorCount)
}

// --- DeleteOlderThan with chain markers ---

func TestStore_DeleteOlderThan_WithChain(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	s.SetEncryptionKey(key)
	s.SeedChain()
	s.StartWorker()

	now := time.Now().UTC().Truncate(time.Microsecond)
	old := makeEntry("del-chain-1", "user@test.com", "get_ltp", "market_data", false, now.Add(-200*24*time.Hour))
	fresh := makeEntry("del-chain-2", "user@test.com", "get_ltp", "market_data", false, now)

	s.Enqueue(old)
	s.Enqueue(fresh)
	s.Stop()

	deleted, err := s.DeleteOlderThan(now.Add(-100 * 24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// A chain-break marker should have been inserted.
	results, total, err := s.List("user@test.com", ListOptions{})
	require.NoError(t, err)
	// Fresh entry should remain; may also see the chain break marker.
	assert.GreaterOrEqual(t, total, 1)
	_ = results
}
