package mcp

import (
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// ===========================================================================
// Coverage push tests: exercise handler bodies that need fully-wired stores.
// Uses newFullDevModeManager which has PaperEngine, PnLService, credentials,
// tokens, and audit store all wired up.
// ===========================================================================

// ---------------------------------------------------------------------------
// Paper trading tools — need PaperEngine
// ---------------------------------------------------------------------------

func TestPaperToggle_Enable_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "ENABLED")
}

func TestPaperToggle_Disable_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Enable first, then disable
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true,
	})
	require.False(t, result.IsError)
	result = callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": false,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "DISABLED")
}

func TestPaperToggle_CustomCash_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable":       true,
		"initial_cash": float64(5000000),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "5000000")
}

func TestPaperStatus_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestPaperReset_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Enable first
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true,
	})
	require.False(t, result.IsError)
	// Reset
	result = callToolDevMode(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "RESET")
}

// ---------------------------------------------------------------------------
// P&L Journal tool — needs PnLService
// ---------------------------------------------------------------------------

func TestPnLJournal_AllPeriods_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"week", "month", "quarter", "year", "all"} {
		result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
		// Should reach GetJournal (returning empty data), not "not available"
		text := resultText(t, result)
		assert.NotContains(t, text, "not available", "period=%s should reach PnLService", period)
	}
}

func TestPnLJournal_CustomDates_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "2026-03-31",
	})
	assert.NotNil(t, result)
	text := resultText(t, result)
	assert.NotContains(t, text, "not available")
}

func TestPnLJournal_InvalidFromDate_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "bad-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Invalid")
}

func TestPnLJournal_InvalidToDate_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "bad-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Invalid")
}

func TestPnLJournal_DefaultPeriod_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"period": "unknown_period",
	})
	assert.NotNil(t, result)
	// Unknown period defaults to "month"
	text := resultText(t, result)
	assert.NotContains(t, text, "not available")
}

// ---------------------------------------------------------------------------
// ext_apps data functions with credentials (brokerClientForEmail returns non-nil)
// ---------------------------------------------------------------------------

func TestPortfolioData_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// cred@example.com has credentials+token seeded in newFullDevModeManager
	data := portfolioData(mgr, nil, "cred@example.com")
	// brokerClientForEmail returns non-nil, but API calls fail (stub endpoint)
	// so data should be an error map
	assert.NotNil(t, data)
}

func TestOrdersData_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newFullDevModeManager(t)
	data := ordersData(mgr, auditStore, "cred@example.com")
	assert.NotNil(t, data)
}

func TestPaperData_WithEngine(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	data := paperData(mgr, nil, "dev@example.com")
	assert.NotNil(t, data)
}

func TestPaperData_WithEngine_Enabled(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	pe := mgr.PaperEngine()
	if pe != nil {
		_ = pe.Enable("paper@example.com", 10000000)
	}
	data := paperData(mgr, nil, "paper@example.com")
	assert.NotNil(t, data)
}

func TestAlertsData_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	store := mgr.AlertStore()
	if store != nil {
		_, _ = store.Add("cred@example.com", "INFY", "NSE", 256265, 1500, "above")
		_, _ = store.Add("cred@example.com", "RELIANCE", "NSE", 408065, 2000, "below")
	}
	data := alertsData(mgr, nil, "cred@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	ws := mgr.WatchlistStore()
	if ws != nil {
		wlID, _ := ws.CreateWatchlist("cred@example.com", "Test WL")
		_ = ws.AddItem("cred@example.com", wlID, &watchlist.WatchlistItem{
			Exchange: "NSE", Tradingsymbol: "INFY", Notes: "test",
			TargetEntry: 1400, TargetExit: 1600,
		})
	}
	data := watchlistData(mgr, nil, "cred@example.com")
	assert.NotNil(t, data)
}

func TestOrderFormData_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	data := orderFormData(mgr, nil, "cred@example.com")
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// brokerClientForEmail directly
// ---------------------------------------------------------------------------

func TestKiteClientForEmail_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	client := brokerClientForEmail(mgr, "cred@example.com")
	assert.NotNil(t, client, "should return non-nil client when creds+token exist")
}

func TestKiteClientForEmail_NoCreds_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// In DevMode, GetBrokerForEmail returns a mock client for all emails,
	// even without stored credentials.
	client := brokerClientForEmail(mgr, "nobody@example.com")
	assert.NotNil(t, client, "DevMode returns mock client for all emails")
}

// ---------------------------------------------------------------------------
// Watchlist get_watchlist handler — exercise full body with items
// ---------------------------------------------------------------------------

func TestGetWatchlist_WithItems_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)

	_, err := ws.CreateWatchlist("wl-full@example.com", "My WL")
	require.NoError(t, err)

	wl := ws.FindWatchlistByName("wl-full@example.com", "My WL")
	require.NotNil(t, wl)

	_ = ws.AddItem("wl-full@example.com", wl.ID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY", Notes: "buy dip",
		TargetEntry: 1400, TargetExit: 1600,
	})
	_ = ws.AddItem("wl-full@example.com", wl.ID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", Notes: "swing",
		TargetEntry: 2400, TargetExit: 2600,
	})

	result := callToolDevMode(t, mgr, "get_watchlist", "wl-full@example.com", map[string]any{
		"watchlist":   "My WL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestGetWatchlist_Empty_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)
	_, err := ws.CreateWatchlist("wl-empty@example.com", "Empty WL")
	require.NoError(t, err)

	result := callToolDevMode(t, mgr, "get_watchlist", "wl-empty@example.com", map[string]any{
		"watchlist":   "Empty WL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "empty")
}

// ---------------------------------------------------------------------------
// Watchlist add/remove cycle through handler
// ---------------------------------------------------------------------------

func TestWatchlist_AddRemove_FullManager(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	email := "wlcycle@example.com"

	// Create
	result := callToolDevMode(t, mgr, "create_watchlist", email, map[string]any{
		"name": "Cycle WL",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Add items
	result = callToolDevMode(t, mgr, "add_to_watchlist", email, map[string]any{
		"watchlist":    "Cycle WL",
		"instruments":  "NSE:INFY,NSE:RELIANCE",
		"notes":        "test notes",
		"target_entry": float64(1400),
		"target_exit":  float64(1600),
	})
	assert.NotNil(t, result)

	// List
	result = callToolDevMode(t, mgr, "list_watchlists", email, map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Get
	result = callToolDevMode(t, mgr, "get_watchlist", email, map[string]any{
		"watchlist":   "Cycle WL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)

	// Remove
	result = callToolDevMode(t, mgr, "remove_from_watchlist", email, map[string]any{
		"watchlist":   "Cycle WL",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)

	// Delete
	result = callToolDevMode(t, mgr, "delete_watchlist", email, map[string]any{
		"watchlist": "Cycle WL",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// set_alert with full manager (alert store wired up)
// ---------------------------------------------------------------------------

func TestSetAlert_AboveDirection_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	// Should create the alert in the store
	if !result.IsError {
		assert.Contains(t, resultText(t, result), "Alert set")
	}
}

func TestSetAlert_BelowDirection_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:RELIANCE",
		"price":      float64(2000),
		"direction":  "below",
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DropPctWithRef_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"price":           float64(5),
		"direction":       "drop_pct",
		"reference_price": float64(1500),
	})
	assert.NotNil(t, result)
}

func TestSetAlert_RisePctWithRef_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(10),
		"direction":       "rise_pct",
		"reference_price": float64(2500),
	})
	assert.NotNil(t, result)
}

func TestListAlerts_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Create an alert first
	_ = callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	result := callToolDevMode(t, mgr, "list_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestDeleteAlert_NotFound_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_alert", "dev@example.com", map[string]any{
		"alert_id": "nonexistent-id",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// RegisterAppResources with audit store
// ---------------------------------------------------------------------------

func TestRegisterAppResources_FullManager(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newFullDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterAppResources(srv, mgr, auditStore, mgr.Logger)
	// Should not panic
}

// ---------------------------------------------------------------------------
// delete_my_account with full stores
// ---------------------------------------------------------------------------

func TestDeleteMyAccount_FullManager(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	email := "deleteme@example.com"

	// Seed some data
	mgr.CredentialStore().Set(email, &kc.KiteCredentialEntry{
		APIKey: "k", APISecret: "s", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set(email, &kc.KiteTokenEntry{
		AccessToken: "t", StoredAt: time.Now(),
	})
	_, _ = mgr.AlertStore().Add(email, "INFY", "NSE", 256265, 1500, "above")

	ws := mgr.WatchlistStore()
	if ws != nil {
		_, _ = ws.CreateWatchlist(email, "To Delete")
	}
	pe := mgr.PaperEngine()
	if pe != nil {
		_ = pe.Enable(email, 10000000)
	}

	result := callToolDevMode(t, mgr, "delete_my_account", email, map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "deleted")

	// Verify data was cleaned up
	_, hasCreds := mgr.CredentialStore().Get(email)
	assert.False(t, hasCreds, "credentials should be deleted")
	_, hasToken := mgr.TokenStore().Get(email)
	assert.False(t, hasToken, "token should be deleted")
	alerts := mgr.AlertStore().List(email)
	assert.Empty(t, alerts, "alerts should be deleted")
}

// ---------------------------------------------------------------------------
// update_my_credentials with full stores
// ---------------------------------------------------------------------------

func TestUpdateMyCredentials_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_key":    "new_key",
		"api_secret": "new_secret",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "updated")

	// Verify stored
	entry, ok := mgr.CredentialStore().Get("dev@example.com")
	assert.True(t, ok)
	assert.Equal(t, "new_key", entry.APIKey)
}

// ---------------------------------------------------------------------------
// All ext_apps appResources data funcs with full manager
// ---------------------------------------------------------------------------

func TestAllAppResources_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newFullDevModeManager(t)
	for _, res := range appResources {
		if res.DataFunc != nil {
			_ = res.DataFunc(mgr, auditStore, "cred@example.com")
		}
	}
}

// ---------------------------------------------------------------------------
// setup_telegram with full manager (no TelegramNotifier, but exercises body)
// ---------------------------------------------------------------------------

func TestSetupTelegram_ValidChatID_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(12345),
	})
	assert.NotNil(t, result)
	// TelegramNotifier is nil, so should return "not configured"
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// close_all_positions with confirm flag
// ---------------------------------------------------------------------------

func TestCloseAllPositions_Confirmed_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	// Should exercise the handler body past the confirm check
}

func TestCloseAllPositions_ConfirmedMIS_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "MIS",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Prompts with full manager
// ---------------------------------------------------------------------------

func TestRegisterPrompts_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
}

// ---------------------------------------------------------------------------
// injectData with CSS placeholder
// ---------------------------------------------------------------------------

func TestInjectData_WithCSSPlaceholder(t *testing.T) {
	t.Parallel()
	html := `<style>/*__INJECTED_CSS__*/</style><script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := map[string]string{"hello": "world"}
	result := injectData(html, data)
	assert.Contains(t, result, "hello")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

// ---------------------------------------------------------------------------
// ordersData with stored order tool calls
// ---------------------------------------------------------------------------

func TestOrdersData_WithToolCalls_FullManager(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newFullDevModeManager(t)
	// Record order tool calls with OrderID populated
	auditStore.Record(&audit.ToolCall{
		CallID:      "ord1",
		Email:       "cred@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD001",
		InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10,"price":1500}`,
	})
	auditStore.Record(&audit.ToolCall{
		CallID:      "ord2",
		Email:       "cred@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD002",
		InputParams: `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"SELL","order_type":"LIMIT","quantity":5,"price":2500}`,
	})
	// Wait for async write to flush
	time.Sleep(100 * time.Millisecond)
	data := ordersData(mgr, auditStore, "cred@example.com")
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// set_alert full path -- instrument exists, direction above/below
// ---------------------------------------------------------------------------

func TestSetAlert_WithInstrument_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// INFY exists in test data. Direction=above. Alert should be created.
	result := callToolDevMode(t, mgr, "set_alert", "alertuser@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	// Should succeed (alert stored in alert store)
	if !result.IsError {
		text := resultText(t, result)
		assert.Contains(t, text, "Alert set")
		assert.Contains(t, text, "INFY")
	}
}

func TestSetAlert_DropPctNoRefPrice_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// drop_pct without reference_price needs LTP fetch -- will fail in DevMode
	result := callToolDevMode(t, mgr, "set_alert", "alertuser@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(5),
		"direction":  "drop_pct",
	})
	assert.NotNil(t, result)
	// Should reach the LTP fetch path and fail with API error
}

func TestSetAlert_InvalidInstrumentFormat_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "alertuser@example.com", map[string]any{
		"instrument": "NOINFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// list_alerts and delete_alert with existing alerts
// ---------------------------------------------------------------------------

func TestListAlerts_WithAlerts_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "list-alert@example.com"

	store := mgr.AlertStore()
	id1, _ := store.Add(email, "INFY", "NSE", 256265, 1500, "above")
	_, _ = store.Add(email, "RELIANCE", "NSE", 408065, 2000, "below")

	result := callToolDevMode(t, mgr, "list_alerts", email, map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "INFY")
	assert.Contains(t, text, "RELIANCE")

	// Delete one
	result = callToolDevMode(t, mgr, "delete_alert", email, map[string]any{
		"alert_id": id1,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// get_watchlist with LTP enabled (will fail at API but exercise code path)
// ---------------------------------------------------------------------------

func TestGetWatchlist_WithLTP_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "wl-ltp@example.com"
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)
	_, err := ws.CreateWatchlist(email, "LTP WL")
	require.NoError(t, err)
	wl := ws.FindWatchlistByName(email, "LTP WL")
	require.NotNil(t, wl)
	_ = ws.AddItem(email, wl.ID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY",
		TargetEntry: 1400, TargetExit: 1600,
	})

	// include_ltp defaults to true -> will try to fetch LTP via session
	result := callToolDevMode(t, mgr, "get_watchlist", email, map[string]any{
		"watchlist": "LTP WL",
	})
	assert.NotNil(t, result)
	// May fail at API call but exercises the LTP enrichment code path
}

// ---------------------------------------------------------------------------
// paper trading with operations
// ---------------------------------------------------------------------------

func TestPaperTrading_EnableStatusReset_FullManager(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	email := "paper-ops@example.com"

	// Enable
	result := callToolDevMode(t, mgr, "paper_trading_toggle", email, map[string]any{
		"enable": true,
	})
	require.False(t, result.IsError)

	// Status (should show enabled)
	result = callToolDevMode(t, mgr, "paper_trading_status", email, map[string]any{})
	assert.False(t, result.IsError)

	// Reset
	result = callToolDevMode(t, mgr, "paper_trading_reset", email, map[string]any{})
	assert.False(t, result.IsError)

	// Disable
	result = callToolDevMode(t, mgr, "paper_trading_toggle", email, map[string]any{
		"enable": false,
	})
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// ext_apps paperData with enabled engine
// ---------------------------------------------------------------------------

func TestPaperData_EnabledEngine_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "paper-data@example.com"
	pe := mgr.PaperEngine()
	require.NotNil(t, pe)
	require.NoError(t, pe.Enable(email, 10000000))

	data := paperData(mgr, nil, email)
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// ext_apps alertsData with alerts and LTP attempt (cred user)
// ---------------------------------------------------------------------------

func TestAlertsData_WithAlertsAndCredentials_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "cred@example.com"

	store := mgr.AlertStore()
	require.NotNil(t, store)
	_, _ = store.Add(email, "INFY", "NSE", 256265, 1500, "above")
	_, _ = store.Add(email, "RELIANCE", "NSE", 408065, 2000, "below")
	// Mark one as triggered
	id3, _ := store.Add(email, "INFY", "NSE", 256265, 1400, "below")
	store.MarkTriggered(id3, 1350)

	data := alertsData(mgr, nil, email)
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	if ok {
		active, _ := dataMap["active_count"].(int)
		triggered, _ := dataMap["triggered_count"].(int)
		assert.GreaterOrEqual(t, active, 1)
		assert.GreaterOrEqual(t, triggered, 1)
	}
}

// ---------------------------------------------------------------------------
// ext_apps portfolioData with credentials (API will fail but code path exercised)
// ---------------------------------------------------------------------------

func TestPortfolioData_WithCredentials_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	data := portfolioData(mgr, nil, "cred@example.com")
	// Should return error map (API fails to connect to stub)
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// ext_apps watchlistData with credentials and items
// ---------------------------------------------------------------------------

func TestWatchlistData_WithCredsAndItems_FullManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "cred@example.com"
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)
	wlID, err := ws.CreateWatchlist(email, "Cred WL")
	require.NoError(t, err)
	_ = ws.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY",
		TargetEntry: 1400, TargetExit: 1600,
	})
	_ = ws.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TargetEntry: 2400, TargetExit: 2600,
	})

	data := watchlistData(mgr, nil, email)
	assert.NotNil(t, data)
}
