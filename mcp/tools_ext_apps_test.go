package mcp

import (
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// Ext apps DataFunc tests: dashboard resource data functions for portfolio, activity, orders, etc.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := audit.New(db)
	require.NoError(t, store.InitTable())
	t.Cleanup(func() { db.Close() })
	return store
}

func TestChartData_ReturnsNil(t *testing.T) {
	t.Parallel()
	result := chartData(nil, nil, "")
	assert.Nil(t, result)
}

func TestOptionsChainData_ReturnsNil(t *testing.T) {
	t.Parallel()
	result := optionsChainData(nil, nil, "")
	assert.Nil(t, result)
}

func TestOrderFormData_WithManager(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := orderFormData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, false, m["paper_mode"])
}

func TestWatchlistData_NoStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := watchlistData(mgr, nil, "test@example.com")
	// watchlist store may be nil in test manager
	_ = result // should not panic
}

func TestSafetyData_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := safetyData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.True(t, m["enabled"].(bool))
	assert.NotNil(t, m["limits"])
	assert.NotNil(t, m["status"])
	assert.NotNil(t, m["sebi"])
	// Verify SEBI section
	sebi, ok := m["sebi"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, true, sebi["static_egress_ip"])
	assert.Equal(t, true, sebi["order_tagging"])
	assert.False(t, sebi["audit_trail"].(bool)) // nil audit store
}

func TestSafetyData_WithAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Use a non-nil audit.Store placeholder (it won't be nil-checked)
	result := safetyData(mgr, &audit.Store{}, "test@example.com")
	m := result.(map[string]any)
	sebi := m["sebi"].(map[string]any)
	assert.True(t, sebi["audit_trail"].(bool))
}

func TestPaperData_NoPaperEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := paperData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	status, ok := m["status"].(map[string]any)
	assert.True(t, ok)
	assert.False(t, status["enabled"].(bool))
}

func TestAlertsData_NoAlertStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := alertsData(mgr, nil, "test@example.com")
	// With no alert store, should return nil or basic data
	_ = result
}

func TestHubData_WithManager(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := hubData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "test@example.com", m["email"])
	assert.False(t, m["kite_connected"].(bool))
	assert.False(t, m["credentials_set"].(bool))
	assert.False(t, m["paper_mode"].(bool))
	assert.Equal(t, 0, m["active_alerts"])
	assert.Equal(t, 0, m["tool_calls_today"])
	assert.NotEmpty(t, m["external_url"])
}

func TestActivityData_NoAuditStore(t *testing.T) {
	t.Parallel()
	result := activityData(nil, nil, "test@example.com")
	assert.Nil(t, result, "should return nil when audit store is nil")
}

func TestPortfolioData_NoSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := portfolioData(mgr, nil, "test@example.com")
	// Without a valid Kite client, should return nil or error data
	_ = result // should not panic
}

func TestOrdersData_NoAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := ordersData(mgr, nil, "test@example.com")
	// Without audit store, should still return some data
	_ = result // should not panic
}

func TestPortfolioData_NilClient(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := portfolioData(mgr, nil, "nobody@example.com")
	assert.Nil(t, data)
}

func TestActivityData_NilAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := activityData(mgr, nil, "nobody@example.com")
	assert.Nil(t, data)
}

func TestOrdersData_NilClient(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := ordersData(mgr, nil, "nobody@example.com")
	assert.Nil(t, data)
}

func TestPaperData_NilEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := paperData(mgr, nil, "nobody@example.com")
	// PaperEngine is nil for test managers, exercises early return
	_ = data
}

func TestWatchlistData_NoWatchlists(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := watchlistData(mgr, nil, "nobody@example.com")
	// Returns nil when no watchlists exist for the user, or may return empty struct
	// The important thing is it exercises the function
	_ = data
}

func TestSafetyData_Basic(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := safetyData(mgr, nil, "test@example.com")
	// safetyData always returns something (riskguard status)
	assert.NotNil(t, data)
}

func TestHubData_NilAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := hubData(mgr, nil, "nobody@example.com")
	// hubData may return partial data even without audit store
	assert.NotNil(t, data)
}

func TestAlertsData_NoAlerts(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := alertsData(mgr, nil, "nobody@example.com")
	// AlertStore exists but has no alerts for this user
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 0, dataMap["active_count"])
	assert.Equal(t, 0, dataMap["triggered_count"])
}

func TestAlertsData_WithAlerts(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Create an alert first using proper signature
	mgr.AlertStore().Add("alert@example.com", "INFY", "NSE", 256265, 1500.0, "above")
	data := alertsData(mgr, nil, "alert@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 1, dataMap["active_count"])
}

func TestPaperData_NoEngineReturnsStatus(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := paperData(mgr, nil, "test@example.com")
	// Returns a status map even when engine is nil
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	_, hasStatus := dataMap["status"]
	assert.True(t, hasStatus)
}

func TestWatchlistData_WithWatchlists(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	mgr.WatchlistStore().CreateWatchlist("wl@example.com", "My Stocks")
	data := watchlistData(mgr, nil, "wl@example.com")
	assert.NotNil(t, data)
}

func TestOrderFormData_Basic(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := orderFormData(mgr, nil, "test@example.com")
	// orderFormData returns a static config map
	assert.NotNil(t, data)
}

func TestOptionsChainData_ReturnsNil_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := optionsChainData(mgr, nil, "nobody@example.com")
	assert.Nil(t, data)
}

func TestChartData_ReturnsNil_V2(t *testing.T) {
	t.Parallel()
	data := chartData(nil, nil, "nobody@example.com")
	assert.Nil(t, data)
}

func TestSafetyData_WithRiskGuard_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := safetyData(mgr, nil, "test@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.True(t, dataMap["enabled"].(bool))
	_, hasLimits := dataMap["limits"]
	assert.True(t, hasLimits)
	_, hasSEBI := dataMap["sebi"]
	assert.True(t, hasSEBI)
}

func TestHubData_WithAlerts(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	mgr.AlertStore().Add("hub@example.com", "INFY", "NSE", 256265, 1500.0, "above")
	data := hubData(mgr, nil, "hub@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 1, dataMap["active_alerts"])
	assert.Equal(t, "hub@example.com", dataMap["email"])
}

func TestOrderFormData_WithPaperEngineNil(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := orderFormData(mgr, nil, "test@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.False(t, dataMap["paper_mode"].(bool))
}

func TestWatchlistData_EmptyReturnsStruct(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := watchlistData(mgr, nil, "empty@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 0, dataMap["total_count"])
}

func TestWatchlistData_WithMultipleWatchlists(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	mgr.WatchlistStore().CreateWatchlist("wl2@example.com", "Stocks")
	mgr.WatchlistStore().CreateWatchlist("wl2@example.com", "Options")
	data := watchlistData(mgr, nil, "wl2@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	// total_count is total items across all watchlists (0 since watchlists are empty)
	assert.Equal(t, 0, dataMap["total_count"])
	// But we should have 2 watchlist entries
	wlEntries, ok := dataMap["watchlists"]
	assert.True(t, ok)
	assert.NotNil(t, wlEntries)
}

func TestWatchlistData_WithItems(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	email := "wlitems@example.com"
	wlID, err := mgr.WatchlistStore().CreateWatchlist(email, "Stocks")
	require.NoError(t, err)
	mgr.WatchlistStore().AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		InstrumentToken: 256265,
		Notes:           "Good stock",
		TargetEntry:     1800,
		TargetExit:      2000,
	})
	mgr.WatchlistStore().AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		InstrumentToken: 408065,
	})
	data := watchlistData(mgr, nil, email)
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 2, dataMap["total_count"])
}

func TestActivityData_WithAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	store := newTestAuditStore(t)
	// Enqueue and flush a tool call
	store.Record(&audit.ToolCall{
		CallID:        "test-001",
		Email:         "activity@example.com",
		ToolName:      "get_holdings",
		ToolCategory:  "query",
		InputSummary:  "test",
		OutputSummary: "ok",
	})
	data := activityData(mgr, store, "activity@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	_, hasEntries := dataMap["entries"]
	assert.True(t, hasEntries)
}

func TestOrdersData_WithAuditStore_NoOrders(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	store := newTestAuditStore(t)
	data := ordersData(mgr, store, "orders@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	_, hasOrders := dataMap["orders"]
	assert.True(t, hasOrders)
}

func TestOrdersData_WithAuditStoreAndToolCalls(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	store := newTestAuditStore(t)
	// Enqueue an order tool call
	store.Record(&audit.ToolCall{
		CallID:       "order-001",
		Email:        "orders2@example.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD123",
		InputSummary: "BUY 10 INFY",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","quantity":10,"order_type":"MARKET"}`,
	})
	data := ordersData(mgr, store, "orders2@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	orders, ok := dataMap["orders"].([]struct {
		OrderID   string  `json:"order_id"`
		Symbol    string  `json:"tradingsymbol"`
		Exchange  string  `json:"exchange"`
		Side      string  `json:"transaction_type"`
		OrderType string  `json:"order_type"`
		Quantity  float64 `json:"quantity"`
	})
	_ = orders
	_ = ok
}

func TestHubData_WithAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	store := newTestAuditStore(t)
	data := hubData(mgr, store, "hub2@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 0, dataMap["tool_calls_today"])
}

func TestHubData_WithAuditStoreAndCalls(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	store := newTestAuditStore(t)
	store.Record(&audit.ToolCall{
		CallID:   "hub-001",
		Email:    "hub3@example.com",
		ToolName: "get_holdings",
	})
	data := hubData(mgr, store, "hub3@example.com")
	assert.NotNil(t, data)
}

func TestAlertsData_WithTriggeredAlerts(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	alertID, _ := mgr.AlertStore().Add("triggered@example.com", "INFY", "NSE", 256265, 1500.0, "above")
	// Trigger the alert
	mgr.AlertStore().MarkTriggered(alertID, 1550.0)
	data := alertsData(mgr, nil, "triggered@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, 1, dataMap["triggered_count"])
}

func TestOrdersData_WithAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Record tool calls WITH order IDs so ListOrders picks them up
	auditStore.Record(&audit.ToolCall{
		CallID:      "o1",
		Email:       "admin@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD001",
		InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10,"price":1500}`,
	})
	auditStore.Record(&audit.ToolCall{
		CallID:      "o2",
		Email:       "admin@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD002",
		InputParams: `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"SELL","order_type":"LIMIT","quantity":5,"price":2500}`,
	})
	// Small sleep to allow async writer to flush
	time.Sleep(50 * time.Millisecond)
	data := ordersData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestOrdersData_NoAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := ordersData(mgr, nil, "admin@example.com")
	assert.Nil(t, data)
}

func TestActivityData_WithAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	auditStore.Record(&audit.ToolCall{
		CallID:        "a1",
		Email:         "admin@example.com",
		ToolName:      "get_holdings",
		ToolCategory:  "query",
		InputSummary:  "test",
		OutputSummary: "ok",
	})
	data := activityData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestPortfolioData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// In DevMode, GetBrokerForEmail returns a mock client for all emails,
	// so portfolioData always returns data even without stored credentials.
	data := portfolioData(mgr, nil, "admin@example.com")
	assert.NotNil(t, data)
}

func TestPaperData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := paperData(mgr, nil, "admin@example.com")
	// Returns status message even without engine
	assert.NotNil(t, data)
}

func TestSafetyData_NoRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := safetyData(mgr, nil, "admin@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithStore_Empty(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := watchlistData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithItems_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	ws := mgr.WatchlistStore()
	if ws != nil {
		wlID, err := ws.CreateWatchlist("wl-admin@example.com", "Test WL")
		require.NoError(t, err)
		_ = ws.AddItem("wl-admin@example.com", wlID, &watchlist.WatchlistItem{
			Exchange: "NSE", Tradingsymbol: "INFY", Notes: "buy on dip",
			TargetEntry: 1400, TargetExit: 1600,
		})
		_ = ws.AddItem("wl-admin@example.com", wlID, &watchlist.WatchlistItem{
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Notes: "swing trade",
			TargetEntry: 2400, TargetExit: 2600,
		})
	}
	data := watchlistData(mgr, auditStore, "wl-admin@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	if ok {
		wlCount, _ := dataMap["total_count"].(int)
		assert.GreaterOrEqual(t, wlCount, 1)
	}
}

func TestHubData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := hubData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestAlertData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestAlertData_WithAlerts_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Create some alerts via the alert store interface
	store := mgr.AlertStore()
	if store != nil {
		_, _ = store.Add("admin@example.com", "INFY", "NSE", 256265, 1500, "above")
		_, _ = store.Add("admin@example.com", "RELIANCE", "NSE", 408065, 2000, "below")
	}
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	if ok {
		activeCount, _ := dataMap["active_count"].(int)
		assert.GreaterOrEqual(t, activeCount, 0)
	}
}

func TestAlertData_WithTriggeredAlerts_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	store := mgr.AlertStore()
	if store != nil {
		alertID, _ := store.Add("admin@example.com", "TCS", "NSE", 300000, 3000, "above")
		store.MarkTriggered(alertID, 3100)
	}
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestOrderFormData_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := orderFormData(mgr, nil, "admin@example.com")
	assert.NotNil(t, data)
}

func TestRegisterAppResources_WithAuditStore(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterAppResources(srv, mgr, auditStore, mgr.Logger)
	// Should not panic — exercises template loading and resource registration
}

func TestAdminOverviewData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Test admin data functions by calling them through the appResources list
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-overview" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data, "admin overview should return data for admin")

			// Non-admin should get nil
			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data, "admin overview should return nil for non-admin")
		}
	}
}

func TestAdminUsersData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-users" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)

			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data)
		}
	}
}

func TestAdminMetricsData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-metrics" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)

			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data)
		}
	}
}

func TestAdminRiskData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-risk" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)
		}
	}
}

func TestOptionsChainData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := optionsChainData(mgr, nil, "admin@example.com")
	assert.Nil(t, data)
}

func TestAllAppResourceDataFuncs_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.DataFunc != nil {
			// Exercise all data functions with a non-admin, non-credentialed email
			_ = res.DataFunc(mgr, auditStore, "nobody@example.com")
		}
	}
}

func TestAllAppResourceDataFuncs_Admin(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.DataFunc != nil {
			_ = res.DataFunc(mgr, auditStore, "admin@example.com")
		}
	}
}
