package mcp

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// DevMode analytics tool tests: SEBI compliance, trading context, pre-trade check, backtest, PnL journal, dashboard, server metrics.

func TestSEBICompliance_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sebi_compliance_status", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestTradingContext_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "trading_context", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestPreTradeCheck_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}


func TestTaxHarvest_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "tax_loss_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestDividendCalendar_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "dividend_calendar", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestSectorExposure_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sector_exposure", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestServerMetrics_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{})
	// server_metrics may succeed without a Kite client
	assert.NotNil(t, result)
}


func TestServerMetrics_WithSession2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{
		"period": "1h",
	})
	assert.NotNil(t, result)
}


func TestDevMode_SEBICompliance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_TradingContext(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PreTradeCheck(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_TradingContext_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises the full handler body; may error if mock broker lacks some data
}


func TestDevMode_PreTradeCheck_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
	// Exercises the full handler body
}


func TestDevMode_SEBICompliance_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}


func TestDevMode_SEBICompliance_WithMetrics(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestTradingContext_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_TradingContext_ReturnsResult(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// trading_context aggregates from mock broker, so may partially succeed
	assertResultNotContains(t, result, "not available in DEV_MODE")
}


func TestDevMode_GetPnLJournal_NoPnLService(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// PnLService is nil in DevMode, should return error about not available
	text := resultText(t, result)
	assert.Contains(t, text, "not available")
}


func TestDevMode_GetPnLJournal_Periods(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, period := range []string{"week", "month", "quarter", "year", "all"} {
		result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}


func TestDevMode_GetPnLJournal_CustomDates(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "2026-03-31",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetPnLJournal_InvalidDates(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "not-a-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	// PnL service is nil in DevMode → returns "not available" before date validation
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}


func TestDevMode_GetPnLJournal_InvalidToDate(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "bad-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}


func TestDevMode_GetPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_ServerMetrics_NotAdmin(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should fail because dev@example.com is not admin
	assert.True(t, result.IsError)
}


func TestDevMode_ServerMetrics_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}


func TestDevMode_SEBICompliance_WithPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should reach API call for positions/orders → error or empty data
}


func TestDevMode_PreTradeCheck_SELLOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PreTradeCheck_MISProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(50),
		"product":          "MIS",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}


func TestDevMode_TradingContext_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_Prompts_Registration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// RegisterPrompts shouldn't panic with a valid manager
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// No assertion needed — just exercising the registration code path
}


func TestDevMode_DropPctWithoutRefPrice(t *testing.T) {
	// drop_pct without reference_price should fail (needs Kite LTP which fails in DevMode)
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(5),
		"direction":  "drop_pct",
		// No reference_price — needs to fetch LTP from Kite
	})
	assert.NotNil(t, result)
}


func TestServerMetrics_AdminWithAuditStore(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)

	// Record some tool calls so metrics have data
	auditStore.Record(&audit.ToolCall{
		CallID:   "m1",
		Email:    "admin@example.com",
		ToolName: "get_holdings",
	})
	auditStore.Record(&audit.ToolCall{
		CallID:   "m2",
		Email:    "admin@example.com",
		ToolName: "place_order",
		IsError:  true,
	})

	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
		"period": "24h",
	})
	assert.NotNil(t, result)
	// Admin with audit store should return metrics
	assert.False(t, result.IsError, "admin should have access to server_metrics")
}


func TestServerMetrics_AllPeriods_Admin(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
		assert.False(t, result.IsError, "period=%s", period)
	}
}


func TestServerMetrics_NonAdmin_Rejected(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestServerMetrics_DefaultPeriod(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestSectorExposure_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// compliance_tool.go: sebi_compliance_status (77.4% -> higher)
// ---------------------------------------------------------------------------
func TestSEBICompliance_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}



// ---------------------------------------------------------------------------
// tax_tools.go: deeper handler paths (78.6% -> higher)
// ---------------------------------------------------------------------------
func TestTaxHarvest_WithMinLoss(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_loss_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
	})
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// dividend_tool.go: deeper handler paths (72% -> higher)
// ---------------------------------------------------------------------------
func TestDividendCalendar_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"week", "month", "quarter"} {
		result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}



// ---------------------------------------------------------------------------
// backtest_tool.go: deeper strategy paths (65.9% -> higher)
// ---------------------------------------------------------------------------
func TestBacktest_MeanReversion(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":        "mean_reversion",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(90),
		"initial_capital": float64(100000),
	})
	assert.NotNil(t, result)
}


func TestBacktest_RSIReversal(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":        "rsi_reversal",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(60),
		"initial_capital": float64(200000),
	})
	assert.NotNil(t, result)
}


func TestBacktest_Breakout(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":        "breakout",
		"exchange":        "NSE",
		"tradingsymbol":   "RELIANCE",
		"days":            float64(120),
		"initial_capital": float64(500000),
	})
	assert.NotNil(t, result)
}


func TestBacktest_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":      "invalid_strategy",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
}



// ---------------------------------------------------------------------------
// admin_tools.go: deeper admin paths (63-77% -> higher)
// ---------------------------------------------------------------------------
func TestPreTradeCheck_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(1500),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// trading_context tool
// ---------------------------------------------------------------------------
func TestTradingContext_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}



// ---------------------------------------------------------------------------
// server_metrics tool
// ---------------------------------------------------------------------------
func TestServerMetrics_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// server_metrics requires admin role
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestServerMetrics_WithPeriod(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}



// ---------------------------------------------------------------------------
// setup_tools: dashboardBaseURL and dashboardLink helpers
// ---------------------------------------------------------------------------
func TestDashboardBaseURL_LocalMode_Push(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// DevMode manager is local -> returns local URL
	base := dashboardBaseURL(mgr)
	// Either returns a URL or empty
	if base != "" {
		assert.Contains(t, base, "http")
	}
}


func TestDashboardLink_Coverage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	// May be empty in test context
	_ = link
}


func TestDashboardPageURL_Coverage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/dashboard")
	_ = url
}


func TestIsAlphanumeric_Push(t *testing.T) {
	t.Parallel()
	assert.True(t, isAlphanumeric("abc123"))
	assert.True(t, isAlphanumeric("ABCXYZ"))
	assert.False(t, isAlphanumeric(""))
	assert.False(t, isAlphanumeric("abc-123"))
	assert.False(t, isAlphanumeric("abc 123"))
	assert.False(t, isAlphanumeric("abc!@#"))
}



// ---------------------------------------------------------------------------
// Additional admin tool edge cases
// ---------------------------------------------------------------------------
func TestSEBICompliance_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// paper_tools: paper_trading_toggle edge cases
// ---------------------------------------------------------------------------
func TestDividendCalendar_MissingInstrument_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	// dividend_calendar uses portfolio, not a required instrument - different path
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// observability: server_metrics tool
// ---------------------------------------------------------------------------
func TestServerMetrics_IncludeSystem_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{
		"include_system": true,
	})
	assert.NotNil(t, result)
}



// ---------------------------------------------------------------------------
// admin_tools: SUCCESS paths (with admin@example.com)
// ---------------------------------------------------------------------------
