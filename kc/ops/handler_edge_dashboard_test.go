package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// user_render.go: safetyToFreezeData with frozen status
// ---------------------------------------------------------------------------
func TestPush100_SafetyToFreezeData_Frozen(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"status": map[string]any{
			"is_frozen":     true,
			"frozen_reason": "market volatility",
			"frozen_by":     "admin@test.com",
			"frozen_at":     "2026-03-15T10:30:00Z",
		},
	}
	result := safetyToFreezeData(data)
	assert.True(t, result.Enabled)
	assert.True(t, result.IsFrozen)
	assert.Equal(t, "market volatility", result.FrozenReason)
	assert.Equal(t, "admin@test.com", result.FrozenBy)
	assert.Contains(t, result.FrozenAtFmt, "15 Mar")
}


func TestPush100_SafetyToFreezeData_FrozenZeroTime(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"status": map[string]any{
			"is_frozen":  true,
			"frozen_at":  "0001-01-01T00:00:00Z",
		},
	}
	result := safetyToFreezeData(data)
	assert.True(t, result.IsFrozen)
	assert.Equal(t, "", result.FrozenAtFmt) // zero time filtered out
}


func TestPush100_SafetyToFreezeData_DisabledWithCustomMessage(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": false,
		"message": "Custom disabled message",
	}
	result := safetyToFreezeData(data)
	assert.False(t, result.Enabled)
	assert.Equal(t, "Custom disabled message", result.Message)
}


// ---------------------------------------------------------------------------
// user_render.go: safetyToLimitsData with high utilization
// ---------------------------------------------------------------------------
func TestPush100_SafetyToLimitsData_FullUtilization(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"status": map[string]any{
			"daily_order_count": float64(190),
			"daily_placed_value": float64(950000),
		},
		"limits": map[string]any{
			"max_orders_per_day":    float64(200),
			"max_daily_value_inr":   float64(1000000),
			"max_single_order_inr":  float64(500000),
			"max_orders_per_minute": float64(10),
			"duplicate_window_secs": float64(30),
		},
	}
	result := safetyToLimitsData(data)
	assert.True(t, result.Enabled)
	assert.Len(t, result.Limits, 5)
	// Daily orders: 190/200 = 95% -> danger
	assert.Equal(t, "danger", result.Limits[0].BarClass)
	// Daily value: 950000/1000000 = 95% -> danger
	assert.Equal(t, "danger", result.Limits[1].BarClass)
	// Static items have no bar
	assert.True(t, result.Limits[2].Static)
	assert.True(t, result.Limits[3].Static)
	assert.True(t, result.Limits[4].Static)
}


func TestPush100_SafetyToLimitsData_LowUtilization(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"status": map[string]any{
			"daily_order_count":  float64(10),
			"daily_placed_value": float64(50000),
		},
		"limits": map[string]any{
			"max_orders_per_day":    float64(200),
			"max_daily_value_inr":   float64(1000000),
			"max_single_order_inr":  float64(500000),
			"max_orders_per_minute": float64(10),
			"duplicate_window_secs": float64(30),
		},
	}
	result := safetyToLimitsData(data)
	// 10/200 = 5% -> safe
	assert.Equal(t, "safe", result.Limits[0].BarClass)
}


func TestPush100_SafetyToLimitsData_ZeroLimits(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"status": map[string]any{
			"daily_order_count": float64(5),
		},
		"limits": map[string]any{
			"max_orders_per_day":  float64(0),
			"max_daily_value_inr": float64(0),
		},
	}
	result := safetyToLimitsData(data)
	// Zero max -> pct stays 0 -> safe
	assert.Equal(t, "safe", result.Limits[0].BarClass)
}


// ---------------------------------------------------------------------------
// user_render.go: safetyToSEBIData with mixed booleans
// ---------------------------------------------------------------------------
func TestPush100_SafetyToSEBIData_MixedBools(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"enabled": true,
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   false,
			"credentials_set":  true,
			"order_tagging":    false,
			"audit_trail":      true,
		},
	}
	result := safetyToSEBIData(data)
	assert.True(t, result.Enabled)
	assert.Equal(t, "ok", result.Checks[0].DotClass)  // static_egress_ip = true
	assert.Equal(t, "off", result.Checks[1].DotClass) // session_active = false
	assert.Equal(t, "ok", result.Checks[2].DotClass)  // credentials_set = true
	assert.Equal(t, "off", result.Checks[3].DotClass) // order_tagging = false
	assert.Equal(t, "ok", result.Checks[4].DotClass)  // audit_trail = true
}


// ---------------------------------------------------------------------------
// user_render.go: marketIndicesToBarData with negative change
// ---------------------------------------------------------------------------
func TestPush100_MarketIndicesToBarData_NegativeChange(t *testing.T) {
	t.Parallel()
	indices := map[string]any{
		"NSE:NIFTY 50": map[string]any{
			"last_price": float64(22500),
			"change":     float64(-150),
			"change_pct": float64(-0.66),
		},
	}
	result := marketIndicesToBarData(indices)
	assert.True(t, len(result.Indices) >= 1)
	// NIFTY 50 should have "down" class
	found := false
	for _, idx := range result.Indices {
		if idx.Label == "NIFTY 50" {
			found = true
			assert.Equal(t, "down", idx.ChangeClass)
			assert.Equal(t, "22500", idx.PriceFmt)
		}
	}
	assert.True(t, found)
}


// ---------------------------------------------------------------------------
// user_render.go: portfolioToStatsData — ticker running branch
// ---------------------------------------------------------------------------
func TestPush100_PortfolioToStatsData_TickerRunning(t *testing.T) {
	t.Parallel()
	status := statusResponse{
		KiteToken: tokenStatus{Valid: true},
		Ticker:    tickerStatus{Running: true, Subscriptions: 5},
	}
	portfolio := portfolioResponse{
		Summary: portfolioSummary{
			HoldingsCount: 10,
			TotalPnL:      5000,
			PositionsPnL:  1000,
			TotalCurrent:  100000,
		},
	}
	result := portfolioToStatsData(status, portfolio, 3)
	// Ticker card should show "5 feeds"
	found := false
	for _, c := range result.Cards {
		if c.Label == "Ticker" {
			found = true
			assert.Equal(t, "5 feeds", c.Value)
			assert.Equal(t, "green", c.Class)
		}
	}
	assert.True(t, found)
}


func TestPush100_PortfolioToStatsData_ZeroCurrentValue(t *testing.T) {
	t.Parallel()
	status := statusResponse{
		KiteToken: tokenStatus{Valid: true},
	}
	portfolio := portfolioResponse{
		Summary: portfolioSummary{
			TotalCurrent: 0,
		},
	}
	// Should not panic on division by zero
	result := portfolioToStatsData(status, portfolio, 0)
	assert.NotNil(t, result.Cards)
}


// ---------------------------------------------------------------------------
// user_render.go: pnlDisplayClass edge cases
// ---------------------------------------------------------------------------
func TestPush100_PnlDisplayClass_ZeroValue(t *testing.T) {
	t.Parallel()
	zero := 0.0
	assert.Equal(t, "pnl-zero", pnlDisplayClass(&zero))
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: paperStatusToBanner/paperStatusToStats
// ---------------------------------------------------------------------------
func TestPush100_PaperStatusToBanner_NotEnabled(t *testing.T) {
	t.Parallel()
	result := paperStatusToBanner(map[string]any{"enabled": false})
	assert.False(t, result.Enabled)
}


func TestPush100_PaperStatusToStats_AllZero(t *testing.T) {
	t.Parallel()
	result := paperStatusToStats(map[string]any{})
	assert.Len(t, result.Cards, 4)
	assert.Equal(t, "\u20B90.00", result.Cards[0].Value) // zero cash
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: paperDataToTables with orders
// ---------------------------------------------------------------------------
func TestPush100_PaperDataToTables_WithOrders(t *testing.T) {
	t.Parallel()
	orders := []map[string]any{
		{
			"order_id":         "abc123456789",
			"tradingsymbol":    "INFY",
			"transaction_type": "SELL",
			"order_type":       "MARKET",
			"quantity":         float64(10),
			"price":            float64(0),
			"status":           "COMPLETE",
			"placed_at":        "2026-03-15T10:00:00Z",
		},
		{
			"order_id":         "def456",
			"tradingsymbol":    "TCS",
			"transaction_type": "BUY",
			"order_type":       "LIMIT",
			"quantity":         float64(5),
			"price":            float64(3500),
			"status":           "REJECTED",
			"placed_at":        "",
		},
	}
	result := paperDataToTables(nil, nil, orders)
	assert.Len(t, result.Orders, 2)
	assert.Equal(t, "abc12345", result.Orders[0].OrderIDShort) // truncated to 8
	assert.Equal(t, "badge-red", result.Orders[0].SideBadge)   // SELL
	assert.Equal(t, "badge-green", result.Orders[0].StatusBadge) // COMPLETE
	assert.Equal(t, "def456", result.Orders[1].OrderIDShort) // short, not truncated
	assert.Equal(t, "badge-green", result.Orders[1].SideBadge) // BUY
	assert.Equal(t, "badge-red", result.Orders[1].StatusBadge) // REJECTED
}


func TestPush100_PaperDataToTables_CancelledOrder(t *testing.T) {
	t.Parallel()
	orders := []map[string]any{
		{
			"order_id": "abc", "tradingsymbol": "X",
			"transaction_type": "BUY", "status": "CANCELLED",
		},
	}
	result := paperDataToTables(nil, nil, orders)
	assert.Equal(t, "badge-red", result.Orders[0].StatusBadge)
}


func TestPush100_PaperDataToTables_OpenOrder(t *testing.T) {
	t.Parallel()
	orders := []map[string]any{
		{
			"order_id": "abc", "tradingsymbol": "X",
			"transaction_type": "BUY", "status": "OPEN",
		},
	}
	result := paperDataToTables(nil, nil, orders)
	assert.Equal(t, "badge-amber", result.Orders[0].StatusBadge)
}


// ===========================================================================
// dashboard.go: marketIndices — no email, no creds, no token
// ===========================================================================
func TestPush100_MarketIndices_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_MarketIndices_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/market-indices", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "no_credentials")
}


func TestPush100_MarketIndices_NoToken(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})

	req := push100DashReq(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "no_session")
}


// ===========================================================================
// dashboard.go: portfolio — no email, no creds, no token
// ===========================================================================
func TestPush100_Portfolio_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_Portfolio_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_Portfolio_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_Portfolio_NoToken(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: pnlChartAPI — no alertDB, with data, period clamping
// ===========================================================================
func TestPush100_PnlChartAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_PnlChartAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/pnl-chart", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_PnlChartAPI_SuccessEmpty(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/pnl-chart?period=30", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "points")
}


func TestPush100_PnlChartAPI_PeriodClamp(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Period > 365 gets clamped
	req := push100DashReq(http.MethodGet, "/dashboard/api/pnl-chart?period=999", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	assert.LessOrEqual(t, resp["period"], float64(365))
}


// ===========================================================================
// dashboard.go: paper endpoints — no engine, success
// ===========================================================================
func TestPush100_PaperStatus_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_PaperStatus_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/status", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_PaperStatus_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_PaperStatus_Success(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	paperStore := papertrading.NewStore(mgr.AlertDB(), slog.Default())
	require.NoError(t, paperStore.InitTables())
	pe := papertrading.NewEngine(paperStore, slog.Default())
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_PaperHoldings_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_PaperHoldings_Success(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	paperStore := papertrading.NewStore(mgr.AlertDB(), slog.Default())
	require.NoError(t, paperStore.InitTables())
	pe := papertrading.NewEngine(paperStore, slog.Default())
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_PaperPositions_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_PaperOrders_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_PaperReset_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper/reset", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_PaperReset_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_PaperReset_Success(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	paperStore := papertrading.NewStore(mgr.AlertDB(), slog.Default())
	require.NoError(t, paperStore.InitTables())
	pe := papertrading.NewEngine(paperStore, slog.Default())
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}


// ===========================================================================
// dashboard.go: sectorExposureAPI — no email, no creds, no token
// ===========================================================================
func TestPush100_SectorExposure_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_SectorExposure_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/sector-exposure", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_SectorExposure_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: taxAnalysisAPI — no email, no creds, no token
// ===========================================================================
func TestPush100_TaxAnalysis_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_TaxAnalysis_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/tax-analysis", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_TaxAnalysis_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: portfolio — with creds+token (Kite fails)
// ===========================================================================
func TestPush100_Portfolio_WithCredsKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Kite API returns error — handler returns 502
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}


// ===========================================================================
// dashboard.go: marketIndices — with creds+token (Kite fails)
// ===========================================================================
func TestPush100_MarketIndices_WithCredsKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}


// ===========================================================================
// dashboard.go: sectorExposureAPI — with creds+token (Kite fails)
// ===========================================================================
func TestPush100_SectorExposure_WithCredsKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}


// ===========================================================================
// dashboard.go: taxAnalysisAPI — with creds+token (Kite fails)
// ===========================================================================
func TestPush100_TaxAnalysis_WithCredsKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}
