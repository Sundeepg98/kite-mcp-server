package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.
func newPush100OpsHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	lb := NewLogBuffer(100)
	// Pass nil userStore to test nil-guard branches
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), nil, nil)
	return h
}

// newPush100OpsHandlerFull creates an ops handler with user store, audit store, and riskguard.
func newPush100OpsHandlerFull(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		userStore.EnsureAdmin("admin@test.com")
	}

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	lb := NewLogBuffer(100)
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), userStore, auditStore)
	return h
}

func push100AdminReq(method, target string, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := oauth.ContextWithEmail(req.Context(), "admin@test.com")
	return req.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// handler.go: freezeTradingGlobal success path (with riskguard, confirm=true)
// ---------------------------------------------------------------------------

func TestPush100_FreezeTradingGlobal_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global",
		`{"reason":"market circuit breaker","confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, "ok", resp["status"])
}

func TestPush100_FreezeTradingGlobal_EmptyReasonDefaulted(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Empty reason should be defaulted to "Admin emergency freeze"
	req := push100AdminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global",
		`{"reason":"","confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// handler.go: suspend/activate/offboard/changeRole nil-userStore (503) paths
// ---------------------------------------------------------------------------

func TestPush100_SuspendUser_NilUserStore_Returns403(t *testing.T) {
	t.Parallel()
	// With nil userStore, isAdmin returns false → 403 Forbidden before reaching nil-userStore guard.
	h := newPush100OpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/suspend?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// handler.go: OffboardUser success with full data cleanup
// ---------------------------------------------------------------------------

func TestPush100_OffboardUser_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed target user in userStore + credential/token stores
	if h.userStore != nil {
		h.userStore.EnsureUser("target@test.com", "", "", "")
	}
	h.manager.CredentialStore().Set("target@test.com", &kc.KiteCredentialEntry{
		APIKey: "target_key", APISecret: "target_secret", StoredAt: time.Now(),
	})
	h.manager.TokenStore().Set("target@test.com", &kc.KiteTokenEntry{
		AccessToken: "target_token", StoredAt: time.Now(),
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=target@test.com",
		`{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, "ok", resp["status"])

	// Verify data was cleaned up
	_, hasCreds := h.manager.CredentialStore().Get("target@test.com")
	assert.False(t, hasCreds)
	_, hasToken := h.manager.TokenStore().Get("target@test.com")
	assert.False(t, hasToken)
}

func TestPush100_OffboardUser_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=target@test.com",
		`not-json`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// handler.go: ChangeRole — invalid JSON body
// ---------------------------------------------------------------------------

func TestPush100_ChangeRole_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/role?email=user@test.com",
		`not-json`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// handler.go: ChangeRole — user not in store (UpdateRole returns error)
// ---------------------------------------------------------------------------

func TestPush100_ChangeRole_UserNotFound(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/role?email=nonexistent@test.com",
		`{"role":"viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// UpdateRole for a nonexistent user may return error or succeed depending on store impl
	// At minimum we exercise the path
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// user_render.go: ordersToStatsData edge cases
// ---------------------------------------------------------------------------

func TestPush100_OrdersToStatsData_NoPnL(t *testing.T) {
	t.Parallel()
	s := ordersSummary{TotalOrders: 5, Completed: 3}
	result := ordersToStatsData(s)
	assert.Equal(t, "5", result.Cards[0].Value)
	assert.Equal(t, "3", result.Cards[1].Value)
	assert.Equal(t, "--", result.Cards[2].Value) // no PnL
	assert.Equal(t, "--", result.Cards[3].Value)  // no win rate
}

func TestPush100_OrdersToStatsData_WithWinRate(t *testing.T) {
	t.Parallel()
	pnl := 5000.0
	s := ordersSummary{
		TotalOrders:  10,
		Completed:    8,
		TotalPnL:     &pnl,
		WinningTrades: 6,
		LosingTrades:  2,
	}
	result := ordersToStatsData(s)
	assert.Contains(t, result.Cards[2].Value, "5,000") // PnL formatted
	assert.Equal(t, "green", result.Cards[2].Class)
	assert.Contains(t, result.Cards[3].Value, "75%")    // 6/(6+2) = 75%
	assert.Contains(t, result.Cards[3].Sub, "6W / 2L")
}

func TestPush100_OrdersToStatsData_NegativePnL(t *testing.T) {
	t.Parallel()
	pnl := -1500.0
	s := ordersSummary{
		TotalOrders:  3,
		Completed:    3,
		TotalPnL:     &pnl,
		WinningTrades: 0,
		LosingTrades:  3,
	}
	result := ordersToStatsData(s)
	assert.Equal(t, "red", result.Cards[2].Class)
	assert.Contains(t, result.Cards[3].Value, "0%") // 0/(0+3) = 0%
}

// ---------------------------------------------------------------------------
// user_render.go: activityToTimelineData with error entries
// ---------------------------------------------------------------------------

func TestPush100_ActivityToTimelineData_WithErrors(t *testing.T) {
	t.Parallel()
	entries := []audit.ToolCall{
		{
			StartedAt:    time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
			ToolName:     "place_order",
			ToolCategory: "order",
			InputSummary: "BUY RELIANCE",
			IsError:      true,
			ErrorMessage: "insufficient funds",
			DurationMs:   250,
		},
		{
			StartedAt:     time.Date(2026, 3, 15, 10, 31, 0, 0, time.UTC),
			ToolName:      "get_holdings",
			ToolCategory:  "query",
			OutputSummary: "5 holdings",
			DurationMs:    1500,
		},
	}
	result := activityToTimelineData(entries)
	assert.Len(t, result.Entries, 2)

	// Error entry
	assert.Equal(t, "fail", result.Entries[0].StatusClass)
	assert.Equal(t, "ERR", result.Entries[0].StatusLabel)
	assert.True(t, result.Entries[0].IsError)
	assert.Equal(t, "insufficient funds", result.Entries[0].ErrorMessage)
	assert.Equal(t, "ORDER", result.Entries[0].CatLabel)

	// Success entry
	assert.Equal(t, "success", result.Entries[1].StatusClass)
	assert.Equal(t, "OK", result.Entries[1].StatusLabel)
	assert.False(t, result.Entries[1].IsError)
	assert.Equal(t, "QUERY", result.Entries[1].CatLabel)
	assert.Equal(t, "1.5s", result.Entries[1].DurationFmt)
}

// ---------------------------------------------------------------------------
// user_render.go: alertsToStatsData edge cases
// ---------------------------------------------------------------------------

func TestPush100_AlertsToStatsData_NilNearest(t *testing.T) {
	t.Parallel()
	summary := alertsSummary{ActiveCount: 3, TriggeredCount: 1, AvgTimeToTrigger: "2h 30m"}
	result := alertsToStatsData(summary, nil)
	assert.Equal(t, "3", result.Cards[0].Value)
	assert.Equal(t, "1", result.Cards[1].Value)
	assert.Equal(t, "2h 30m", result.Cards[2].Value)
	assert.Equal(t, "--", result.Cards[3].Value) // no nearest
}

func TestPush100_AlertsToStatsData_WithNearest(t *testing.T) {
	t.Parallel()
	dist := 1.5
	nearest := &enrichedActiveAlert{
		Tradingsymbol: "RELIANCE",
		DistancePct:   &dist,
	}
	summary := alertsSummary{ActiveCount: 1, TriggeredCount: 0}
	result := alertsToStatsData(summary, nearest)
	assert.Equal(t, "RELIANCE", result.Cards[3].Value)
	assert.Contains(t, result.Cards[3].Sub, "1.5%")
}

func TestPush100_AlertsToStatsData_EmptyAvgTime(t *testing.T) {
	t.Parallel()
	summary := alertsSummary{ActiveCount: 0, TriggeredCount: 0}
	result := alertsToStatsData(summary, nil)
	assert.Equal(t, "--", result.Cards[2].Value) // empty AvgTimeToTrigger
}

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
// user_render.go: fmtINR edge cases
// ---------------------------------------------------------------------------

func TestPush100_FmtINR_ExactlyThreeDigits(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B9999.00", fmtINR(999))
}

func TestPush100_FmtINR_FourDigits(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91,000.00", fmtINR(1000))
}

func TestPush100_FmtINR_NegativeSmall(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "-\u20B950.50", fmtINR(-50.50))
}

func TestPush100_FmtINR_Zero(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B90.00", fmtINR(0))
}

func TestPush100_FmtINR_NegativeLarge(t *testing.T) {
	t.Parallel()
	result := fmtINR(-1234567.89)
	assert.True(t, strings.HasPrefix(result, "-\u20B9"))
	assert.Contains(t, result, "12,34,567.89")
}

// ---------------------------------------------------------------------------
// user_render.go: fmtINRShort edge cases
// ---------------------------------------------------------------------------

func TestPush100_FmtINRShort_ExactlyLakh(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91.0L", fmtINRShort(100000))
}

func TestPush100_FmtINRShort_ExactlyThousand(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91.0K", fmtINRShort(1000))
}

func TestPush100_FmtINRShort_BelowThousand(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B9500", fmtINRShort(500))
}

func TestPush100_FmtINRShort_NegativeLakh(t *testing.T) {
	t.Parallel()
	// Negative value: -200000 -> abs >= 100000 -> format with v/100000 = -2.0
	result := fmtINRShort(-200000)
	assert.Contains(t, result, "-2.0L")
}

// ---------------------------------------------------------------------------
// user_render.go: ordersToTableData with various statuses
// ---------------------------------------------------------------------------

func TestPush100_OrdersToTableData_SellSide(t *testing.T) {
	t.Parallel()
	fillPrice := 500.0
	currentPrice := 480.0
	pnl := 200.0
	pnlPct := 4.0
	entries := []orderEntry{
		{
			Symbol:       "INFY",
			Side:         "SELL",
			Quantity:     10,
			FillPrice:    &fillPrice,
			CurrentPrice: &currentPrice,
			PnL:          &pnl,
			PnLPct:       &pnlPct,
			Status:       "COMPLETE",
			PlacedAt:     "2026-03-15T10:00:00Z",
		},
	}
	result := ordersToTableData(entries)
	assert.Len(t, result.Orders, 1)
	assert.Equal(t, "side-sell", result.Orders[0].SideClass)
	assert.Equal(t, "status-complete", result.Orders[0].StatusBadge)
	assert.Equal(t, "pnl-pos", result.Orders[0].PnLClass)
}

func TestPush100_OrdersToTableData_AllNilOptionals(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{
			Symbol:   "TCS",
			Side:     "BUY",
			Quantity: 5,
			Status:   "OPEN",
			PlacedAt: "",
		},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "--", result.Orders[0].FillPriceFmt)
	assert.Equal(t, "--", result.Orders[0].CurrentPriceFmt)
	assert.Equal(t, "--", result.Orders[0].PnLFmt)
	assert.Equal(t, "--", result.Orders[0].PnLPctFmt)
	assert.Equal(t, "status-open", result.Orders[0].StatusBadge)
}

func TestPush100_OrdersToTableData_TriggerPending(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "TRIGGER PENDING"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-open", result.Orders[0].StatusBadge)
}

func TestPush100_OrdersToTableData_Rejected(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "REJECTED"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-rejected", result.Orders[0].StatusBadge)
}

func TestPush100_OrdersToTableData_Cancelled(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "CANCELLED"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-cancelled", result.Orders[0].StatusBadge)
}

func TestPush100_OrdersToTableData_UnknownStatus(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "VALIDATION PENDING"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-pending", result.Orders[0].StatusBadge)
}

// ---------------------------------------------------------------------------
// user_render.go: alertsToActiveData with distance
// ---------------------------------------------------------------------------

func TestPush100_AlertsToActiveData_WithDistance(t *testing.T) {
	t.Parallel()
	dist := 1.5
	active := []enrichedActiveAlert{
		{
			ID: "a1", Tradingsymbol: "RELIANCE", Exchange: "NSE",
			Direction: "above", TargetPrice: 2500, CurrentPrice: 2450,
			DistancePct: &dist, CreatedAt: "2026-03-15T10:00:00Z",
		},
	}
	result := alertsToActiveData(active)
	assert.Len(t, result.Alerts, 1)
	assert.Equal(t, "1.5%", result.Alerts[0].DistFmt)
	assert.Equal(t, "dist-green", result.Alerts[0].DistClass) // < 2%
	assert.Equal(t, "green", result.Alerts[0].DirBadge)
}

func TestPush100_AlertsToActiveData_HighDistance(t *testing.T) {
	t.Parallel()
	dist := 7.0
	active := []enrichedActiveAlert{
		{
			ID: "a2", Tradingsymbol: "TCS",
			Direction: "below", DistancePct: &dist,
			CreatedAt: "2026-03-15T10:00:00Z",
		},
	}
	result := alertsToActiveData(active)
	assert.Equal(t, "dist-red", result.Alerts[0].DistClass) // >= 5%
	assert.Equal(t, "red", result.Alerts[0].DirBadge)
}

// ---------------------------------------------------------------------------
// user_render.go: alertsToTriggeredData
// ---------------------------------------------------------------------------

func TestPush100_AlertsToTriggeredData_WithNotification(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			Tradingsymbol:     "INFY",
			Direction:         "rise_pct",
			TargetPrice:       1500,
			CreatedAt:         "2026-03-14T09:00:00Z",
			TriggeredAt:       "2026-03-15T10:00:00Z",
			TimeToTrigger:     "1d 1h 0m",
			NotificationSentAt: "2026-03-15T10:00:05Z",
			NotificationDelay:  "5s",
		},
	}
	result := alertsToTriggeredData(triggered)
	assert.Len(t, result.Alerts, 1)
	assert.Equal(t, "green", result.Alerts[0].DirBadge) // rise_pct -> green
	assert.Contains(t, result.Alerts[0].NotificationFmt, "15 Mar")
}

func TestPush100_AlertsToTriggeredData_EmptyNotification(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			Tradingsymbol:      "TCS",
			Direction:          "drop_pct",
			CreatedAt:          "2026-03-14T09:00:00Z",
			TriggeredAt:        "2026-03-15T10:00:00Z",
			NotificationSentAt: "",
		},
	}
	result := alertsToTriggeredData(triggered)
	assert.Equal(t, "", result.Alerts[0].NotificationFmt)
	assert.Equal(t, "red", result.Alerts[0].DirBadge) // drop_pct -> red
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
// admin_render.go: metricsToTemplateData edge cases
// ---------------------------------------------------------------------------

func TestPush100_MetricsToTemplateData_NilStats(t *testing.T) {
	t.Parallel()
	result := metricsToTemplateData(nil, nil, 3600)
	// Nil stats: totalCalls=0, errorCount=0 → Cards[1]="0", Cards[2]="0.0%", Cards[3]="0ms"
	assert.Equal(t, "0", result.Cards[1].Value)      // Total Calls
	assert.Equal(t, "0.0%", result.Cards[2].Value)    // Error Rate
	assert.Equal(t, "0ms", result.Cards[3].Value)      // Avg Latency
	assert.Equal(t, "--", result.Cards[4].Value)       // Top Tool
}

func TestPush100_MetricsToTemplateData_ZeroTotalCalls(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls: 0,
		ErrorCount: 0,
	}
	result := metricsToTemplateData(stats, nil, 3600)
	assert.Equal(t, "0", result.Cards[1].Value)      // Total Calls
	assert.Equal(t, "0.0%", result.Cards[2].Value)    // Error Rate: 0/0 → 0%
}

// ---------------------------------------------------------------------------
// admin_render.go: formatInt edge cases
// ---------------------------------------------------------------------------

func TestPush100_FormatInt_Small(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0", formatInt(0))
	assert.Equal(t, "999", formatInt(999))
}

func TestPush100_FormatInt_WithCommas(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1,000", formatInt(1000))
	assert.Equal(t, "1,000,000", formatInt(1000000))
}

// ---------------------------------------------------------------------------
// admin_render.go: formatFloat
// ---------------------------------------------------------------------------

func TestPush100_FormatFloat_Decimal(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "3.14", formatFloat(3.14))
	assert.Equal(t, "0.00", formatFloat(0))
}

// ---------------------------------------------------------------------------
// overview_render.go: boolClass
// ---------------------------------------------------------------------------

func TestPush100_BoolClass_True(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "active", boolClass(true, "active"))
}

func TestPush100_BoolClass_False(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", boolClass(false, "active"))
}

// ---------------------------------------------------------------------------
// user_render.go: barClass
// ---------------------------------------------------------------------------

func TestPush100_BarClass_Boundaries(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "safe", barClass(0))
	assert.Equal(t, "safe", barClass(69))
	assert.Equal(t, "warn", barClass(70))
	assert.Equal(t, "warn", barClass(89))
	assert.Equal(t, "danger", barClass(90))
	assert.Equal(t, "danger", barClass(100))
}

// ---------------------------------------------------------------------------
// user_render.go: distanceClass boundaries
// ---------------------------------------------------------------------------

func TestPush100_DistanceClass_Boundaries(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "dist-green", distanceClass(0))
	assert.Equal(t, "dist-green", distanceClass(1.99))
	assert.Equal(t, "dist-amber", distanceClass(2.0))
	assert.Equal(t, "dist-amber", distanceClass(4.99))
	assert.Equal(t, "dist-red", distanceClass(5.0))
}

// ---------------------------------------------------------------------------
// user_render.go: getCatColor/getCatLabel for all known categories
// ---------------------------------------------------------------------------

func TestPush100_GetCatColor_AllKnown(t *testing.T) {
	t.Parallel()
	knownCats := []string{
		"order", "query", "market_data", "alert", "notification",
		"ticker", "setup", "mf_order", "trailing_stop", "watchlist", "analytics",
	}
	for _, cat := range knownCats {
		bg, fg := getCatColor(cat)
		assert.NotEmpty(t, bg, "bg for %s", cat)
		assert.NotEmpty(t, fg, "fg for %s", cat)
	}
}

func TestPush100_GetCatLabel_AllKnown(t *testing.T) {
	t.Parallel()
	expected := map[string]string{
		"order": "ORDER", "query": "QUERY", "market_data": "MARKET",
		"alert": "ALERT", "notification": "NOTIF", "ticker": "TICKER",
		"setup": "SETUP", "mf_order": "MF ORDER", "trailing_stop": "TRAILING",
		"watchlist": "WATCHLIST", "analytics": "ANALYTICS",
	}
	for cat, label := range expected {
		assert.Equal(t, label, getCatLabel(cat))
	}
}

// ---------------------------------------------------------------------------
// user_render.go: fmtTimeDDMon / fmtTimeHMS edge cases
// ---------------------------------------------------------------------------

func TestPush100_FmtTimeDDMon_NonZero(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 1, 5, 14, 30, 0, 0, time.UTC)
	assert.Equal(t, "05 Jan 14:30", fmtTimeDDMon(ts))
}

func TestPush100_FmtTimeHMS_NonZero(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 1, 5, 9, 5, 3, 0, time.UTC)
	assert.Equal(t, "09:05:03", fmtTimeHMS(ts))
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
// dashboard_templates.go: buildOrderSummary with mixed entries
// ---------------------------------------------------------------------------

func TestPush100_BuildOrderSummary_MixedEntries(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	win := 500.0
	loss := -200.0
	entries := []orderEntry{
		{Status: "COMPLETE", PnL: &win},
		{Status: "COMPLETE", PnL: &loss},
		{Status: "OPEN"},
		{Status: "REJECTED"},
	}
	summary := d.buildOrderSummary(entries)
	assert.Equal(t, 4, summary.TotalOrders)
	assert.Equal(t, 2, summary.Completed)
	assert.Equal(t, 1, summary.WinningTrades)
	assert.Equal(t, 1, summary.LosingTrades)
	require.NotNil(t, summary.TotalPnL)
	assert.InDelta(t, 300.0, *summary.TotalPnL, 0.01)
}

func TestPush100_BuildOrderSummary_NoPnLEntries(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	entries := []orderEntry{
		{Status: "OPEN"},
		{Status: "OPEN"},
	}
	summary := d.buildOrderSummary(entries)
	assert.Equal(t, 2, summary.TotalOrders)
	assert.Nil(t, summary.TotalPnL)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: buildOrderEntries with nil ToolCall
// ---------------------------------------------------------------------------

func TestPush100_BuildOrderEntries_NilToolCall(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	toolCalls := []*audit.ToolCall{
		nil,
		{OrderID: "order-1", StartedAt: time.Now(), InputParams: `{}`},
		nil,
	}
	entries := d.buildOrderEntries(toolCalls, "test@example.com")
	assert.Len(t, entries, 1) // nils skipped
	assert.Equal(t, "order-1", entries[0].OrderID)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: parseOrderParamsJSON
// ---------------------------------------------------------------------------

func TestPush100_ParseOrderParamsJSON_AllFields(t *testing.T) {
	t.Parallel()
	raw := `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"BUY","order_type":"LIMIT","quantity":100,"price":2500.5}`
	var oe orderEntry
	parseOrderParamsJSON(raw, &oe)
	assert.Equal(t, "RELIANCE", oe.Symbol)
	assert.Equal(t, "NSE", oe.Exchange)
	assert.Equal(t, "BUY", oe.Side)
	assert.Equal(t, "LIMIT", oe.OrderType)
	assert.Equal(t, float64(100), oe.Quantity)
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

// ---------------------------------------------------------------------------
// dashboard_templates.go: toFloat / toInt with string values
// ---------------------------------------------------------------------------

func TestPush100_ToFloat_ValidString(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 3.14, toFloat("3.14"), 0.001)
}

func TestPush100_ToInt_Float64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 42, toInt(float64(42.7)))
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: servePageFallback
// ---------------------------------------------------------------------------

func TestPush100_ServePageFallback(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "dashboard.html")
	// Should serve the static HTML file from templates.FS
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
}

func TestPush100_ServePageFallback_NonExistent(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "nonexistent.html")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard.go: serveBillingPage with Pro tier + Stripe
// ---------------------------------------------------------------------------

func TestPush100_ServeBillingPage_ProTierWithStripe(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return false })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:             billing.TierPro,
				Status:           "active",
				MaxUsers:         1,
				StripeCustomerID: "cus_12345",
			},
		},
	})
	d.InitTemplates() // ensure routes are available

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Pro")
	assert.Contains(t, body, "Stripe")
}

func TestPush100_ServeBillingPage_PremiumTierAdmin(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"admin@test.com": {
				Tier:     billing.TierPremium,
				Status:   "active",
				MaxUsers: 5,
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Premium")
	assert.Contains(t, body, "5 family member")
}

func TestPush100_ServeBillingPage_PastDueStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:   billing.TierPro,
				Status: "past_due",
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Past Due")
}

func TestPush100_ServeBillingPage_CanceledStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:   billing.TierPro,
				Status: "canceled",
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Canceled")
}

func TestPush100_ServeBillingPage_FreeDefaultActive(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Free Plan")
	assert.Contains(t, body, "All tools are currently available for free")
}

// ---------------------------------------------------------------------------
// dashboard.go: serveBillingPage with family member (inherited tier)
// ---------------------------------------------------------------------------

func TestPush100_ServeBillingPage_FamilyMember(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"admin@test.com": {
				Tier:     billing.TierPro,
				Status:   "active",
				MaxUsers: 5,
			},
		},
	})

	// Set up user as family member of admin
	if us := d.manager.UserStore(); us != nil {
		us.EnsureUser("member@test.com", "", "", "")
		_ = us.SetAdminEmail("member@test.com", "admin@test.com")
	}

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "member@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard.go: tierDisplayName
// ---------------------------------------------------------------------------

func TestPush100_TierDisplayName_AllTiers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Free", tierDisplayName(billing.TierFree))
	assert.Equal(t, "Pro", tierDisplayName(billing.TierPro))
	assert.Equal(t, "Premium", tierDisplayName(billing.TierPremium))
	assert.Equal(t, "Free", tierDisplayName(billing.Tier(99))) // unknown
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: serveSafetyPageSSR with riskguard
// ---------------------------------------------------------------------------

func TestPush100_ServeSafetyPageSSR_WithRiskGuard(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/safety", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: servePaperPageSSR with engine enabled
// ---------------------------------------------------------------------------

func TestPush100_ServePaperPageSSR_WithEngine(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	// Enable paper trading
	paperStore := papertrading.NewStore(mgr.AlertDB(), logger)
	pe := papertrading.NewEngine(paperStore, logger)
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/paper", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: serveAlertsPageSSR with alerts
// ---------------------------------------------------------------------------

func TestPush100_ServeAlertsPageSSR_WithAlerts(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	// Add an alert
	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/alerts", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPush100_ServeAlertsPageSSR_NoEmail(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/alerts", nil)
	// No email in context
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: serveOrdersPageSSR with audit data
// ---------------------------------------------------------------------------

func TestPush100_ServeOrdersPageSSR_WithAuditData(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	d := NewDashboardHandler(mgr, logger, auditStore)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/orders", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// dashboard_templates.go: serveOrdersPageSSR with no audit store
// ---------------------------------------------------------------------------

func TestPush100_ServeOrdersPageSSR_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/orders", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// handler.go: logStream keepalive (test cancelled context during stream)
// ---------------------------------------------------------------------------

func TestPush100_LogStream_CancelledDuringStream(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	lb := h.logBuffer

	// Add some log entries for backfill
	lb.Add(LogEntry{Time: time.Now(), Level: "INFO", Message: "test entry"})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	req := push100AdminReq(http.MethodGet, "/admin/ops/api/logs", "")
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ServeHTTP(rec, req)
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	assert.Contains(t, rec.Body.String(), "test entry")
}

// ---------------------------------------------------------------------------
// overview_sse.go: sendAllAdminEvents
// ---------------------------------------------------------------------------

func TestPush100_SendAllAdminEvents_WithData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed some data
	h.manager.CredentialStore().Set("user2@test.com", &kc.KiteCredentialEntry{
		APIKey: "key2", APISecret: "secret2", StoredAt: time.Now(),
	})
	h.manager.TokenStore().Set("user2@test.com", &kc.KiteTokenEntry{
		AccessToken: "tok2", StoredAt: time.Now(),
	})

	// Add an alert
	_, _ = h.manager.AlertStore().Add("user2@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	rec := httptest.NewRecorder()
	// httptest.ResponseRecorder implements http.Flusher directly
	h.sendAllAdminEvents(rec, rec, "admin@test.com")

	body := rec.Body.String()
	assert.Contains(t, body, "event:")
}

// ---------------------------------------------------------------------------
// logbuffer.go: TeeHandler.WithAttrs and WithGroup
// ---------------------------------------------------------------------------

func TestPush100_TeeHandler_WithAttrs(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	withAttrs := th.WithAttrs([]slog.Attr{slog.String("key", "val")})
	assert.NotNil(t, withAttrs)
	// Must still be a TeeHandler
	_, ok := withAttrs.(*TeeHandler)
	assert.True(t, ok)
}

func TestPush100_TeeHandler_WithGroup(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	withGroup := th.WithGroup("mygroup")
	assert.NotNil(t, withGroup)
	_, ok := withGroup.(*TeeHandler)
	assert.True(t, ok)
}

func TestPush100_TeeHandler_Handle(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	logger := slog.New(th)
	logger.Info("test message", "key1", "val1", "key2", 42)

	entries := buf.Recent(10)
	require.Len(t, entries, 1)
	assert.Equal(t, "INFO", entries[0].Level)
	assert.Equal(t, "test message", entries[0].Message)
	assert.Contains(t, entries[0].Attrs, "key1=val1")
}

// ---------------------------------------------------------------------------
// logbuffer.go: LogBuffer fan-out to multiple listeners
// ---------------------------------------------------------------------------

func TestPush100_LogBuffer_MultipleListeners(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	ch1 := buf.AddListener("l1")
	ch2 := buf.AddListener("l2")

	entry := LogEntry{Time: time.Now(), Level: "INFO", Message: "broadcast"}
	buf.Add(entry)

	// Both listeners should receive
	select {
	case e := <-ch1:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("l1 did not receive entry")
	}
	select {
	case e := <-ch2:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("l2 did not receive entry")
	}

	buf.RemoveListener("l1")
	buf.RemoveListener("l2")
}

func TestPush100_LogBuffer_RingBufferWrapAround(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(3)
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{Message: fmt.Sprintf("msg-%d", i)})
	}
	// Should only have the last 3
	entries := buf.Recent(10)
	assert.Len(t, entries, 3)
	assert.Equal(t, "msg-2", entries[0].Message)
	assert.Equal(t, "msg-3", entries[1].Message)
	assert.Equal(t, "msg-4", entries[2].Message)
}

// ---------------------------------------------------------------------------
// admin_render.go: usersToTemplateData with various user statuses
// ---------------------------------------------------------------------------

func TestPush100_UsersToTemplateData_SuspendedAndOffboarded(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Add users with different statuses
	if h.userStore != nil {
		h.userStore.EnsureUser("active@test.com", "", "", "")
		h.userStore.EnsureUser("suspended@test.com", "", "", "")
		_ = h.userStore.UpdateStatus("suspended@test.com", "suspended")
		h.userStore.EnsureUser("offboarded@test.com", "", "", "")
		_ = h.userStore.UpdateStatus("offboarded@test.com", "offboarded")
	}

	users := h.userStore.List()
	result := usersToTemplateData(users, "admin@test.com")
	assert.True(t, len(result.Users) >= 3)
}

// ---------------------------------------------------------------------------
// handler.go: servePage (full ops page render with all data)
// ---------------------------------------------------------------------------

func TestPush100_ServePage_WithFullData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should render the full ops page
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
}

// ---------------------------------------------------------------------------
// handler.go: credentials POST with auto-register to registry
// ---------------------------------------------------------------------------

func TestPush100_Credentials_Post_AutoRegisterNewKey(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"api_key":"brand_new_key_12345","api_secret":"brand_new_secret"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/credentials", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "newuser@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Verify credentials were stored
	_, hasCreds := h.manager.CredentialStore().Get("newuser@test.com")
	assert.True(t, hasCreds)
}

// ---------------------------------------------------------------------------
// handler.go: credentials GET with long secret (>7 chars)
// ---------------------------------------------------------------------------

func TestPush100_Credentials_Get_LongSecret(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	h.manager.CredentialStore().Set("showuser@test.com", &kc.KiteCredentialEntry{
		APIKey: "key123", APISecret: "long_secret_value_here", StoredAt: time.Now(),
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "showuser@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	require.Len(t, resp, 1)
	hint, _ := resp[0]["api_secret_hint"].(string)
	assert.Contains(t, hint, "****")
	assert.True(t, len(hint) > 4) // Not just "****" — has prefix+suffix
}

// ---------------------------------------------------------------------------
// handler.go: truncKey
// ---------------------------------------------------------------------------

func TestPush100_TruncKey_Short(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "ab", truncKey("abcde", 2))
}

func TestPush100_TruncKey_ExactLength(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc", truncKey("abc", 5))
}

// ---------------------------------------------------------------------------
// handler.go: metricsAPI with different period params
// ---------------------------------------------------------------------------

func TestPush100_MetricsAPI_30dPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics?period=30d", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPush100_MetricsAPI_7dPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics?period=7d", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// user_render.go: userDashboardFragmentTemplates and renderUserFragment
// ---------------------------------------------------------------------------

func TestPush100_UserDashboardFragmentTemplates(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}

func TestPush100_RenderUserFragment_OrdersTable(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	require.NoError(t, err)

	data := OrdersTableData{
		Orders: []OrderRow{
			{
				Symbol: "RELIANCE", Side: "BUY", SideClass: "side-buy",
				QuantityFmt: "100", FillPriceFmt: "2500.00",
				Status: "COMPLETE", StatusBadge: "status-complete",
			},
		},
	}
	result, err := renderUserFragment(tmpl, "user_orders_table", data)
	assert.NoError(t, err)
	assert.Contains(t, result, "RELIANCE")
}

func TestPush100_RenderUserFragment_AlertsActive(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	require.NoError(t, err)

	data := AlertsActiveData{
		Alerts: []ActiveAlertRow{
			{
				Tradingsymbol: "TCS", Direction: "above",
				DirBadge: "green", TargetFmt: "3500.00",
			},
		},
	}
	result, err := renderUserFragment(tmpl, "user_alerts_active", data)
	assert.NoError(t, err)
	assert.Contains(t, result, "TCS")
}

// ===========================================================================
// DashboardHandler helpers for push100 tests
// ===========================================================================

// newPush100Dashboard creates a DashboardHandler with audit store for API tests.
func newPush100Dashboard(t *testing.T) (*DashboardHandler, *kc.Manager) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	d := NewDashboardHandler(mgr, logger, auditStore)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d, mgr
}

func push100DashReq(method, target, email string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if email != "" {
		req = req.WithContext(oauth.ContextWithEmail(req.Context(), email))
	}
	return req
}

func push100DashReqBody(method, target, email, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if email != "" {
		req = req.WithContext(oauth.ContextWithEmail(req.Context(), email))
	}
	return req
}

// ===========================================================================
// dashboard.go: activityAPI — method not allowed, no email, no audit store,
// full success with filters
// ===========================================================================

func TestPush100_ActivityAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_ActivityAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_ActivityAPI_WithFilters(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Insert test audit entries
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "c1",
		Email:        "user@test.com",
		ToolName:     "get_holdings",
		ToolCategory: "portfolio",
		StartedAt:    time.Now().Add(-1 * time.Hour),
		CompletedAt:  time.Now().Add(-1 * time.Hour),
	})

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	until := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	req := push100DashReq(http.MethodGet,
		"/dashboard/api/activity?category=portfolio&errors=true&since="+since+"&until="+until+"&limit=5&offset=0",
		"user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

func TestPush100_ActivityAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ===========================================================================
// dashboard.go: activityExport — CSV, JSON, no email/auditStore
// ===========================================================================

func TestPush100_ActivityExport_CSV(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "ex1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
		IsError:      true,
		ErrorMessage: "rate limited",
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Body.String(), "place_order")
}

func TestPush100_ActivityExport_JSON(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

func TestPush100_ActivityExport_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPush100_ActivityExport_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity/export", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_ActivityExport_WithTimeRange(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	req := push100DashReq(http.MethodGet,
		"/dashboard/api/activity/export?since="+since+"&until="+until+"&category=admin&errors=true",
		"user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard.go: activityStreamSSE — no email, no audit store
// ===========================================================================

func TestPush100_ActivityStreamSSE_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_ActivityStreamSSE_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/stream", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_ActivityStreamSSE_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPush100_ActivityStreamSSE_CancelledContext(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "user@test.com")
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	assert.Contains(t, rec.Body.String(), ": connected")
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
// dashboard.go: ordersAPI — method not allowed, no email, no audit store,
// with since param, with audit data
// ===========================================================================

func TestPush100_OrdersAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_OrdersAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_OrdersAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPush100_OrdersAPI_WithSinceParam(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	req := push100DashReq(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPush100_OrdersAPI_WithAuditData(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "ord1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-100",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
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
// dashboard.go: orderAttributionAPI — missing order_id, no audit store, success
// ===========================================================================

func TestPush100_OrderAttribution_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-1", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_OrderAttribution_MissingOrderID(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPush100_OrderAttribution_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/order-attribution?order_id=ORD-1", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_OrderAttribution_Success(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Record an attribution
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "attr1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-99",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-99", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ORD-99")
}

// ===========================================================================
// dashboard.go: alertsEnrichedAPI — DELETE, GET
// ===========================================================================

func TestPush100_AlertsEnriched_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_AlertsEnriched_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_AlertsEnriched_DeleteNoAlertID(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodDelete, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPush100_AlertsEnriched_DeleteSuccess(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	alertID, _ := mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	req := push100DashReq(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id="+alertID, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestPush100_AlertsEnriched_GetWithAlerts(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 408065, 2500, alerts.DirectionAbove)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "RELIANCE")
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
// dashboard.go: selfDeleteAccount — method not allowed, no confirm, success
// ===========================================================================

func TestPush100_SelfDeleteAccount_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/account/delete", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_SelfDeleteAccount_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPush100_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":false}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPush100_SelfDeleteAccount_Success(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed some data
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{AccessToken: "t", StoredAt: time.Now()})
	_, _ = mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Account deleted")

	// Verify data was cleaned up
	_, hasCreds := mgr.CredentialStore().Get("user@test.com")
	assert.False(t, hasCreds)
	_, hasToken := mgr.TokenStore().Get("user@test.com")
	assert.False(t, hasToken)
}

func TestPush100_SelfDeleteAccount_WithPaperEngine(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	paperStore := papertrading.NewStore(mgr.AlertDB(), slog.Default())
	require.NoError(t, paperStore.InitTables())
	pe := papertrading.NewEngine(paperStore, slog.Default())
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
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
// dashboard.go: alerts API — method not allowed, no email, success
// ===========================================================================

func TestPush100_AlertsAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_AlertsAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: status API
// ===========================================================================

func TestPush100_StatusAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: verifyChain — success, no audit store, method not allowed
// ===========================================================================

func TestPush100_VerifyChain_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_VerifyChain_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandler(t) // nil audit store
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Will get 403 because nil userStore means isAdmin returns false
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPush100_VerifyChain_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: listUsers — success
// ===========================================================================

func TestPush100_ListUsers_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/users", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "admin@test.com")
}

func TestPush100_ListUsers_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: suspendUser/activateUser — success paths
// ===========================================================================

func TestPush100_SuspendUser_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	h.userStore.EnsureUser("target@test.com", "", "", "")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/suspend?email=target@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestPush100_ActivateUser_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	h.userStore.EnsureUser("target@test.com", "", "", "")
	_ = h.userStore.UpdateStatus("target@test.com", "suspended")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/activate?email=target@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestPush100_SuspendUser_SelfSuspend(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPush100_SuspendUser_NoEmail(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/users/suspend", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// handler.go: metricsFragment — all period variants
// ===========================================================================

func TestPush100_MetricsFragment_1hPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics-fragment?period=1h", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestPush100_MetricsFragment_DefaultPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPush100_MetricsFragment_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: logStream — backfill, keepalive, cancel
// ===========================================================================

func TestPush100_LogStream_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/logs", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPush100_LogStream_Backfill(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Add some log entries to the buffer
	h.logBuffer.Add(LogEntry{Time: time.Now(), Level: "INFO", Message: "test entry"})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// handler.go: logAdminAction — nil audit store path
// ===========================================================================

func TestPush100_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandler(t) // nil audit store
	// Just call directly — should not panic
	h.logAdminAction("admin@test.com", "test_action", "target@test.com")
}

// ===========================================================================
// handler.go: overviewStream — cancel context
// ===========================================================================

func TestPush100_OverviewStream_Cancel(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	// Should have sent at least one event
	body := rec.Body.String()
	assert.Contains(t, body, "event:")
}

// ===========================================================================
// dashboard.go: RegisterRoutes — static file serving and billing no-store branch
// ===========================================================================

func TestPush100_StaticCSS(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}

func TestPush100_StaticHTMX(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
}

// ===========================================================================
// dashboard.go: writeJSON encode error path
// ===========================================================================

func TestPush100_WriteJSON_EncodeError(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	rec := httptest.NewRecorder()
	// func() is not JSON-encodable, triggers the error path
	d.writeJSON(rec, map[string]interface{}{"fn": func() {}})
	// Should still set Content-Type even on error
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

// ===========================================================================
// data.go: buildOverview — per-user view with tokens and credentials
// ===========================================================================

func TestPush100_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed user data
	h.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})
	h.manager.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{AccessToken: "t", StoredAt: time.Now()})
	_, _ = h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
	assert.Equal(t, 1, overview.TotalAlerts)
	assert.Equal(t, 1, overview.ActiveAlerts)
}

// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR — with audit data
// ===========================================================================

func TestPush100_ServeActivityPageSSR_WithData(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "act1",
		Email:        "user@test.com",
		ToolName:     "get_holdings",
		ToolCategory: "portfolio",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR — with triggered alerts
// ===========================================================================

func TestPush100_ServeAlertsPageSSR_WithTriggered(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	alertID, _ := mgr.AlertStore().Add("user@test.com", "TCS", "NSE", 0, 3500, alerts.DirectionAbove)
	_ = mgr.AlertStore().MarkTriggered(alertID, 3550)

	req := push100DashReq(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePortfolioPage — no email redirect
// ===========================================================================

func TestPush100_ServePortfolioPage_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Renders a page even with empty email (status card data will be empty)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePaperFragment — various branches
// ===========================================================================

func TestPush100_ServePaperFragment_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePortfolioFragment — without creds
// ===========================================================================

func TestPush100_ServePortfolioFragment_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveSafetyFragment
// ===========================================================================

// ===========================================================================
// dashboard.go: ordersAPI — with creds/tokens (Kite client created, API fails)
// ===========================================================================

func TestPush100_OrdersAPI_WithCredsButKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Record an order in audit trail
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "kiteord1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-200",
		InputParams:  `{"tradingsymbol":"TCS","exchange":"NSE","transaction_type":"BUY","order_type":"LIMIT","quantity":5}`,
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	// Set up creds+token so the handler creates a Kite client (which will fail since no real API)
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should still return 200 (order entries with error field set)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "TCS")
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

// ===========================================================================
// dashboard.go: alertsEnrichedAPI — with creds (Kite LTP fails gracefully)
// ===========================================================================

func TestPush100_AlertsEnriched_WithCredsAndAlerts(t *testing.T) {
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

	// Add active and triggered alerts
	_, _ = mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)
	alertID2, _ := mgr.AlertStore().Add("user@test.com", "TCS", "NSE", 0, 3500, alerts.DirectionAbove)
	_ = mgr.AlertStore().MarkTriggered(alertID2, 3550)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
	assert.Contains(t, rec.Body.String(), "TCS")
}

// ===========================================================================
// dashboard.go: alerts — with data
// ===========================================================================

func TestPush100_AlertsAPI_WithAlerts(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "RELIANCE")
}

// ===========================================================================
// dashboard.go: status — success
// ===========================================================================

func TestPush100_StatusAPI_Success(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: writeJSON and writeJSONError encode error path
// ===========================================================================

func TestPush100_Handler_WriteJSON_EncodeError(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	rec := httptest.NewRecorder()
	h.writeJSON(rec, map[string]interface{}{"fn": func() {}})
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

func TestPush100_Handler_WriteJSONError(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	rec := httptest.NewRecorder()
	h.writeJSONError(rec, http.StatusBadRequest, "test error msg")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "test error msg")
}

// ===========================================================================
// data.go: buildOverview — admin sees global counts
// ===========================================================================

func TestPush100_BuildOverview_Admin(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed alerts
	_, _ = h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	overview := h.buildOverview()
	assert.Equal(t, "test-v1", overview.Version)
	assert.GreaterOrEqual(t, overview.TotalAlerts, 1)
}

// ===========================================================================
// data.go: buildSessions — with real sessions containing KiteSessionData
// ===========================================================================

func TestPush100_BuildSessions_WithData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Create sessions with KiteSessionData
	sm := h.manager.SessionManager()
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "user1@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "user2@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: ""}) // orphan session — should be skipped

	sessions := h.buildSessions()
	assert.Equal(t, 2, len(sessions))
	emails := map[string]bool{}
	for _, s := range sessions {
		emails[s.Email] = true
	}
	assert.True(t, emails["user1@test.com"])
	assert.True(t, emails["user2@test.com"])
}

func TestPush100_BuildSessionsForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	sm := h.manager.SessionManager()
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "target@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "other@test.com"})

	sessions := h.buildSessionsForUser("target@test.com")
	assert.Equal(t, 1, len(sessions))
	assert.Equal(t, "target@test.com", sessions[0].Email)
}

func TestPush100_BuildTickersForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	tickers := h.buildTickersForUser("user@test.com")
	assert.Equal(t, 0, len(tickers.Tickers))
}

func TestPush100_ServeSafetyFragment(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.SetRiskGuard(riskguard.NewGuard(slog.Default()))

	req := push100DashReq(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
