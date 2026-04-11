package ops

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// ===========================================================================
// intParam tests
// ===========================================================================

func TestIntParam_Valid(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?limit=25", nil)
	assert.Equal(t, 25, intParam(req, "limit", 50))
}

func TestIntParam_Missing(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	assert.Equal(t, 50, intParam(req, "limit", 50))
}

func TestIntParam_Invalid(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?limit=abc", nil)
	assert.Equal(t, 50, intParam(req, "limit", 50))
}

func TestIntParam_Negative(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?limit=-5", nil)
	assert.Equal(t, 50, intParam(req, "limit", 50))
}

func TestIntParam_Zero(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?limit=0", nil)
	assert.Equal(t, 0, intParam(req, "limit", 50))
}

// ===========================================================================
// toFloat / toInt tests
// ===========================================================================

func TestToFloat_Float64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.14, toFloat(3.14))
}

func TestToFloat_Int(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 42.0, toFloat(42))
}

func TestToFloat_Int64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 100.0, toFloat(int64(100)))
}

func TestToFloat_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 9.99, toFloat("9.99"))
}

func TestToFloat_InvalidString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0.0, toFloat("not-a-number"))
}

func TestToFloat_Nil(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0.0, toFloat(nil))
}

func TestToInt_Float64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 10, toInt(float64(10.7)))
}

func TestToInt_Int(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 5, toInt(5))
}

func TestToInt_Int64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 200, toInt(int64(200)))
}

func TestToInt_Nil(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0, toInt(nil))
}

// ===========================================================================
// portfolioToStatsData tests
// ===========================================================================

func TestPortfolioToStatsData_ValidToken(t *testing.T) {
	t.Parallel()
	status := statusResponse{
		KiteToken: tokenStatus{Valid: true},
		Ticker:    tickerStatus{Running: true, Subscriptions: 3},
	}
	portfolio := portfolioResponse{
		Summary: portfolioSummary{
			HoldingsCount: 5,
			TotalPnL:      1000.0,
			TotalCurrent:  100000.0,
			PositionsPnL:  500.0,
		},
	}
	data := portfolioToStatsData(status, portfolio, 2)

	assert.Len(t, data.Cards, 5)
	assert.Equal(t, "Active", data.Cards[0].Value)
	assert.Equal(t, "green", data.Cards[0].Class)
	assert.Equal(t, "5", data.Cards[1].Value)
	// Today's P&L = TotalPnL + PositionsPnL = 1500
	assert.Contains(t, data.Cards[2].Value, "1,500")
	assert.Equal(t, "green", data.Cards[2].Class)
	assert.Equal(t, "2", data.Cards[3].Value)
	assert.Equal(t, "3 feeds", data.Cards[4].Value)
}

func TestPortfolioToStatsData_ExpiredToken(t *testing.T) {
	t.Parallel()
	status := statusResponse{
		KiteToken: tokenStatus{Valid: false},
		Ticker:    tickerStatus{Running: false},
	}
	portfolio := portfolioResponse{}
	data := portfolioToStatsData(status, portfolio, 0)

	assert.Equal(t, "Expired", data.Cards[0].Value)
	assert.Equal(t, "red", data.Cards[0].Class)
	assert.Equal(t, "Off", data.Cards[4].Value)
}

func TestPortfolioToStatsData_NegativePnL(t *testing.T) {
	t.Parallel()
	status := statusResponse{KiteToken: tokenStatus{Valid: true}}
	portfolio := portfolioResponse{
		Summary: portfolioSummary{
			TotalPnL:     -2000.0,
			TotalCurrent: 50000.0,
			PositionsPnL: -500.0,
		},
	}
	data := portfolioToStatsData(status, portfolio, 0)
	assert.Equal(t, "red", data.Cards[2].Class)
}

// ===========================================================================
// alertsToActiveData tests
// ===========================================================================

func TestAlertsToActiveData(t *testing.T) {
	t.Parallel()
	dist := 1.5
	active := []enrichedActiveAlert{
		{
			ID:            "a1",
			Tradingsymbol: "RELIANCE",
			Direction:     "above",
			TargetPrice:   2500,
			CurrentPrice:  2460,
			DistancePct:   &dist,
			CreatedAt:     "2026-04-06T10:00:00Z",
		},
		{
			ID:            "a2",
			Tradingsymbol: "INFY",
			Direction:     "below",
			TargetPrice:   1400,
			CurrentPrice:  1500,
			CreatedAt:     "2026-04-06T11:00:00Z",
		},
	}
	data := alertsToActiveData(active)
	assert.Len(t, data.Alerts, 2)
	assert.Equal(t, "green", data.Alerts[0].DirBadge) // above
	assert.Equal(t, "dist-green", data.Alerts[0].DistClass)
	assert.Equal(t, "1.5%", data.Alerts[0].DistFmt)
	assert.Equal(t, "red", data.Alerts[1].DirBadge) // below
	assert.Equal(t, "--", data.Alerts[1].DistFmt)     // nil DistancePct
}

func TestAlertsToActiveData_Empty(t *testing.T) {
	t.Parallel()
	data := alertsToActiveData(nil)
	assert.Empty(t, data.Alerts)
}

// ===========================================================================
// alertsToTriggeredData tests
// ===========================================================================

func TestAlertsToTriggeredData(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			ID:                 "t1",
			Tradingsymbol:      "SBIN",
			Direction:          "above",
			TargetPrice:        600,
			CreatedAt:          "2026-04-01T09:00:00Z",
			TriggeredAt:        "2026-04-03T14:30:00Z",
			TimeToTrigger:      "2d 5h 30m",
			NotificationSentAt: "2026-04-03T14:30:05Z",
			NotificationDelay:  "5s",
		},
	}
	data := alertsToTriggeredData(triggered)
	assert.Len(t, data.Alerts, 1)
	assert.Equal(t, "green", data.Alerts[0].DirBadge)
	assert.Equal(t, "2d 5h 30m", data.Alerts[0].TimeToTrigger)
	assert.NotEmpty(t, data.Alerts[0].NotificationFmt)
}

func TestAlertsToTriggeredData_NoNotification(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			Tradingsymbol: "SBIN",
			Direction:     "drop_pct",
			TargetPrice:   550,
			CreatedAt:     "2026-04-01T09:00:00Z",
			TriggeredAt:   "2026-04-02T10:00:00Z",
		},
	}
	data := alertsToTriggeredData(triggered)
	assert.Len(t, data.Alerts, 1)
	assert.Equal(t, "red", data.Alerts[0].DirBadge) // drop_pct
	assert.Empty(t, data.Alerts[0].NotificationFmt)
}

func TestAlertsToTriggeredData_Empty(t *testing.T) {
	t.Parallel()
	data := alertsToTriggeredData(nil)
	assert.Empty(t, data.Alerts)
}

// ===========================================================================
// paperStatusToBanner tests
// ===========================================================================

func TestPaperStatusToBanner_Disabled(t *testing.T) {
	t.Parallel()
	data := paperStatusToBanner(map[string]any{"enabled": false})
	assert.False(t, data.Enabled)
}

func TestPaperStatusToBanner_Enabled(t *testing.T) {
	t.Parallel()
	data := paperStatusToBanner(map[string]any{
		"enabled":      true,
		"initial_cash": float64(10000000),
		"created_at":   "2026-04-01T09:00:00Z",
	})
	assert.True(t, data.Enabled)
	assert.Contains(t, data.InitialCashFmt, "1,00,00,000")
	assert.NotEmpty(t, data.CreatedFmt)
}

func TestPaperStatusToBanner_EnabledNoDates(t *testing.T) {
	t.Parallel()
	data := paperStatusToBanner(map[string]any{
		"enabled":      true,
		"initial_cash": float64(0),
	})
	assert.True(t, data.Enabled)
	assert.Empty(t, data.CreatedFmt)
}

// ===========================================================================
// paperStatusToStats tests
// ===========================================================================

func TestPaperStatusToStats(t *testing.T) {
	t.Parallel()
	data := paperStatusToStats(map[string]any{
		"cash":        float64(9500000),
		"total_value": float64(10500000),
		"total_pnl":   float64(500000),
		"pnl_pct":     float64(5.0),
	})
	assert.Len(t, data.Cards, 4)
	assert.Equal(t, "Cash Balance", data.Cards[0].Label)
	assert.Equal(t, "green", data.Cards[2].Class)  // positive PnL
	assert.Equal(t, "green", data.Cards[3].Class)  // positive PnL %
}

func TestPaperStatusToStats_NegativePnL(t *testing.T) {
	t.Parallel()
	data := paperStatusToStats(map[string]any{
		"total_pnl": float64(-100000),
		"pnl_pct":   float64(-1.0),
	})
	assert.Equal(t, "red", data.Cards[2].Class)
	assert.Equal(t, "red", data.Cards[3].Class)
}

// ===========================================================================
// paperDataToTables tests
// ===========================================================================

func TestPaperDataToTables_AllData(t *testing.T) {
	t.Parallel()
	holdings := []map[string]any{
		{
			"tradingsymbol": "RELIANCE",
			"exchange":      "NSE",
			"quantity":      float64(10),
			"average_price": float64(2400),
			"last_price":    float64(2500),
			"pnl":           float64(1000),
		},
	}
	positions := []map[string]any{
		{
			"tradingsymbol": "INFY",
			"product":       "MIS",
			"quantity":      float64(-5),
			"average_price": float64(1500),
			"last_price":    float64(1480),
			"pnl":           float64(100),
		},
	}
	orders := []map[string]any{
		{
			"order_id":         "order-123456789",
			"tradingsymbol":    "SBIN",
			"transaction_type": "BUY",
			"order_type":       "MARKET",
			"quantity":         float64(100),
			"price":            float64(600),
			"status":           "COMPLETE",
			"placed_at":        "2026-04-06T10:00:00Z",
		},
		{
			"order_id":         "order-987",
			"tradingsymbol":    "TCS",
			"transaction_type": "SELL",
			"order_type":       "LIMIT",
			"quantity":         float64(50),
			"price":            float64(3500),
			"status":           "REJECTED",
			"placed_at":        "2026-04-06T11:00:00Z",
		},
	}
	data := paperDataToTables(holdings, positions, orders)

	assert.Len(t, data.Holdings, 1)
	assert.Equal(t, "RELIANCE", data.Holdings[0].Tradingsymbol)
	assert.Equal(t, 10, data.Holdings[0].Quantity)
	assert.Equal(t, "green", data.Holdings[0].PnLClass)

	assert.Len(t, data.Positions, 1)
	assert.Equal(t, "MIS", data.Positions[0].Product)

	assert.Len(t, data.Orders, 2)
	assert.Equal(t, "order-12", data.Orders[0].OrderIDShort) // truncated to 8
	assert.Equal(t, "badge-green", data.Orders[0].SideBadge)  // BUY
	assert.Equal(t, "badge-green", data.Orders[0].StatusBadge) // COMPLETE
	assert.Equal(t, "order-98", data.Orders[1].OrderIDShort)
	assert.Equal(t, "badge-red", data.Orders[1].SideBadge)    // SELL
	assert.Equal(t, "badge-red", data.Orders[1].StatusBadge)  // REJECTED
}

func TestPaperDataToTables_NilInputs(t *testing.T) {
	t.Parallel()
	data := paperDataToTables(nil, nil, nil)
	assert.Empty(t, data.Holdings)
	assert.Empty(t, data.Positions)
	assert.Empty(t, data.Orders)
}

func TestPaperDataToTables_WrongType(t *testing.T) {
	t.Parallel()
	// Pass wrong types - should not panic
	data := paperDataToTables("not-a-list", 42, true)
	assert.Empty(t, data.Holdings)
	assert.Empty(t, data.Positions)
	assert.Empty(t, data.Orders)
}

// ===========================================================================
// formatDuration tests (extended from render_test.go)
// ===========================================================================

func TestFormatDuration_SecondsOnly(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "45s", formatDuration(45*time.Second))
}

func TestFormatDuration_DaysHoursMinutes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "2d 3h 15m", formatDuration(2*24*time.Hour+3*time.Hour+15*time.Minute))
}

// ===========================================================================
// DashboardHandler initialization (extended)
// ===========================================================================

func TestNewDashboardHandler_InitTemplates(t *testing.T) {
	t.Parallel()
	d := NewDashboardHandler(nil, nil, nil)
	assert.NotNil(t, d)
	// Verify templates were initialized (at least the fragment template)
	assert.NotNil(t, d.fragmentTmpl)
}

func TestDashboardHandler_SetAdminCheck_Callback(t *testing.T) {
	t.Parallel()
	d := NewDashboardHandler(nil, nil, nil)
	called := false
	d.SetAdminCheck(func(email string) bool {
		called = true
		return email == "admin@test.com"
	})
	assert.True(t, d.adminCheck("admin@test.com"))
	assert.True(t, called)
	assert.False(t, d.adminCheck("user@test.com"))
}

// ===========================================================================
// renderUserFragment tests
// ===========================================================================

func TestRenderUserFragment_Success(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)

	data := portfolioToHoldingsData([]holdingItem{
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 5, AveragePrice: 2400, LastPrice: 2500, PnL: 500},
	})
	html, err := renderUserFragment(tmpl, "user_portfolio_holdings", data)
	assert.NoError(t, err)
	assert.Contains(t, html, "RELIANCE")
}

func TestRenderUserFragment_EmptyData(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)

	data := portfolioToHoldingsData(nil)
	html, err := renderUserFragment(tmpl, "user_portfolio_holdings", data)
	assert.NoError(t, err)
	assert.NotEmpty(t, html) // template renders even with empty data
}

func TestRenderUserFragment_ActivityTimeline(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)

	data := activityToTimelineData(nil)
	html, err := renderUserFragment(tmpl, "user_activity_timeline", data)
	assert.NoError(t, err)
	assert.NotEmpty(t, html)
}

func TestRenderUserFragment_SafetyLimits(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)

	data := safetyToLimitsData(map[string]any{
		"enabled": true,
		"status":  map[string]any{"daily_order_count": float64(10), "daily_placed_value": float64(50000)},
		"limits":  map[string]any{"max_orders_per_day": float64(200), "max_daily_value_inr": float64(1000000), "max_single_order_inr": float64(500000), "max_orders_per_minute": float64(10), "duplicate_window_secs": float64(30)},
	})
	html, err := renderUserFragment(tmpl, "user_safety_limits", data)
	assert.NoError(t, err)
	assert.Contains(t, html, "Daily Orders")
}

// ===========================================================================
// writeSSEEvent edge cases
// ===========================================================================

func TestWriteSSEEvent_EmptyPayload(t *testing.T) {
	t.Parallel()
	rw := &mockResponseWriter{}
	writeSSEEvent(rw, "ping", "")
	output := rw.buf.String()
	assert.Contains(t, output, "event: ping\n")
	assert.Contains(t, output, "data: \n")
}

func TestWriteSSEEvent_SingleLine(t *testing.T) {
	t.Parallel()
	rw := &mockResponseWriter{}
	writeSSEEvent(rw, "update", "single line data")
	output := rw.buf.String()
	assert.Contains(t, output, "event: update\n")
	assert.Contains(t, output, "data: single line data\n")
}

// ===========================================================================
// Additional render helpers for completeness
// ===========================================================================

func TestPortfolioToHoldingsData_MultipleHoldings(t *testing.T) {
	t.Parallel()
	holdings := []holdingItem{
		{Tradingsymbol: "RELIANCE", PnL: 1000, DayChangePercent: 2.5},
		{Tradingsymbol: "INFY", PnL: -500, DayChangePercent: -1.2},
		{Tradingsymbol: "TCS", PnL: 0, DayChangePercent: 0},
	}
	data := portfolioToHoldingsData(holdings)
	assert.Len(t, data.Holdings, 3)
	assert.Equal(t, "green", data.Holdings[0].PnLClass)
	assert.Equal(t, "red", data.Holdings[1].PnLClass)
	assert.Equal(t, "", data.Holdings[2].PnLClass)
}

func TestPortfolioToPositionsData_MultiplePositions(t *testing.T) {
	t.Parallel()
	positions := []positionItem{
		{Tradingsymbol: "RELIANCE", Product: "CNC", PnL: 500},
		{Tradingsymbol: "INFY", Product: "MIS", PnL: -200},
	}
	data := portfolioToPositionsData(positions)
	assert.Len(t, data.Positions, 2)
	assert.Equal(t, "CNC", data.Positions[0].Product)
	assert.Equal(t, "green", data.Positions[0].PnLClass)
	assert.Equal(t, "red", data.Positions[1].PnLClass)
}

func TestOrdersToTableData_AllStatuses(t *testing.T) {
	t.Parallel()
	fillPrice := 100.0
	pnl := -50.0
	pnlPct := -0.5
	currentPrice := 99.5
	entries := []orderEntry{
		{Symbol: "NSE:SBIN", Side: "BUY", Quantity: 100, Status: "OPEN", PlacedAt: "2026-04-06T10:00:00Z"},
		{Symbol: "NSE:INFY", Side: "SELL", Quantity: 50, Status: "CANCELLED", PlacedAt: "2026-04-06T11:00:00Z"},
		{Symbol: "NSE:TCS", Side: "BUY", Quantity: 10, Status: "TRIGGER PENDING", PlacedAt: "2026-04-06T12:00:00Z"},
		{Symbol: "NSE:HDFC", Side: "BUY", Quantity: 25, Status: "UPDATE VALIDATION PENDING",
			FillPrice: &fillPrice, CurrentPrice: &currentPrice, PnL: &pnl, PnLPct: &pnlPct,
			PlacedAt: "2026-04-06T13:00:00Z"},
	}
	data := ordersToTableData(entries)
	assert.Len(t, data.Orders, 4)
	assert.Equal(t, "status-open", data.Orders[0].StatusBadge)
	assert.Equal(t, "status-cancelled", data.Orders[1].StatusBadge)
	assert.Equal(t, "status-open", data.Orders[2].StatusBadge)
	assert.Equal(t, "status-pending", data.Orders[3].StatusBadge)
	// Check PnL display classes
	assert.Equal(t, "pnl-neg", data.Orders[3].PnLClass)
	assert.Equal(t, "pnl-neg", data.Orders[3].PnLPctClass)
}

func TestOrdersToTableData_NilOptionalFields(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "NSE:TEST", Side: "BUY", Quantity: 1, Status: "COMPLETE", PlacedAt: "invalid-date"},
	}
	data := ordersToTableData(entries)
	assert.Len(t, data.Orders, 1)
	assert.Equal(t, "--", data.Orders[0].FillPriceFmt)
	assert.Equal(t, "--", data.Orders[0].CurrentPriceFmt)
	assert.Equal(t, "--", data.Orders[0].PnLFmt)
	assert.Equal(t, "--", data.Orders[0].PnLPctFmt)
}

// ===========================================================================
// SafetyToFreezeData extended tests
// ===========================================================================

func TestSafetyToFreezeData_EnabledNotFrozen(t *testing.T) {
	t.Parallel()
	data := safetyToFreezeData(map[string]any{
		"enabled": true,
		"status": map[string]any{
			"is_frozen": false,
		},
	})
	assert.True(t, data.Enabled)
	assert.False(t, data.IsFrozen)
}

func TestSafetyToFreezeData_NilStatus(t *testing.T) {
	t.Parallel()
	data := safetyToFreezeData(map[string]any{
		"enabled": true,
	})
	assert.True(t, data.Enabled)
	assert.False(t, data.IsFrozen)
}

func TestSafetyToFreezeData_DisabledDefaultMessage(t *testing.T) {
	t.Parallel()
	data := safetyToFreezeData(map[string]any{"enabled": false})
	assert.False(t, data.Enabled)
	assert.Equal(t, "Not enabled on this server.", data.Message)
}

// ===========================================================================
// SafetyToLimitsData extended tests
// ===========================================================================

func TestSafetyToLimitsData_NilStatusOrLimits(t *testing.T) {
	t.Parallel()
	data := safetyToLimitsData(map[string]any{"enabled": true})
	assert.True(t, data.Enabled)
	assert.Empty(t, data.Limits)
}

func TestSafetyToLimitsData_HighUtilization(t *testing.T) {
	t.Parallel()
	data := safetyToLimitsData(map[string]any{
		"enabled": true,
		"status":  map[string]any{"daily_order_count": float64(190), "daily_placed_value": float64(950000)},
		"limits":  map[string]any{"max_orders_per_day": float64(200), "max_daily_value_inr": float64(1000000), "max_single_order_inr": float64(500000), "max_orders_per_minute": float64(10), "duplicate_window_secs": float64(30)},
	})
	assert.True(t, data.Enabled)
	assert.Len(t, data.Limits, 5)
	assert.Equal(t, 95, data.Limits[0].Pct)       // 190/200 = 95%
	assert.Equal(t, "danger", data.Limits[0].BarClass) // >=90
	assert.Equal(t, 95, data.Limits[1].Pct)
	assert.Equal(t, "danger", data.Limits[1].BarClass)
}

// ===========================================================================
// SafetyToSEBIData extended tests
// ===========================================================================

func TestSafetyToSEBIData_NilSebi(t *testing.T) {
	t.Parallel()
	data := safetyToSEBIData(map[string]any{"enabled": true})
	assert.True(t, data.Enabled)
	assert.Empty(t, data.Checks)
}

func TestSafetyToSEBIData_AllTrue(t *testing.T) {
	t.Parallel()
	data := safetyToSEBIData(map[string]any{
		"enabled": true,
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   true,
			"credentials_set":  true,
			"order_tagging":    true,
			"audit_trail":      true,
		},
	})
	assert.True(t, data.Enabled)
	assert.Len(t, data.Checks, 5)
	for _, check := range data.Checks {
		assert.Equal(t, "ok", check.DotClass)
	}
}

// ===========================================================================
// MarketIndicesToBarData edge cases
// ===========================================================================

func TestMarketIndicesToBarData_AllIndices(t *testing.T) {
	t.Parallel()
	indices := map[string]any{
		"NSE:NIFTY 50": map[string]any{
			"last_price": float64(22000),
			"change":     float64(150),
			"change_pct": float64(0.68),
		},
		"NSE:NIFTY BANK": map[string]any{
			"last_price": float64(48000),
			"change":     float64(200),
			"change_pct": float64(0.42),
		},
		"BSE:SENSEX": map[string]any{
			"last_price": float64(72000),
			"change":     float64(-300),
			"change_pct": float64(-0.42),
		},
	}
	data := marketIndicesToBarData(indices)
	assert.Len(t, data.Indices, 3)
	assert.Equal(t, "NIFTY 50", data.Indices[0].Label)
	assert.Equal(t, "up", data.Indices[0].ChangeClass)
	assert.Equal(t, "BANK NIFTY", data.Indices[1].Label)
	assert.Equal(t, "up", data.Indices[1].ChangeClass)
	assert.Equal(t, "SENSEX", data.Indices[2].Label)
	assert.Equal(t, "down", data.Indices[2].ChangeClass)
	assert.NotEqual(t, "--", data.Indices[2].PriceFmt) // SENSEX present
}

func TestMarketIndicesToBarData_Empty(t *testing.T) {
	t.Parallel()
	data := marketIndicesToBarData(map[string]any{})
	assert.Len(t, data.Indices, 3) // always 3 entries (with fallback)
	for _, idx := range data.Indices {
		assert.Equal(t, "--", idx.PriceFmt)
	}
}

func TestMarketIndicesToBarData_InvalidType(t *testing.T) {
	t.Parallel()
	// Pass a non-map value for an index
	data := marketIndicesToBarData(map[string]any{
		"NSE:NIFTY 50": "not-a-map",
	})
	assert.Len(t, data.Indices, 3)
	assert.Equal(t, "--", data.Indices[0].PriceFmt) // not a map, so fallback
}

// ===========================================================================
// dashboardNormalizeSymbol tests
// ===========================================================================

func TestDashboardNormalizeSymbol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"RELIANCE-BE", "RELIANCE"},
		{"RELIANCE-EQ", "RELIANCE"},
		{"SBIN-BZ", "SBIN"},
		{"TCS-BL", "TCS"},
		{"INFY", "INFY"},
		{"  reliance-be  ", "RELIANCE"},
		{"", ""},
		{"ABC-BX", "ABC-BX"}, // unknown suffix - no strip
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, dashboardNormalizeSymbol(tc.in), "dashboardNormalizeSymbol(%q)", tc.in)
	}
}

// ===========================================================================
// maskKey tests
// ===========================================================================

func TestMaskKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"abcdefghijkl", "abcd****ijkl"},
		{"12345678", "****"},          // exactly 8 chars
		{"short", "****"},             // less than 8 chars
		{"", "****"},                  // empty
		{"abcdefghij", "abcd****ghij"}, // exactly 10 chars
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, maskKey(tc.in), "maskKey(%q)", tc.in)
	}
}

// ===========================================================================
// parseOrderParamsJSON tests
// ===========================================================================

func TestParseOrderParamsJSON_Full(t *testing.T) {
	t.Parallel()
	oe := &orderEntry{}
	parseOrderParamsJSON(`{
		"tradingsymbol": "RELIANCE",
		"exchange": "NSE",
		"transaction_type": "BUY",
		"order_type": "LIMIT",
		"quantity": 10
	}`, oe)
	assert.Equal(t, "RELIANCE", oe.Symbol)
	assert.Equal(t, "NSE", oe.Exchange)
	assert.Equal(t, "BUY", oe.Side)
	assert.Equal(t, "LIMIT", oe.OrderType)
	assert.Equal(t, float64(10), oe.Quantity)
}

func TestParseOrderParamsJSON_Partial(t *testing.T) {
	t.Parallel()
	oe := &orderEntry{Symbol: "ORIGINAL"}
	parseOrderParamsJSON(`{"tradingsymbol": "INFY"}`, oe)
	assert.Equal(t, "INFY", oe.Symbol) // overwritten
	assert.Empty(t, oe.Exchange)       // not in JSON
}

func TestParseOrderParamsJSON_Empty(t *testing.T) {
	t.Parallel()
	oe := &orderEntry{Symbol: "KEEP"}
	parseOrderParamsJSON("", oe)
	assert.Equal(t, "KEEP", oe.Symbol) // unchanged
}

func TestParseOrderParamsJSON_InvalidJSON(t *testing.T) {
	t.Parallel()
	oe := &orderEntry{Symbol: "KEEP"}
	parseOrderParamsJSON("{not valid json}", oe)
	assert.Equal(t, "KEEP", oe.Symbol) // unchanged
}

// ===========================================================================
// nowTimestamp test
// ===========================================================================

func TestNowTimestamp(t *testing.T) {
	t.Parallel()
	ts := nowTimestamp()
	// Returns "Updated HH:MM:SS" format
	assert.Contains(t, ts, "Updated ")
	// Should have the time part parseable
	assert.Len(t, ts, len("Updated 15:04:05"))
}

// ===========================================================================
// Additional render helper edge cases
// ===========================================================================

func TestFmtINR_LargeNumber(t *testing.T) {
	t.Parallel()
	// 10 crore = 10,00,00,000
	result := fmtINR(100000000)
	assert.Contains(t, result, "10,00,00,000")
}

func TestFmtINRShort_Negative(t *testing.T) {
	t.Parallel()
	result := fmtINRShort(-500000)
	assert.Contains(t, result, "L")
	assert.Contains(t, result, "-")
}

func TestActivityToStatsData_WithTopTool(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls:   100,
		ErrorCount:   0,
		AvgLatencyMs: 25.0,
		TopTool:      "get_holdings",
		TopToolCount: 50,
	}
	data := activityToStatsData(stats)
	assert.Equal(t, "get_holdings", data.Cards[3].Value)
	assert.Equal(t, "50 calls", data.Cards[3].Sub)
	assert.Equal(t, "", data.Cards[1].Class) // 0 errors, no red class
}

func TestMetricsToTemplateData_HighErrorRate(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls:   100,
		ErrorCount:   10,
		AvgLatencyMs: 50.0,
		TopTool:      "place_order",
		TopToolCount: 30,
	}
	data := metricsToTemplateData(stats, nil, 3600)
	// Error rate = 10/100 = 10% -> should be "red"
	assert.Equal(t, "10.0%", data.Cards[2].Value)
	assert.Equal(t, "red", data.Cards[2].Class)
}

func TestMetricsToTemplateData_LowErrorRate(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls:   1000,
		ErrorCount:   15,
		AvgLatencyMs: 30.0,
	}
	data := metricsToTemplateData(stats, nil, 90000)
	// Error rate = 1.5% -> "amber"
	assert.Equal(t, "1.5%", data.Cards[2].Value)
	assert.Equal(t, "amber", data.Cards[2].Class)
	// Uptime 90000s = 1d 1h 0m
	assert.Equal(t, "1d 1h 0m", data.Cards[0].Value)
}
