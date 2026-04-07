package ops

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// ===========================================================================
// Pure helper / formatter tests
// ===========================================================================

func TestFormatFloat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0.00"},
		{1.5, "1.50"},
		{1234.5678, "1234.57"},
		{-42.1, "-42.10"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, formatFloat(tc.in))
	}
}

func TestFormatInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
		{1000000, "1,000,000"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, formatInt(tc.in), "formatInt(%d)", tc.in)
	}
}

func TestFmtTimeStr(t *testing.T) {
	t.Parallel()
	// Zero time returns "--"
	assert.Equal(t, "--", fmtTimeStr(time.Time{}))

	// Known time
	ts := time.Date(2026, 4, 6, 14, 30, 45, 0, time.UTC)
	assert.Equal(t, "14:30:45 06 Apr", fmtTimeStr(ts))
}

func TestBoolClass(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "green", boolClass(true, "green"))
	assert.Equal(t, "", boolClass(false, "green"))
}

func TestTruncKey(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abcdefgh", truncKey("abcdefghijklmnop", 8))
	assert.Equal(t, "short", truncKey("short", 8))
	assert.Equal(t, "", truncKey("", 5))
}

func TestTierDisplayName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Pro", tierDisplayName(billing.TierPro))
	assert.Equal(t, "Premium", tierDisplayName(billing.TierPremium))
	assert.Equal(t, "Free", tierDisplayName(billing.TierFree))
	// Unknown tier
	assert.Equal(t, "Free", tierDisplayName(billing.Tier(99)))
}

// ===========================================================================
// user_render.go helpers
// ===========================================================================

func TestFmtINR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{0, "\u20B90.00"},
		{999, "\u20B9999.00"},
		{1000, "\u20B91,000.00"},
		{12345.67, "\u20B912,345.67"},
		{123456.78, "\u20B91,23,456.78"},
		{-5000, "-\u20B95,000.00"},
		{1234567.89, "\u20B912,34,567.89"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, fmtINR(tc.in), "fmtINR(%f)", tc.in)
	}
}

func TestFmtINRShort(t *testing.T) {
	t.Parallel()
	// Lakh level
	assert.Contains(t, fmtINRShort(500000), "L")
	// Thousand level
	assert.Contains(t, fmtINRShort(5000), "K")
	// Small
	assert.Equal(t, "\u20B9500", fmtINRShort(500))
}

func TestFmtPrice(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "--", fmtPrice(0))
	assert.Equal(t, "123.45", fmtPrice(123.45))
}

func TestFmtPct(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "+1.25%", fmtPct(1.25))
	assert.Equal(t, "-2.50%", fmtPct(-2.50))
	assert.Equal(t, "0.00%", fmtPct(0))
}

func TestPnlClass(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "green", pnlClass(100))
	assert.Equal(t, "red", pnlClass(-50))
	assert.Equal(t, "", pnlClass(0))
}

func TestFmtTimeDDMon(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "--", fmtTimeDDMon(time.Time{}))
	ts := time.Date(2026, 3, 15, 9, 30, 0, 0, time.UTC)
	assert.Equal(t, "15 Mar 09:30", fmtTimeDDMon(ts))
}

func TestFmtTimeHMS(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "--:--:--", fmtTimeHMS(time.Time{}))
	ts := time.Date(2026, 3, 15, 14, 5, 33, 0, time.UTC)
	assert.Equal(t, "14:05:33", fmtTimeHMS(ts))
}

func TestFmtDurationMs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "500ms", fmtDurationMs(500))
	assert.Equal(t, "1.5s", fmtDurationMs(1500))
	assert.Equal(t, "0ms", fmtDurationMs(0))
}

func TestStatusBadgeClass(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "status-complete", statusBadgeClass("COMPLETE"))
	assert.Equal(t, "status-cancelled", statusBadgeClass("CANCELLED"))
	assert.Equal(t, "status-rejected", statusBadgeClass("REJECTED"))
	assert.Equal(t, "status-open", statusBadgeClass("OPEN"))
	assert.Equal(t, "status-open", statusBadgeClass("TRIGGER PENDING"))
	assert.Equal(t, "status-pending", statusBadgeClass("UPDATE VALIDATION PENDING"))
}

func TestPnlDisplayClass(t *testing.T) {
	t.Parallel()
	pos := 10.0
	neg := -5.0
	zero := 0.0
	assert.Equal(t, "pnl-pos", pnlDisplayClass(&pos))
	assert.Equal(t, "pnl-neg", pnlDisplayClass(&neg))
	assert.Equal(t, "pnl-zero", pnlDisplayClass(&zero))
	assert.Equal(t, "pnl-zero", pnlDisplayClass(nil))
}

func TestDirBadge(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "green", dirBadge("above"))
	assert.Equal(t, "green", dirBadge("rise_pct"))
	assert.Equal(t, "red", dirBadge("below"))
	assert.Equal(t, "red", dirBadge("drop_pct"))
	assert.Equal(t, "amber", dirBadge("unknown"))
}

func TestDistanceClass(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "dist-green", distanceClass(1.5))
	assert.Equal(t, "dist-amber", distanceClass(3.0))
	assert.Equal(t, "dist-red", distanceClass(6.0))
}

func TestBarClass(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "safe", barClass(50))
	assert.Equal(t, "warn", barClass(75))
	assert.Equal(t, "danger", barClass(95))
}

func TestGetCatLabel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "ORDER", getCatLabel("order"))
	assert.Equal(t, "QUERY", getCatLabel("query"))
	assert.Equal(t, "MARKET", getCatLabel("market_data"))
	assert.Equal(t, "CUSTOM", getCatLabel("custom"))
	assert.Equal(t, "OTHER", getCatLabel(""))
}

func TestGetCatColor(t *testing.T) {
	t.Parallel()
	// Known category
	bg, fg := getCatColor("order")
	assert.NotEmpty(t, bg)
	assert.NotEmpty(t, fg)

	// Unknown category falls back to "setup"
	bg2, fg2 := getCatColor("nonexistent")
	setupBg, setupFg := catColors["setup"].bg, catColors["setup"].fg
	assert.Equal(t, setupBg, bg2)
	assert.Equal(t, setupFg, fg2)
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
		{3*24*time.Hour + 1*time.Hour + 30*time.Minute, "3d 1h 30m"},
		{-10 * time.Second, "0s"}, // negative is clamped to 0
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, formatDuration(tc.d), "formatDuration(%v)", tc.d)
	}
}

// ===========================================================================
// Template data conversion tests
// ===========================================================================

func TestSessionsToTemplateData(t *testing.T) {
	t.Parallel()
	sessions := []SessionInfo{
		{
			ID:        "abcdef1234567890",
			Email:     "user@test.com",
			CreatedAt: time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 4, 6, 14, 0, 0, 0, time.UTC),
		},
		{
			ID:    "short-id",
			Email: "",
		},
	}
	data := sessionsToTemplateData(sessions)
	assert.Len(t, data.Sessions, 2)

	// First session: long ID gets truncated
	assert.Equal(t, "abcdef123456\u2026", data.Sessions[0].IDShort)
	assert.Equal(t, "user@test.com", data.Sessions[0].Email)

	// Second session: short ID stays, empty email becomes em-dash
	assert.Equal(t, "short-id", data.Sessions[1].IDShort)
	assert.Equal(t, "\u2014", data.Sessions[1].Email)
}

func TestTickersToTemplateData(t *testing.T) {
	t.Parallel()
	data := tickersToTemplateData(TickerData{
		Tickers: []ticker.UserTickerInfo{
			{Email: "user@test.com", Connected: true, StartedAt: time.Date(2026, 4, 6, 9, 15, 0, 0, time.UTC), Subscriptions: 5},
			{Email: "other@test.com", Connected: false, StartedAt: time.Time{}, Subscriptions: 0},
		},
	})
	assert.Len(t, data.Tickers, 2)
	assert.Equal(t, "connected", data.Tickers[0].StatusLabel)
	assert.Equal(t, "green", data.Tickers[0].StatusClass)
	assert.Equal(t, "5", data.Tickers[0].Subscriptions)
	assert.Equal(t, "disconnected", data.Tickers[1].StatusLabel)
	assert.Equal(t, "red", data.Tickers[1].StatusClass)
}

func TestAlertsToTemplateData(t *testing.T) {
	t.Parallel()
	data := alertsToTemplateData(AlertData{
		Alerts: map[string][]*alerts.Alert{
			"user@test.com": {
				{ID: "a1", Email: "user@test.com", Tradingsymbol: "RELIANCE", Exchange: "NSE", TargetPrice: 2500, Direction: alerts.DirectionAbove, Triggered: false, CreatedAt: time.Now()},
				{ID: "a2", Email: "user@test.com", Tradingsymbol: "INFY", Exchange: "NSE", TargetPrice: 1500, Direction: alerts.DirectionBelow, Triggered: true, CreatedAt: time.Now()},
			},
		},
		Telegram: map[string]int64{
			"user@test.com": 123456789,
		},
	})
	assert.Len(t, data.Alerts, 2)
	assert.Len(t, data.TelegramMappings, 1)
	assert.Equal(t, "123456789", data.TelegramMappings[0].ChatID)

	// Check status labels
	for _, row := range data.Alerts {
		if row.ID == "a1" {
			assert.Equal(t, "active", row.StatusLabel)
			assert.Equal(t, "green", row.StatusClass)
		}
		if row.ID == "a2" {
			assert.Equal(t, "triggered", row.StatusLabel)
			assert.Equal(t, "amber", row.StatusClass)
		}
	}
}

func TestAlertsToTemplateData_Sorted(t *testing.T) {
	t.Parallel()
	data := alertsToTemplateData(AlertData{
		Alerts: map[string][]*alerts.Alert{
			"beta@test.com":  {{ID: "b1", Email: "beta@test.com", CreatedAt: time.Now()}},
			"alpha@test.com": {{ID: "a1", Email: "alpha@test.com", CreatedAt: time.Now()}},
		},
	})
	// alpha should come before beta
	assert.Equal(t, "alpha@test.com", data.Alerts[0].Email)
	assert.Equal(t, "beta@test.com", data.Alerts[1].Email)
}

func TestUsersToTemplateData(t *testing.T) {
	t.Parallel()
	userList := []*users.User{
		{Email: "admin@test.com", Role: "admin", Status: "active", LastLogin: time.Now(), CreatedAt: time.Now()},
		{Email: "user@test.com", Role: "trader", Status: "suspended", LastLogin: time.Time{}, CreatedAt: time.Now()},
	}
	data := usersToTemplateData(userList, "admin@test.com")
	assert.Len(t, data.Users, 2)

	// Admin row
	assert.Equal(t, "purple", data.Users[0].RoleClass)
	assert.True(t, data.Users[0].IsSelf)

	// Suspended trader
	assert.Equal(t, "green", data.Users[1].RoleClass)
	assert.Equal(t, "red", data.Users[1].StatusClass)
	assert.False(t, data.Users[1].IsSelf)
}

func TestOverviewToTemplateData(t *testing.T) {
	t.Parallel()
	data := overviewToTemplateData(OverviewData{
		Version:        "v1.0.0",
		ActiveSessions: 2,
		ActiveTickers:  1,
		ActiveAlerts:   5,
		TotalAlerts:    10,
		CachedTokens:   3,
		PerUserCredentials: 2,
		DailyUsers:     1,
		HeapAllocMB:    15.5,
		Goroutines:     42,
		GCPauseMs:      0.5,
		DBSizeMB:       1.25,
		ToolUsage:      map[string]int64{"place_order": 100, "get_holdings": 50},
		GlobalFrozen:   false,
	})
	// Cards should include version, sessions, tickers, etc.
	assert.NotEmpty(t, data.Cards)
	assert.Len(t, data.Tools, 2) // 2 tool usage entries
	assert.False(t, data.GlobalFrozen)
}

func TestOverviewToTemplateData_GlobalFrozen(t *testing.T) {
	t.Parallel()
	data := overviewToTemplateData(OverviewData{GlobalFrozen: true})
	assert.True(t, data.GlobalFrozen)
	// First card should be the Global Freeze card
	assert.Equal(t, "Global Freeze", data.Cards[0].Label)
	assert.Equal(t, "ACTIVE", data.Cards[0].Value)
	assert.Equal(t, "red", data.Cards[0].Class)
}

func TestMetricsToTemplateData(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls:   1000,
		ErrorCount:   5,
		AvgLatencyMs: 42.5,
		TopTool:      "get_holdings",
		TopToolCount: 200,
	}
	toolMetrics := []audit.ToolMetric{
		{ToolName: "get_holdings", CallCount: 200, AvgMs: 30.0, MaxMs: 150, ErrorCount: 1},
		{ToolName: "place_order", CallCount: 50, AvgMs: 100.0, MaxMs: 500, ErrorCount: 4},
	}
	data := metricsToTemplateData(stats, toolMetrics, 7200) // 2 hours uptime

	assert.Len(t, data.Cards, 5) // Uptime, Total Calls, Error Rate, Avg Latency, Top Tool
	assert.Len(t, data.ToolMetrics, 2)

	// Verify uptime formatting
	assert.Equal(t, "2h 0m", data.Cards[0].Value) // 7200 seconds = 2h 0m

	// Verify error rate
	assert.Equal(t, "0.5%", data.Cards[2].Value)

	// Verify tool metrics
	assert.Equal(t, "get_holdings", data.ToolMetrics[0].ToolName)
	assert.True(t, data.ToolMetrics[1].HasErrors)
}

func TestMetricsToTemplateData_NilStats(t *testing.T) {
	t.Parallel()
	data := metricsToTemplateData(nil, nil, 0)
	assert.NotEmpty(t, data.Cards)
	assert.Equal(t, "0m", data.Cards[0].Value)  // 0 seconds uptime
	assert.Equal(t, "--", data.Cards[4].Value)   // Top Tool is "--" when no stats
}

func TestActivityToStatsData_NilStats(t *testing.T) {
	t.Parallel()
	data := activityToStatsData(nil)
	assert.Len(t, data.Cards, 4)
	assert.Equal(t, "--", data.Cards[0].Value)
}

func TestActivityToStatsData_WithStats(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls:   50,
		ErrorCount:   2,
		AvgLatencyMs: 35.0,
		TopTool:      "get_orders",
		TopToolCount: 10,
	}
	data := activityToStatsData(stats)
	assert.Equal(t, "50", data.Cards[0].Value)
	assert.Equal(t, "2", data.Cards[1].Value)
	assert.Equal(t, "red", data.Cards[1].Class) // errors > 0
}

func TestActivityToTimelineData(t *testing.T) {
	t.Parallel()
	entries := []audit.ToolCall{
		{
			ToolName:     "get_holdings",
			ToolCategory: "query",
			StartedAt:    time.Date(2026, 4, 6, 14, 0, 0, 0, time.UTC),
			DurationMs:   50,
			IsError:      false,
			InputSummary: "email=test@example.com",
		},
		{
			ToolName:     "place_order",
			ToolCategory: "order",
			StartedAt:    time.Date(2026, 4, 6, 14, 1, 0, 0, time.UTC),
			DurationMs:   200,
			IsError:      true,
			ErrorMessage: "insufficient margin",
		},
	}
	data := activityToTimelineData(entries)
	assert.Len(t, data.Entries, 2)
	assert.Equal(t, "success", data.Entries[0].StatusClass)
	assert.Equal(t, "fail", data.Entries[1].StatusClass)
	assert.True(t, data.Entries[1].IsError)
	assert.Equal(t, "QUERY", data.Entries[0].CatLabel)
	assert.Equal(t, "ORDER", data.Entries[1].CatLabel)
}

func TestOrdersToStatsData(t *testing.T) {
	t.Parallel()
	pnl := 5000.0
	summary := ordersSummary{
		TotalOrders:   10,
		Completed:     8,
		TotalPnL:      &pnl,
		WinningTrades: 6,
		LosingTrades:  2,
	}
	data := ordersToStatsData(summary)
	assert.Len(t, data.Cards, 4)
	assert.Equal(t, "10", data.Cards[0].Value)
	assert.Equal(t, "75%", data.Cards[3].Value) // 6/(6+2) = 75%
}

func TestOrdersToStatsData_NilPnL(t *testing.T) {
	t.Parallel()
	data := ordersToStatsData(ordersSummary{TotalOrders: 0})
	assert.Equal(t, "--", data.Cards[2].Value) // nil PnL
	assert.Equal(t, "--", data.Cards[3].Value) // 0 total trades
}

func TestOrdersToTableData(t *testing.T) {
	t.Parallel()
	fillPrice := 100.5
	pnl := 50.0
	entries := []orderEntry{
		{
			Symbol:   "NSE:RELIANCE",
			Side:     "BUY",
			Quantity: 10,
			FillPrice: &fillPrice,
			Status:   "COMPLETE",
			PlacedAt: "2026-04-06T10:00:00Z",
			PnL:      &pnl,
		},
		{
			Symbol:   "NSE:INFY",
			Side:     "SELL",
			Quantity: 5,
			Status:   "REJECTED",
			PlacedAt: "2026-04-06T11:00:00Z",
		},
	}
	data := ordersToTableData(entries)
	assert.Len(t, data.Orders, 2)
	assert.Equal(t, "side-buy", data.Orders[0].SideClass)
	assert.Equal(t, "side-sell", data.Orders[1].SideClass)
	assert.Equal(t, "status-complete", data.Orders[0].StatusBadge)
	assert.Equal(t, "status-rejected", data.Orders[1].StatusBadge)
}

func TestAlertsToStatsData(t *testing.T) {
	t.Parallel()
	dist := 2.5
	summary := alertsSummary{ActiveCount: 3, TriggeredCount: 1, AvgTimeToTrigger: "1h 30m"}
	nearest := &enrichedActiveAlert{Tradingsymbol: "RELIANCE", DistancePct: &dist}
	data := alertsToStatsData(summary, nearest)
	assert.Len(t, data.Cards, 4)
	assert.Equal(t, "3", data.Cards[0].Value)
	assert.Equal(t, "RELIANCE", data.Cards[3].Value)
}

func TestAlertsToStatsData_NoNearest(t *testing.T) {
	t.Parallel()
	data := alertsToStatsData(alertsSummary{}, nil)
	assert.Equal(t, "--", data.Cards[3].Value) // no nearest alert
}

func TestSafetyToFreezeData_Disabled(t *testing.T) {
	t.Parallel()
	data := safetyToFreezeData(map[string]any{"enabled": false, "message": "Not available"})
	assert.False(t, data.Enabled)
	assert.Equal(t, "Not available", data.Message)
}

func TestSafetyToFreezeData_EnabledFrozen(t *testing.T) {
	t.Parallel()
	data := safetyToFreezeData(map[string]any{
		"enabled": true,
		"status": map[string]any{
			"is_frozen":     true,
			"frozen_reason": "circuit breaker triggered",
			"frozen_by":     "system",
			"frozen_at":     "2026-04-06T14:00:00Z",
		},
	})
	assert.True(t, data.Enabled)
	assert.True(t, data.IsFrozen)
	assert.Equal(t, "circuit breaker triggered", data.FrozenReason)
	assert.NotEmpty(t, data.FrozenAtFmt)
}

func TestSafetyToLimitsData_Disabled(t *testing.T) {
	t.Parallel()
	data := safetyToLimitsData(map[string]any{"enabled": false})
	assert.False(t, data.Enabled)
}

func TestSafetyToLimitsData_Enabled(t *testing.T) {
	t.Parallel()
	data := safetyToLimitsData(map[string]any{
		"enabled": true,
		"status": map[string]any{
			"daily_order_count":  float64(50),
			"daily_placed_value": float64(250000),
		},
		"limits": map[string]any{
			"max_orders_per_day":    float64(200),
			"max_daily_value_inr":   float64(1000000),
			"max_single_order_inr":  float64(500000),
			"max_orders_per_minute": float64(10),
			"duplicate_window_secs": float64(30),
		},
	})
	assert.True(t, data.Enabled)
	assert.Len(t, data.Limits, 5)
	// Daily orders: 50/200 = 25%
	assert.Equal(t, 25, data.Limits[0].Pct)
	assert.Equal(t, "safe", data.Limits[0].BarClass)
}

func TestSafetyToSEBIData_Disabled(t *testing.T) {
	t.Parallel()
	data := safetyToSEBIData(map[string]any{"enabled": false})
	assert.False(t, data.Enabled)
}

func TestSafetyToSEBIData_Enabled(t *testing.T) {
	t.Parallel()
	data := safetyToSEBIData(map[string]any{
		"enabled": true,
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   true,
			"credentials_set":  false,
			"order_tagging":    true,
			"audit_trail":      true,
		},
	})
	assert.True(t, data.Enabled)
	assert.Len(t, data.Checks, 5)
	assert.Equal(t, "ok", data.Checks[0].DotClass)   // static_egress_ip = true
	assert.Equal(t, "off", data.Checks[2].DotClass)  // credentials_set = false
}

func TestMarketIndicesToBarData(t *testing.T) {
	t.Parallel()

	indices := map[string]any{
		"NSE:NIFTY 50": map[string]any{
			"last_price": float64(22000),
			"change":     float64(150),
			"change_pct": float64(0.68),
		},
		"NSE:NIFTY BANK": map[string]any{
			"last_price": float64(48000),
			"change":     float64(-200),
			"change_pct": float64(-0.42),
		},
	}
	data := marketIndicesToBarData(indices)

	assert.Len(t, data.Indices, 3) // NIFTY, BANK NIFTY, SENSEX (SENSEX missing → fallback)
	assert.Equal(t, "NIFTY 50", data.Indices[0].Label)
	assert.Equal(t, "up", data.Indices[0].ChangeClass)
	assert.Equal(t, "down", data.Indices[1].ChangeClass)
	assert.Equal(t, "--", data.Indices[2].PriceFmt) // SENSEX not in input
}

// ===========================================================================
// DashboardHandler initialization
// ===========================================================================

func TestNewDashboardHandler_NoPanic(t *testing.T) {
	t.Parallel()
	// Verifies that DashboardHandler can be created with nil dependencies.
	d := NewDashboardHandler(nil, nil, nil)
	assert.NotNil(t, d)
}

func TestDashboardHandler_SetAdminCheck(t *testing.T) {
	t.Parallel()
	d := NewDashboardHandler(nil, nil, nil)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	assert.NotNil(t, d.adminCheck)
}

func TestDashboardHandler_SetBillingStore(t *testing.T) {
	t.Parallel()
	d := NewDashboardHandler(nil, nil, nil)
	d.SetBillingStore(nil)
	assert.Nil(t, d.billingStore)
}

// ===========================================================================
// SSE helpers
// ===========================================================================

func TestWriteSSEEvent(t *testing.T) {
	t.Parallel()
	// writeSSEEvent writes to any io.Writer (http.ResponseWriter in prod)
	// We can't easily capture it without httptest, but we can verify it doesn't panic.
	// This is a smoke test.
	rw := &mockResponseWriter{}
	writeSSEEvent(rw, "test-event", "hello\nworld")
	output := rw.buf.String()
	assert.Contains(t, output, "event: test-event\n")
	assert.Contains(t, output, "data: hello\n")
	assert.Contains(t, output, "data: world\n")
}

// ===========================================================================
// Paper trading render helpers
// ===========================================================================

func TestPortfolioToHoldingsData(t *testing.T) {
	t.Parallel()
	holdings := []holdingItem{
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 10, AveragePrice: 2400, LastPrice: 2500, PnL: 1000, DayChangePercent: 2.5},
	}
	data := portfolioToHoldingsData(holdings)
	assert.Len(t, data.Holdings, 1)
	assert.Equal(t, "RELIANCE", data.Holdings[0].Tradingsymbol)
	assert.Equal(t, "green", data.Holdings[0].PnLClass)
}

func TestPortfolioToPositionsData(t *testing.T) {
	t.Parallel()
	positions := []positionItem{
		{Tradingsymbol: "INFY", Exchange: "NSE", Product: "MIS", Quantity: -5, AveragePrice: 1500, LastPrice: 1480, PnL: 100},
	}
	data := portfolioToPositionsData(positions)
	assert.Len(t, data.Positions, 1)
	assert.Equal(t, "MIS", data.Positions[0].Product)
	assert.Equal(t, "green", data.Positions[0].PnLClass)
}

// ===========================================================================
// Template parsing smoke tests
// ===========================================================================

func TestOverviewFragmentTemplates_Parse(t *testing.T) {
	t.Parallel()
	tmpl, err := overviewFragmentTemplates()
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}

func TestAdminFragmentTemplates_Parse(t *testing.T) {
	t.Parallel()
	tmpl, err := adminFragmentTemplates()
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}

func TestUserDashboardFragmentTemplates_Parse(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}

func TestRenderFragment(t *testing.T) {
	t.Parallel()
	tmpl, err := overviewFragmentTemplates()
	assert.NoError(t, err)

	data := overviewToTemplateData(OverviewData{
		Version:        "v1.0.0",
		ActiveSessions: 1,
	})

	html, err := renderFragment(tmpl, "overview_stats", data)
	assert.NoError(t, err)
	assert.Contains(t, html, "v1.0.0")
}

// ===========================================================================
// mock helpers
// ===========================================================================

// mockResponseWriter is a minimal http.ResponseWriter that captures output.
type mockResponseWriter struct {
	buf     bufWriter
	headers http.Header
}

type bufWriter struct {
	bytes []byte
}

func (b *bufWriter) String() string { return string(b.bytes) }

func (m *mockResponseWriter) Header() http.Header {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	return m.headers
}
func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.buf.bytes = append(m.buf.bytes, b...)
	return len(b), nil
}
func (m *mockResponseWriter) WriteHeader(int) {}
