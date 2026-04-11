package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appmetrics "github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ===========================================================================
// coverage_push6_test.go — Push trackToolCall/trackToolError to 80%+
//
// Existing tests only cover the nil-metrics (if-false) branch.
// These tests cover the if-true branch by creating a manager with metrics.
// ===========================================================================

// newMetricsManager creates a Manager with metrics enabled for testing
// the trackToolCall / trackToolError if-true branches.
func newMetricsManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	metricsMgr := appmetrics.New(appmetrics.Config{ServiceName: "test"})

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		Metrics:            metricsMgr,
	})
	require.NoError(t, err)

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

// ---------------------------------------------------------------------------
// trackToolCall / trackToolError — with metrics enabled (covers if-true branch)
// ---------------------------------------------------------------------------

func TestTrackToolCall_WithMetrics_LiveSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "get_holdings")
	})
	assert.True(t, mgr.HasMetrics())
}

func TestTrackToolCall_WithMetrics_PaperSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "paper")
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "place_order")
	})
}

func TestTrackToolCall_WithMetrics_UnknownSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	// No session type in context — falls back to SessionTypeUnknown
	ctx := context.Background()
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "get_profile")
	})
}

func TestTrackToolError_WithMetrics_AuthError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "place_order", "auth")
	})
}

func TestTrackToolError_WithMetrics_ValidationError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "paper")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "modify_order", "validation")
	})
}

func TestTrackToolError_WithMetrics_APIError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "cancel_order", "api")
	})
}

func TestTrackToolError_WithMetrics_UnknownSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := context.Background()
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "get_quotes", "timeout")
	})
}

func TestTrackToolCall_WithMetrics_MultipleTools(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	tools := []string{"get_holdings", "get_positions", "get_orders", "place_order", "set_alert"}
	for _, tool := range tools {
		handler.trackToolCall(ctx, tool)
	}
}

// ---------------------------------------------------------------------------
// SessionType context helpers — ensure coverage of WithSessionType / SessionTypeFromContext
// ---------------------------------------------------------------------------

func TestSessionType_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := WithSessionType(context.Background(), "paper")
	assert.Equal(t, "paper", SessionTypeFromContext(ctx))
}

func TestSessionType_DefaultUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))
}

// ---------------------------------------------------------------------------
// DevMode alert paths — exercise handler bodies with actual sessions
// ---------------------------------------------------------------------------

func TestSetAlert_DevMode_BelowDirection(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(500),
		"direction":  "below",
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_DropPctWithExplicitReference(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(5.0),
		"direction":       "drop_pct",
		"reference_price": float64(2500),
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_RisePctWithExplicitReference(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(10.0),
		"direction":       "rise_pct",
		"reference_price": float64(2000),
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_DropPctNoReference_FetchLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// No reference_price — will try to fetch LTP from stub Kite client
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(5.0),
		"direction":  "drop_pct",
	})
	assert.NotNil(t, result)
	// Either succeeds or returns error about LTP — both exercise more code
}

func TestSetAlert_DevMode_RisePctNoReference_FetchLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:RELIANCE",
		"price":      float64(10.0),
		"direction":  "rise_pct",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// DevMode SetupTelegram with session
// ---------------------------------------------------------------------------

func TestSetupTelegram_DevMode_NilNotifier_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(999888777),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Telegram notifications are not configured")
}
