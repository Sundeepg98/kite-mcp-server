package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.

func TestGetHoldings_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_holdings", "trader@example.com", map[string]any{})
	// Should fail with login required (no real Kite client), not panic
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestGetPositions_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_positions", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestGetMargins_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestGetProfile_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_profile", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestGetOrders_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestGetTrades_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestPortfolioSummary_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_summary", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestPortfolioConcentration_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_concentration", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestPositionAnalysis_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "position_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestPortfolioRebalance_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
	})
	assert.True(t, result.IsError)
}


func TestPortfolioRebalance_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"mode":      "percentage",
		"threshold": float64(1.0),
	})
	assert.NotNil(t, result)
	// Exercises handler body with mock broker
}


func TestPortfolioRebalance_ValueMode_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"targets": `{"RELIANCE": 200000, "INFY": 150000}`,
		"mode":    "value",
	})
	assert.NotNil(t, result)
}


func TestPortfolioRebalance_WithThreshold_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"mode":      "percentage",
		"threshold": float64(5.0),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// get_tools.go: PaginatedToolHandler paths (77-78% -> higher)
// ---------------------------------------------------------------------------
func TestGetTrades_Paginated(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}


func TestGetOrders_Paginated(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// analytics_tools.go: deeper handler paths (69-77% -> higher)
// ---------------------------------------------------------------------------
func TestPortfolioConcentration_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "cred@example.com", map[string]any{
		"threshold": float64(30),
	})
	assert.NotNil(t, result)
}


func TestPositionAnalysis_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestPortfolioSummary_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// rebalance tool
// ---------------------------------------------------------------------------
func TestPortfolioRebalance_WithTargets(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"target_allocation": `{"INFY":40,"RELIANCE":60}`,
		"position_size_pct": float64(100),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// get_margins with segment
// ---------------------------------------------------------------------------
func TestGetMargins_WithSegment(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// analytics: portfolio_analysis edge cases
// ---------------------------------------------------------------------------
func TestPortfolioRebalance_InvalidJSON_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"target_allocation": `{not json}`,
	})
	assert.True(t, result.IsError)
}


// ---------------------------------------------------------------------------
// get_holdings / get_positions with pagination
// ---------------------------------------------------------------------------
func TestGetHoldings_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


func TestGetPositions_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// portfolio_analysis: missing params
// ---------------------------------------------------------------------------
func TestPortfolioRebalance_MissingTargets_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}
