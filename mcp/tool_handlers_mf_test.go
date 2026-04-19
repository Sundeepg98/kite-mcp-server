package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// MF tools: pre-session validation
// ---------------------------------------------------------------------------
func TestPlaceMFOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_mf_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestPlaceMFOrder_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"transaction_type": "BUY",
		"amount":           float64(5000),
		// tradingsymbol missing
	})
	assert.True(t, result.IsError, "place_mf_order without tradingsymbol should fail")
	assertResultContains(t, result, "tradingsymbol")
}


func TestPlaceMFOrder_BuyRequiresAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		// amount missing → should error for BUY
	})
	assert.True(t, result.IsError, "place_mf_order BUY without amount should fail")
	assertResultContains(t, result, "amount is required")
}


func TestPlaceMFOrder_SellRequiresQuantity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "SELL",
		// quantity missing → should error for SELL
	})
	assert.True(t, result.IsError, "place_mf_order SELL without quantity should fail")
	assertResultContains(t, result, "quantity is required")
}


func TestPlaceMFSIP_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_mf_sip with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestPlaceMFSIP_ZeroAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{
		"tradingsymbol": "INF209K01YS2",
		"amount":        float64(0),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError, "place_mf_sip with zero amount should fail")
	assertResultContains(t, result, "amount must be greater than 0")
}


func TestCancelMFOrder_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_mf_order without order_id should fail")
	assertResultContains(t, result, "is required")
}


func TestCancelMFSIP_MissingSIPID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_sip", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_mf_sip without sip_id should fail")
	assertResultContains(t, result, "is required")
}
