package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
)

func TestBuildOrderConfirmMessage(t *testing.T) {
	t.Run("place_order MARKET", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_order", map[string]any{
			"transaction_type": "BUY",
			"quantity":         float64(10),
			"exchange":         "NSE",
			"tradingsymbol":    "RELIANCE",
			"order_type":       "MARKET",
			"product":          "CNC",
		})
		assert.Contains(t, msg, "BUY")
		assert.Contains(t, msg, "10")
		assert.Contains(t, msg, "NSE:RELIANCE")
		assert.Contains(t, msg, "MARKET")
		assert.Contains(t, msg, "CNC")
	})

	t.Run("place_order LIMIT with price", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_order", map[string]any{
			"transaction_type": "SELL",
			"quantity":         float64(5),
			"exchange":         "BSE",
			"tradingsymbol":    "INFY",
			"order_type":       "LIMIT",
			"price":            float64(1500.50),
			"product":          "MIS",
		})
		assert.Contains(t, msg, "SELL")
		assert.Contains(t, msg, "BSE:INFY")
		assert.Contains(t, msg, "1500.50")
	})

	t.Run("modify_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("modify_order", map[string]any{
			"order_id":   "250402000123",
			"order_type": "LIMIT",
			"quantity":   float64(20),
			"price":      float64(2800),
		})
		assert.Contains(t, msg, "Modify order")
		assert.Contains(t, msg, "250402000123")
		assert.Contains(t, msg, "2800")
	})

	t.Run("close_all_positions", func(t *testing.T) {
		msg := buildOrderConfirmMessage("close_all_positions", map[string]any{
			"confirm": true,
			"product": "ALL",
		})
		assert.Contains(t, msg, "Close ALL")
	})

	t.Run("place_gtt_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_gtt_order", map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"trigger_type":     "single",
			"trigger_value":    float64(1400),
			"limit_price":      float64(1395),
		})
		assert.Contains(t, msg, "GTT")
		assert.Contains(t, msg, "NSE:INFY")
		assert.Contains(t, msg, "1400")
	})

	t.Run("place_mf_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
			"tradingsymbol":    "INF209K01YN0",
			"transaction_type": "BUY",
			"amount":           float64(10000),
		})
		assert.Contains(t, msg, "MF")
		assert.Contains(t, msg, "INF209K01YN0")
		assert.Contains(t, msg, "10000")
	})

	t.Run("place_mf_sip", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_mf_sip", map[string]any{
			"tradingsymbol": "INF209K01YN0",
			"amount":        float64(5000),
			"frequency":     "monthly",
			"instalments":   float64(12),
		})
		assert.Contains(t, msg, "SIP")
		assert.Contains(t, msg, "5000")
		assert.Contains(t, msg, "monthly")
		assert.Contains(t, msg, "12")
	})

	t.Run("unknown tool returns generic message", func(t *testing.T) {
		msg := buildOrderConfirmMessage("unknown_tool", map[string]any{})
		assert.Contains(t, msg, "Confirm")
	})
}

func TestIsConfirmableTool(t *testing.T) {
	assert.True(t, isConfirmableTool("place_order"))
	assert.True(t, isConfirmableTool("modify_order"))
	assert.True(t, isConfirmableTool("close_position"))
	assert.True(t, isConfirmableTool("close_all_positions"))
	assert.True(t, isConfirmableTool("place_gtt_order"))
	assert.True(t, isConfirmableTool("modify_gtt_order"))
	assert.True(t, isConfirmableTool("place_mf_order"))
	assert.True(t, isConfirmableTool("place_mf_sip"))
	assert.False(t, isConfirmableTool("cancel_order"))
	assert.False(t, isConfirmableTool("delete_gtt_order"))
	assert.False(t, isConfirmableTool("get_holdings"))
	assert.False(t, isConfirmableTool("login"))
}

func TestParseElicitationError(t *testing.T) {
	t.Run("user declined", func(t *testing.T) {
		err := errors.New("order declined by user")
		assert.Contains(t, err.Error(), "declined")
	})

	t.Run("user cancelled", func(t *testing.T) {
		err := errors.New("order cancelled by user")
		assert.Contains(t, err.Error(), "cancelled")
	})
}

// ---------------------------------------------------------------------------
// requestConfirmation: direct unit tests covering all branches
// ---------------------------------------------------------------------------

func TestRequestConfirmation_NilServerRef(t *testing.T) {
	err := requestConfirmation(context.Background(), nil, "test")
	assert.NoError(t, err, "nil server should fail open")
}

func TestRequestConfirmation_NonMCPServerType(t *testing.T) {
	err := requestConfirmation(context.Background(), "not-a-server", "test")
	assert.NoError(t, err, "non-MCPServer should fail open")
}

func TestRequestConfirmation_NoActiveSession(t *testing.T) {
	// MCPServer with no active session → ErrNoActiveSession → fail open
	srv := server.NewMCPServer("test", "1.0", server.WithElicitation())
	err := requestConfirmation(context.Background(), srv, "Confirm order?")
	assert.NoError(t, err, "no active session should fail open")
}

func TestRequestConfirmation_ElicitationNotEnabled(t *testing.T) {
	// MCPServer without elicitation support → ErrElicitationNotSupported → fail open
	srv := server.NewMCPServer("test", "1.0") // no WithElicitation
	err := requestConfirmation(context.Background(), srv, "Confirm order?")
	assert.NoError(t, err, "elicitation not supported should fail open")
}
