package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_PassesNonBrokerTools(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)
	called := false
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		called = true
		return gomcp.NewToolResultText("ok"), nil
	}

	mw := cb.Middleware()
	wrapped := mw(handler)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "search_instruments"
	result, err := wrapped(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, called)
	assert.NotNil(t, result)
}

func TestCircuitBreaker_ClosedState_PassesThrough(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}

	mw := cb.Middleware()
	wrapped := mw(handler)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := wrapped(context.Background(), req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return nil, errors.New("kite API connection refused")
	}

	mw := cb.Middleware()
	wrapped := mw(handler)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"

	// Fail 3 times to open the circuit
	for i := 0; i < 3; i++ {
		_, _ = wrapped(context.Background(), req)
	}

	assert.Equal(t, CircuitOpen, cb.State())

	// Next call should be blocked
	result, err := wrapped(context.Background(), req)
	require.NoError(t, err) // error is returned as tool result, not Go error
	assert.Contains(t, result.Content[0].(gomcp.TextContent).Text, "circuit breaker is open")
}

func TestCircuitBreaker_RecoversAfterSuccess(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	callCount := 0
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		callCount++
		if callCount <= 2 {
			return nil, errors.New("broker timeout")
		}
		return gomcp.NewToolResultText("ok"), nil
	}

	mw := cb.Middleware()
	wrapped := mw(handler)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	// Fail twice to open
	_, _ = wrapped(context.Background(), req)
	_, _ = wrapped(context.Background(), req)
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for open duration to expire (half-open)
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Next call should go through (probe) and succeed
	result, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_SuccessResetsCounter(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)
	callCount := 0
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		callCount++
		if callCount == 2 {
			return gomcp.NewToolResultText("ok"), nil // success on second call
		}
		return nil, errors.New("kite error")
	}

	mw := cb.Middleware()
	wrapped := mw(handler)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_orders"

	// Fail once
	_, _ = wrapped(context.Background(), req)
	assert.Equal(t, CircuitClosed, cb.State())

	// Succeed — should reset counter
	_, _ = wrapped(context.Background(), req)
	assert.Equal(t, CircuitClosed, cb.State())

	// Fail once more — counter should be at 1, not 2
	_, _ = wrapped(context.Background(), req)
	assert.Equal(t, CircuitClosed, cb.State(), "counter should have reset after success")
}

func TestCircuitBreaker_IsBrokerTool(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)

	assert.True(t, cb.isBrokerTool("place_order"))
	assert.True(t, cb.isBrokerTool("get_holdings"))
	assert.True(t, cb.isBrokerTool("get_ltp"))
	assert.False(t, cb.isBrokerTool("search_instruments"))
	assert.False(t, cb.isBrokerTool("backtest_strategy"))
	assert.False(t, cb.isBrokerTool(""))
}

func TestIsBrokerError(t *testing.T) {
	assert.True(t, isBrokerError(nil, errors.New("kite API error")))
	assert.True(t, isBrokerError(nil, errors.New("broker connection failed")))
	assert.True(t, isBrokerError(nil, errors.New("timeout waiting for response")))
	assert.True(t, isBrokerError(nil, errors.New("connection refused")))
	assert.False(t, isBrokerError(nil, errors.New("invalid quantity")))
	assert.False(t, isBrokerError(nil, nil))
}
