package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/mcp/trade"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// Anchor 1 PR 1.7: indicator-internals tests (TestSafeLastValue_*,
// TestSafeBBWidth*, TestComputeSignals_*) moved to
// mcp/analytics/tools_pure_math_test.go because they reference
// unexported analytics-package symbols.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func TestRound4(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.1416, trade.Round4(3.14159265))
	assert.Equal(t, 0.0, trade.Round4(0.0))
	assert.Equal(t, 1.0, trade.Round4(1.0))
	assert.Equal(t, -2.7183, trade.Round4(-2.71828))
}

func TestRound6(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.141593, trade.Round6(3.14159265))
	assert.Equal(t, 0.0, trade.Round6(0.0))
	assert.Equal(t, 1.0, trade.Round6(1.0))
}

func TestBsRho_Call(t *testing.T) {
	t.Parallel()
	// S=100, K=100, T=1, r=0.05, sigma=0.2, isCall=true
	rho := trade.BsRho(100, 100, 1, 0.05, 0.2, true)
	assert.Greater(t, rho, 0.0, "call rho should be positive")
}

func TestBsRho_Put(t *testing.T) {
	t.Parallel()
	rho := trade.BsRho(100, 100, 1, 0.05, 0.2, false)
	assert.Less(t, rho, 0.0, "put rho should be negative")
}

func TestBsRho_ZeroTime(t *testing.T) {
	t.Parallel()
	rho := trade.BsRho(100, 100, 0, 0.05, 0.2, true)
	assert.Equal(t, 0.0, rho, "rho with zero time should be 0")
}

func TestBsRho_ZeroVol(t *testing.T) {
	t.Parallel()
	rho := trade.BsRho(100, 100, 1, 0.05, 0, true)
	assert.Equal(t, 0.0, rho, "rho with zero vol should be 0")
}

func TestRoundTo2(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.14, roundTo2(3.14159))
	assert.Equal(t, 0.0, roundTo2(0.0))
	assert.Equal(t, -1.23, roundTo2(-1.234))
	assert.Equal(t, 100.0, roundTo2(100.0))
}
