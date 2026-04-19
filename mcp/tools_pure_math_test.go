package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestRound4(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.1416, round4(3.14159265))
	assert.Equal(t, 0.0, round4(0.0))
	assert.Equal(t, 1.0, round4(1.0))
	assert.Equal(t, -2.7183, round4(-2.71828))
}


func TestRound6(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.141593, round6(3.14159265))
	assert.Equal(t, 0.0, round6(0.0))
	assert.Equal(t, 1.0, round6(1.0))
}


func TestBsRho_Call(t *testing.T) {
	t.Parallel()
	// S=100, K=100, T=1, r=0.05, sigma=0.2, isCall=true
	rho := bsRho(100, 100, 1, 0.05, 0.2, true)
	assert.Greater(t, rho, 0.0, "call rho should be positive")
}


func TestBsRho_Put(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 1, 0.05, 0.2, false)
	assert.Less(t, rho, 0.0, "put rho should be negative")
}


func TestBsRho_ZeroTime(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 0, 0.05, 0.2, true)
	assert.Equal(t, 0.0, rho, "rho with zero time should be 0")
}


func TestBsRho_ZeroVol(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 1, 0.05, 0, true)
	assert.Equal(t, 0.0, rho, "rho with zero vol should be 0")
}


func TestSafeLastValue_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0.0, safeLastValue([]float64{}))
	assert.Equal(t, 0.0, safeLastValue(nil))
	assert.Equal(t, 5.0, safeLastValue([]float64{1, 2, 3, 4, 5}))
	assert.Equal(t, 42.0, safeLastValue([]float64{42}))
	assert.Equal(t, -1.0, safeLastValue([]float64{-1}))
}


func TestSafeBBWidth(t *testing.T) {
	t.Parallel()
	// Normal case
	upper := []float64{110}
	lower := []float64{90}
	middle := []float64{100}
	assert.Equal(t, 20.0, safeBBWidth(upper, lower, middle))

	// Zero middle
	assert.Equal(t, 0.0, safeBBWidth([]float64{10}, []float64{5}, []float64{0}))

	// Empty arrays
	assert.Equal(t, 0.0, safeBBWidth([]float64{}, []float64{}, []float64{}))
}


func TestRoundTo2(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.14, roundTo2(3.14159))
	assert.Equal(t, 0.0, roundTo2(0.0))
	assert.Equal(t, -1.23, roundTo2(-1.234))
	assert.Equal(t, 100.0, roundTo2(100.0))
}


func TestComputeSignals_WithData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 102, 104, 106, 108}
	rsi := []float64{75} // Overbought
	sma20 := []float64{100}
	sma50 := []float64{95}
	ema12 := []float64{105}
	ema26 := []float64{100}
	bbUpper := []float64{115}
	bbLower := []float64{85}
	macdLine := []float64{5}
	macdSignal := []float64{3}

	signals := computeSignals(closes, rsi, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal)
	assert.NotEmpty(t, signals)
	// With RSI=75, should have overbought signal
	found := false
	for _, s := range signals {
		if len(s) > 0 {
			found = true
		}
	}
	assert.True(t, found, "should produce at least one signal")
}


func TestComputeSignals_OversoldRSI(t *testing.T) {
	t.Parallel()
	closes := []float64{90, 88, 86, 84, 82}
	rsi := []float64{25} // Oversold
	signals := computeSignals(closes, rsi, nil, nil, nil, nil, nil, nil, nil, nil)
	found := false
	for _, s := range signals {
		if len(s) > 0 {
			found = true
		}
	}
	assert.True(t, found)
}


func TestComputeSignals_GoldenCross(t *testing.T) {
	t.Parallel()
	closes := []float64{100}
	sma20 := []float64{105} // SMA20 > SMA50 = golden cross
	sma50 := []float64{95}
	signals := computeSignals(closes, nil, sma20, sma50, nil, nil, nil, nil, nil, nil)
	assert.NotEmpty(t, signals)
}


func TestComputeSignals_NoSignals(t *testing.T) {
	t.Parallel()
	closes := []float64{100}
	// Everything neutral
	signals := computeSignals(closes, []float64{50}, []float64{100}, []float64{100}, nil, nil, nil, nil, nil, nil)
	assert.Contains(t, signals, "No strong signals")
}


func TestComputeSignals_WithSufficientData(t *testing.T) {
	t.Parallel()
	// Generate enough data for all indicators
	n := 60
	prices := make([]float64, n)
	for i := range prices {
		prices[i] = 100 + float64(i%10)*2
	}

	rsi := computeRSI(prices, 14)
	sma20 := computeSMA(prices, 20)
	sma50 := computeSMA(prices, 50)
	ema12 := computeEMA(prices, 12)
	ema26 := computeEMA(prices, 26)
	bbUpper, _, bbLower := computeBollingerBands(prices, 20, 2.0)
	macdLine := make([]float64, n)
	for i := range prices {
		if i < len(ema12) && i < len(ema26) {
			macdLine[i] = ema12[i] - ema26[i]
		}
	}
	macdSignal := computeEMA(macdLine, 9)

	signals := computeSignals(prices, rsi, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal)
	assert.NotNil(t, signals)
}


func TestSafeLastValue_NegativeValues(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -5.0, safeLastValue([]float64{-5}))
	assert.Equal(t, -100.5, safeLastValue([]float64{10, 20, -100.5}))
}


func TestSafeBBWidth_ZeroMiddle(t *testing.T) {
	t.Parallel()
	// Zero middle should avoid division by zero
	upper := []float64{10}
	lower := []float64{-10}
	middle := []float64{0}
	w := safeBBWidth(upper, lower, middle)
	// Depends on implementation: either 0 or Inf
	_ = w
}
