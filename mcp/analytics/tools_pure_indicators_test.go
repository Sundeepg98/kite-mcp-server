package analytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: indicator-internals tests (TestComputeRSI_*,
// TestComputeSMA_*, TestComputeEMA_*, TestComputeBollingerBands_*)
// previously lived in mcp/tools_pure_test.go but reference unexported
// analytics symbols (computeRSI, computeSMA, computeEMA,
// computeBollingerBands). Moved here so the tests can access internals
// without exporting them.

func TestComputeRSI_InsufficientData(t *testing.T) {
	t.Parallel()
	result := computeRSI([]float64{100, 101}, 14)
	assert.Nil(t, result)
}

func TestComputeRSI_AllUp(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = float64(100 + i)
	}
	result := computeRSI(prices, 14)
	assert.NotNil(t, result)
	assert.Equal(t, 100.0, result[14])
}

func TestComputeRSI_BoundsCheck(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		if i%2 == 0 {
			prices[i] = 100 + float64(i)
		} else {
			prices[i] = 100 - float64(i)
		}
	}
	result := computeRSI(prices, 14)
	assert.NotNil(t, result)
	for i := 14; i < len(result); i++ {
		assert.GreaterOrEqual(t, result[i], 0.0)
		assert.LessOrEqual(t, result[i], 100.0)
	}
}

func TestComputeSMA_InsufficientData(t *testing.T) {
	t.Parallel()
	result := computeSMA([]float64{100, 101}, 5)
	assert.Nil(t, result)
}

func TestComputeSMA_ExactPeriod(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20, 30, 40, 50}
	result := computeSMA(prices, 5)
	assert.NotNil(t, result)
	assert.Equal(t, 30.0, result[4])
}

func TestComputeSMA_RollingWindow(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20, 30, 40, 50, 60}
	result := computeSMA(prices, 3)
	assert.NotNil(t, result)
	assert.InDelta(t, 20.0, result[2], 0.01)
	assert.InDelta(t, 30.0, result[3], 0.01)
	assert.InDelta(t, 40.0, result[4], 0.01)
	assert.InDelta(t, 50.0, result[5], 0.01)
}

func TestComputeEMA_InsufficientData(t *testing.T) {
	t.Parallel()
	result := computeEMA([]float64{100}, 5)
	assert.Nil(t, result)
}

func TestComputeEMA_FirstValueIsSMA(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20, 30, 40, 50}
	result := computeEMA(prices, 5)
	assert.NotNil(t, result)
	assert.Equal(t, 30.0, result[4])
}

func TestComputeEMA_ResponsivenessToJump(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 10, 10, 10, 10, 100}
	result := computeEMA(prices, 5)
	assert.NotNil(t, result)
	assert.Greater(t, result[5], 10.0)
	assert.Less(t, result[5], 100.0)
}

func TestComputeBollingerBands_InsufficientData(t *testing.T) {
	t.Parallel()
	u, m, l := computeBollingerBands([]float64{100}, 5, 2.0)
	assert.Nil(t, u)
	assert.Nil(t, m)
	assert.Nil(t, l)
}

func TestComputeBollingerBands_ConstantPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{100, 100, 100, 100, 100}
	u, m, l := computeBollingerBands(prices, 5, 2.0)
	assert.NotNil(t, u)
	assert.Equal(t, 100.0, m[4])
	assert.Equal(t, 100.0, u[4])
	assert.Equal(t, 100.0, l[4])
}

func TestComputeBollingerBands_UpperAboveLower(t *testing.T) {
	t.Parallel()
	prices := []float64{95, 100, 105, 100, 95, 100, 105}
	u, m, l := computeBollingerBands(prices, 5, 2.0)
	assert.NotNil(t, u)
	for i := 4; i < len(prices); i++ {
		assert.GreaterOrEqual(t, u[i], m[i])
		assert.LessOrEqual(t, l[i], m[i])
	}
}

// Second batch — TestComputeRSI_Basics through TestComputeBollingerBands_TooFewPrices
// originally at lines 1451–1540 of mcp/tools_pure_test.go.

func TestComputeRSI_Basics(t *testing.T) {
	t.Parallel()
	// 15 prices: first 14 go up → RSI should be high
	prices := make([]float64, 20)
	for i := range prices {
		prices[i] = 100 + float64(i)*2
	}
	rsi := computeRSI(prices, 14)
	assert.NotNil(t, rsi)
	assert.Greater(t, len(rsi), 0)
	// All gains → RSI should be near 100
	last := rsi[len(rsi)-1]
	assert.Greater(t, last, 80.0)
}

func TestComputeRSI_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	rsi := computeRSI(prices, 14)
	assert.Nil(t, rsi)
}

func TestComputeSMA_Basic(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20, 30, 40, 50}
	sma := computeSMA(prices, 3)
	assert.NotNil(t, sma)
	// SMA of last 3 values (30+40+50)/3 = 40
	assert.InDelta(t, 40.0, sma[4], 0.01)
}

func TestComputeSMA_PeriodTooLong(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20}
	sma := computeSMA(prices, 5)
	assert.Nil(t, sma)
}

func TestComputeEMA_Basic(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = 100 + float64(i)
	}
	ema := computeEMA(prices, 12)
	assert.NotNil(t, ema)
	assert.Equal(t, len(prices), len(ema))
}

func TestComputeEMA_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	ema := computeEMA(prices, 12)
	assert.Nil(t, ema)
}

func TestComputeBollingerBands_Basic(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = 100 + float64(i%5)
	}
	upper, middle, lower := computeBollingerBands(prices, 20, 2.0)
	assert.NotNil(t, upper)
	assert.NotNil(t, middle)
	assert.NotNil(t, lower)
	// Upper should be > middle > lower for the last value
	last := len(upper) - 1
	if last >= 0 && upper[last] > 0 {
		assert.Greater(t, upper[last], lower[last])
	}
}

func TestComputeBollingerBands_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	upper, middle, lower := computeBollingerBands(prices, 20, 2.0)
	assert.Nil(t, upper)
	assert.Nil(t, middle)
	assert.Nil(t, lower)
}
