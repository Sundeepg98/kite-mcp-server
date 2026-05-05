package analytics

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-broker/mock"
)

// Anchor 1 PR 1.7: these backtest-internals tests previously lived in
// mcp/get_tools_test.go but reference unexported symbols
// (runBacktest, computeMaxDrawdown, computeSharpeRatio, BacktestTrade,
// generateSignals, simulateTrades, backtestDefaults, backtestSignal)
// that were extracted into the mcp/analytics package. Moved here so
// the tests can continue to access those internals without exporting
// them or coupling mcp/ back to mcp/analytics.

// ---------------------------------------------------------------------------
// Backtest engine: pure function tests with mock data
// ---------------------------------------------------------------------------

func TestRunBacktest_SMACrossover(t *testing.T) {
	t.Parallel()
	client := mock.New()
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	candles, err := client.GetHistoricalData(256265, "day", from, to)
	require.NoError(t, err)
	require.Greater(t, len(candles), 50, "need at least 50 candles")

	result := runBacktest(candles, "sma_crossover", "NSE", "RELIANCE",
		1000000, 100, 20, 50)

	assert.Equal(t, "sma_crossover", result.Strategy)
	assert.Equal(t, "NSE:RELIANCE", result.Symbol)
	assert.Equal(t, 1000000.0, result.InitialCapital)
	assert.Greater(t, result.FinalCapital, 0.0, "final capital must be positive")
	assert.GreaterOrEqual(t, result.MaxDrawdown, 0.0, "max drawdown must be >= 0")
	assert.LessOrEqual(t, result.MaxDrawdown, 100.0, "max drawdown must be <= 100")
	assert.InDelta(t, result.WinRate, 50.0, 50.0, "win rate in [0, 100]")
	assert.NotEmpty(t, result.Period)

	// Buy and hold should be computable
	assert.False(t, math.IsNaN(result.BuyAndHold), "buy and hold should not be NaN")
	assert.False(t, math.IsInf(result.BuyAndHold, 0), "buy and hold should not be Inf")
}

func TestRunBacktest_AllStrategies(t *testing.T) {
	t.Parallel()
	client := mock.New()
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	candles, err := client.GetHistoricalData(256265, "day", from, to)
	require.NoError(t, err)

	strategies := []struct {
		name   string
		param1 float64
		param2 float64
	}{
		{"sma_crossover", 20, 50},
		{"rsi_reversal", 14, 70},
		{"breakout", 20, 10},
		{"mean_reversion", 20, 2.0},
	}

	for _, s := range strategies {
		t.Run(s.name, func(t *testing.T) {
			result := runBacktest(candles, s.name, "NSE", "TEST",
				500000, 100, s.param1, s.param2)

			assert.Equal(t, s.name, result.Strategy)
			assert.Greater(t, result.FinalCapital, 0.0)
			assert.GreaterOrEqual(t, result.MaxDrawdown, 0.0)
			assert.LessOrEqual(t, result.MaxDrawdown, 100.0)
			assert.False(t, math.IsNaN(result.TotalReturn))
			assert.False(t, math.IsNaN(result.SharpeRatio))
			assert.Equal(t, result.TotalTrades, result.WinningTrades+result.LosingTrades)
		})
	}
}

func TestComputeMaxDrawdown(t *testing.T) {
	t.Parallel()
	t.Run("no trades returns 0", func(t *testing.T) {
		dd := computeMaxDrawdown(nil, 100000)
		assert.Equal(t, 0.0, dd)
	})

	t.Run("all winning trades returns 0 drawdown", func(t *testing.T) {
		trades := []BacktestTrade{
			{PnL: 1000},
			{PnL: 2000},
			{PnL: 500},
		}
		dd := computeMaxDrawdown(trades, 100000)
		assert.Equal(t, 0.0, dd)
	})

	t.Run("single losing trade computes drawdown", func(t *testing.T) {
		trades := []BacktestTrade{
			{PnL: -10000},
		}
		dd := computeMaxDrawdown(trades, 100000)
		// Equity goes from 100000 to 90000. Drawdown = 10000/100000 * 100 = 10%
		assert.InDelta(t, 10.0, dd, 0.01)
	})

	t.Run("recovery then new loss", func(t *testing.T) {
		trades := []BacktestTrade{
			{PnL: -10000}, // 100K -> 90K, DD=10%
			{PnL: 20000},  // 90K -> 110K, new peak
			{PnL: -22000}, // 110K -> 88K, DD = 22K/110K = 20%
		}
		dd := computeMaxDrawdown(trades, 100000)
		assert.InDelta(t, 20.0, dd, 0.01)
	})
}

func TestComputeSharpeRatio(t *testing.T) {
	t.Parallel()
	t.Run("fewer than 2 trades returns 0", func(t *testing.T) {
		assert.Equal(t, 0.0, computeSharpeRatio(nil, 100000))
		assert.Equal(t, 0.0, computeSharpeRatio([]BacktestTrade{{PnL: 100}}, 100000))
	})

	t.Run("uniform returns give 0 stddev and 0 sharpe", func(t *testing.T) {
		trades := []BacktestTrade{
			{PnLPct: 5.0},
			{PnLPct: 5.0},
			{PnLPct: 5.0},
		}
		sharpe := computeSharpeRatio(trades, 100000)
		// StdDev = 0, so sharpe = 0
		assert.Equal(t, 0.0, sharpe)
	})

	t.Run("positive trades give positive sharpe", func(t *testing.T) {
		trades := []BacktestTrade{
			{PnLPct: 10.0},
			{PnLPct: 5.0},
			{PnLPct: 8.0},
			{PnLPct: 3.0},
			{PnLPct: 12.0},
		}
		sharpe := computeSharpeRatio(trades, 100000)
		assert.Greater(t, sharpe, 0.0, "mostly positive trades should give positive sharpe")
	})
}

func TestBacktestDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		strategy string
		p1       float64
		p2       float64
	}{
		{"sma_crossover", 20, 50},
		{"rsi_reversal", 14, 70},
		{"breakout", 20, 10},
		{"mean_reversion", 20, 2.0},
	}

	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			// No param overrides — should use defaults
			p1, p2 := backtestDefaults(tc.strategy, map[string]interface{}{})
			assert.Equal(t, tc.p1, p1)
			assert.Equal(t, tc.p2, p2)
		})
	}

	t.Run("overrides defaults", func(t *testing.T) {
		args := map[string]interface{}{
			"param1": 30.0,
			"param2": 100.0,
		}
		p1, p2 := backtestDefaults("sma_crossover", args)
		assert.Equal(t, 30.0, p1)
		assert.Equal(t, 100.0, p2)
	})
}

// ---------------------------------------------------------------------------
// Backtest signal generation tests
// ---------------------------------------------------------------------------

func TestGenerateSignals_SMACrossover(t *testing.T) {
	t.Parallel()
	// Create a price series with a clear crossover
	prices := make([]float64, 100)
	for i := 0; i < 50; i++ {
		prices[i] = 100.0 - float64(i)*0.5 // declining
	}
	for i := 50; i < 100; i++ {
		prices[i] = 75.0 + float64(i-50)*1.0 // strong recovery
	}

	highs := make([]float64, 100)
	lows := make([]float64, 100)
	for i := range prices {
		highs[i] = prices[i] + 2
		lows[i] = prices[i] - 2
	}

	signals := generateSignals("sma_crossover", prices, highs, lows, 10, 30)
	assert.Len(t, signals, len(prices))

	// There should be at least one signal in the recovery phase
	var hasBuy, hasSell bool
	for _, s := range signals {
		if s != nil && s.action == "BUY" {
			hasBuy = true
		}
		if s != nil && s.action == "SELL" {
			hasSell = true
		}
	}
	assert.True(t, hasBuy || hasSell, "SMA crossover should generate at least one signal")
}

func TestSimulateTrades_ForcesCloseAtEnd(t *testing.T) {
	t.Parallel()
	candles := make([]broker.HistoricalCandle, 10)
	for i := range candles {
		candles[i] = broker.HistoricalCandle{
			Date:  time.Date(2025, 1, i+1, 0, 0, 0, 0, time.UTC),
			Close: 100 + float64(i),
		}
	}

	signals := make([]*backtestSignal, 10)
	// Buy at index 2, no sell signal
	signals[2] = &backtestSignal{action: "BUY", reason: "test entry"}

	trades := simulateTrades(candles, signals, 100000, 100)

	// Should force close the open position
	assert.Len(t, trades, 1)
	assert.Contains(t, trades[0].Reason, "forced close")
	assert.Equal(t, 109.0, trades[0].ExitPrice) // last candle close
}
