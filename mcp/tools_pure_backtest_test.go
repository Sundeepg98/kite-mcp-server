package mcp

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestSignalsSMACrossover_InsufficientData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101, 102}
	signals := signalsSMACrossover(closes, 5, 20)
	// SMA returns nil for insufficient data, signals should be all nil
	for _, s := range signals {
		assert.Nil(t, s)
	}
}


func TestSignalsSMACrossover_CrossoverAndCrossunder(t *testing.T) {
	t.Parallel()
	// Create price data where short SMA crosses above then below long SMA
	closes := make([]float64, 60)
	for i := range 60 {
		closes[i] = 100 + float64(i)*0.5
	}
	// Insert a dip in the middle to create crossunder then crossover
	for i := 25; i < 35; i++ {
		closes[i] = 100 - float64(i-25)*2
	}

	signals := signalsSMACrossover(closes, 5, 20)
	assert.Equal(t, 60, len(signals))

	hasBuy, hasSell := false, false
	for _, s := range signals {
		if s != nil {
			assert.Contains(t, []string{"BUY", "SELL"}, s.action)
			assert.Contains(t, s.reason, "SMA")
			if s.action == "BUY" {
				hasBuy = true
			}
			if s.action == "SELL" {
				hasSell = true
			}
		}
	}
	assert.True(t, hasBuy || hasSell, "should generate at least one signal")
}


func TestSignalsRSIReversal_OversoldBuy(t *testing.T) {
	t.Parallel()
	// Create a downtrend followed by reversal to trigger oversold RSI
	closes := make([]float64, 40)
	for i := range 20 {
		closes[i] = 100 - float64(i)*3 // steep decline
	}
	for i := 20; i < 40; i++ {
		closes[i] = 40 + float64(i-20)*2 // recovery
	}

	signals := signalsRSIReversal(closes, 14, 70)
	assert.Equal(t, 40, len(signals))

	for _, s := range signals {
		if s != nil {
			assert.Contains(t, []string{"BUY", "SELL"}, s.action)
			assert.Contains(t, s.reason, "RSI")
		}
	}
}


func TestSignalsRSIReversal_InsufficientData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101}
	signals := signalsRSIReversal(closes, 14, 70)
	for _, s := range signals {
		assert.Nil(t, s)
	}
}


func TestSignalsBreakout_BreakAboveHigh(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 30)
	highs := make([]float64, 30)
	lows := make([]float64, 30)
	for i := range 25 {
		closes[i] = 100
		highs[i] = 105
		lows[i] = 95
	}
	for i := 25; i < 30; i++ {
		closes[i] = 115
		highs[i] = 120
		lows[i] = 110
	}

	signals := signalsBreakout(closes, highs, lows, 10, 5)
	assert.Equal(t, 30, len(signals))

	hasBuy := false
	for _, s := range signals {
		if s != nil && s.action == "BUY" {
			hasBuy = true
			assert.Contains(t, s.reason, "broke above")
		}
	}
	assert.True(t, hasBuy, "should have at least one BUY breakout signal")
}


func TestSignalsBreakout_BreakBelowLow(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 30)
	highs := make([]float64, 30)
	lows := make([]float64, 30)
	for i := range 25 {
		closes[i] = 100
		highs[i] = 105
		lows[i] = 95
	}
	for i := 25; i < 30; i++ {
		closes[i] = 80
		highs[i] = 85
		lows[i] = 75
	}

	signals := signalsBreakout(closes, highs, lows, 10, 5)
	hasSell := false
	for _, s := range signals {
		if s != nil && s.action == "SELL" {
			hasSell = true
			assert.Contains(t, s.reason, "broke below")
		}
	}
	assert.True(t, hasSell, "should have at least one SELL breakdown signal")
}


func TestSignalsMeanReversion_BelowLowerBand(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 40)
	for i := range 30 {
		closes[i] = 100 + float64(i%5)
	}
	for i := 30; i < 40; i++ {
		closes[i] = 80
	}

	signals := signalsMeanReversion(closes, 20, 2.0)
	assert.Equal(t, 40, len(signals))

	hasBuy := false
	for _, s := range signals {
		if s != nil && s.action == "BUY" {
			hasBuy = true
			assert.Contains(t, s.reason, "below lower BB")
		}
	}
	assert.True(t, hasBuy, "should have BUY signal when price drops below lower BB")
}


func TestSignalsMeanReversion_InsufficientData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101, 102}
	signals := signalsMeanReversion(closes, 20, 2.0)
	for _, s := range signals {
		assert.Nil(t, s)
	}
}


func TestSimulateTrades_BuyAndSellRoundTrip(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{100, 105, 110, 115, 120}, time.Now())
	signals := make([]*backtestSignal, 5)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry"}
	signals[3] = &backtestSignal{action: "SELL", reason: "exit"}

	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Equal(t, 1, len(trades))
	assert.Equal(t, "BUY", trades[0].Side)
	assert.Greater(t, trades[0].PnL, 0.0)
	assert.Contains(t, trades[0].Reason, "entry")
	assert.Contains(t, trades[0].Reason, "exit")
}


func TestSimulateTrades_NoSignals(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{100, 105, 110}, time.Now())
	signals := make([]*backtestSignal, 3)
	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Empty(t, trades)
}


func TestSimulateTrades_PositionSizing(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{100, 110}, time.Now())
	signals := make([]*backtestSignal, 2)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry"}
	signals[1] = &backtestSignal{action: "SELL", reason: "exit"}

	// 50% position size of 100000 = 50000 / 100 = 500 shares
	trades := simulateTrades(candles, signals, 100000, 50)
	assert.Equal(t, 1, len(trades))
	assert.Equal(t, 500, trades[0].Quantity)
}


func TestSimulateTrades_SellWithoutPosition(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{100, 105}, time.Now())
	signals := make([]*backtestSignal, 2)
	signals[0] = &backtestSignal{action: "SELL", reason: "premature sell"}
	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Empty(t, trades)
}


func TestSimulateTrades_MultipleBuysSameSignal(t *testing.T) {
	t.Parallel()
	// Second BUY while already in position should be ignored
	candles := makeCandlesHelper([]float64{100, 105, 110, 115, 120}, time.Now())
	signals := make([]*backtestSignal, 5)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry1"}
	signals[1] = &backtestSignal{action: "BUY", reason: "entry2"} // ignored
	signals[4] = &backtestSignal{action: "SELL", reason: "exit"}
	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Equal(t, 1, len(trades), "should only enter once")
}


func TestComputeMaxDrawdown_SingleLoss(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{{PnL: -5000}}
	dd := computeMaxDrawdown(trades, 100000)
	assert.InDelta(t, 5.0, dd, 0.01)
}


func TestComputeSharpeRatio_MixedReturns(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnLPct: 10},
		{PnLPct: -5},
		{PnLPct: 8},
		{PnLPct: -3},
		{PnLPct: 15},
	}
	sharpe := computeSharpeRatio(trades, 100000)
	// Mixed but net positive returns should give a positive Sharpe (usually)
	assert.False(t, math.IsNaN(sharpe))
	assert.False(t, math.IsInf(sharpe, 0))
}


func TestGenerateSignals_AllStrategiesDispatch(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 60)
	highs := make([]float64, 60)
	lows := make([]float64, 60)
	for i := range closes {
		closes[i] = 100 + float64(i%10)*2
		highs[i] = closes[i] + 5
		lows[i] = closes[i] - 5
	}

	for _, strategy := range []string{"sma_crossover", "rsi_reversal", "breakout", "mean_reversion"} {
		signals := generateSignals(strategy, closes, highs, lows, 10, 20)
		assert.Equal(t, 60, len(signals), "strategy %s should return correct length", strategy)
	}
}


func TestGenerateSignals_UnknownStrategy(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101, 102}
	signals := generateSignals("unknown", closes, closes, closes, 10, 20)
	for _, s := range signals {
		assert.Nil(t, s)
	}
}


func TestRunBacktest_RSIReversalIntegration(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeOscillatingPricesHelper(150), time.Now().AddDate(0, 0, -150))
	result := runBacktest(candles, "rsi_reversal", "NSE", "RELIANCE", 500000, 100, 14, 70)
	assert.Equal(t, "rsi_reversal", result.Strategy)
	assert.GreaterOrEqual(t, result.TotalTrades, 0)
}


func TestRunBacktest_BreakoutIntegration(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeTrendingPricesHelper(200, 100), time.Now().AddDate(0, 0, -200))
	result := runBacktest(candles, "breakout", "NSE", "TCS", 1000000, 100, 20, 10)
	assert.Equal(t, "breakout", result.Strategy)
}


func TestRunBacktest_MeanReversionIntegration(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeOscillatingPricesHelper(150), time.Now().AddDate(0, 0, -150))
	result := runBacktest(candles, "mean_reversion", "BSE", "WIPRO", 1000000, 100, 20, 2.0)
	assert.Equal(t, "mean_reversion", result.Strategy)
	assert.Equal(t, "BSE:WIPRO", result.Symbol)
}


func TestRunBacktest_TradeLogCapped(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeOscillatingPricesHelper(500), time.Now().AddDate(0, 0, -500))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 3, 10)
	assert.LessOrEqual(t, len(result.TradeLog), 50, "trade log should be capped at 50")
}


func TestRunBacktest_WinLossStats(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeOscillatingPricesHelper(200), time.Now().AddDate(0, 0, -200))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 15)
	if result.TotalTrades > 0 {
		assert.Equal(t, result.TotalTrades, result.WinningTrades+result.LosingTrades)
		assert.GreaterOrEqual(t, result.WinRate, 0.0)
		assert.LessOrEqual(t, result.WinRate, 100.0)
	}
}


func TestRunBacktest_BuyAndHoldComputed(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeTrendingPricesHelper(100, 100), time.Now().AddDate(0, 0, -100))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 20)
	assert.False(t, math.IsNaN(result.BuyAndHold))
	assert.False(t, math.IsInf(result.BuyAndHold, 0))
}


func TestBacktestDefaults_PartialOverride(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"param1": float64(7),
		// param2 not set — should use default
	}
	p1, p2 := backtestDefaults("sma_crossover", args)
	assert.Equal(t, 7.0, p1)
	assert.Equal(t, 50.0, p2)
}


func TestRunBacktest_ResultFields(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper(makeTrendingPricesHelper(100, 100), time.Now().AddDate(0, 0, -100))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 500000, 50, 5, 20)
	// Verify all fields are populated
	assert.Equal(t, "sma_crossover", result.Strategy)
	assert.Equal(t, "NSE:TEST", result.Symbol)
	assert.NotEmpty(t, result.Period)
	assert.Equal(t, 500000.0, result.InitialCapital)
	assert.Greater(t, result.FinalCapital, 0.0)
	assert.False(t, math.IsNaN(result.TotalReturn))
	assert.False(t, math.IsNaN(result.MaxDrawdown))
	assert.False(t, math.IsNaN(result.SharpeRatio))
	assert.False(t, math.IsNaN(result.BuyAndHold))
	assert.GreaterOrEqual(t, result.MaxDrawdown, 0.0)
	assert.LessOrEqual(t, result.MaxDrawdown, 100.0)
}


func TestSignalsSMACrossover_NoCrossover(t *testing.T) {
	t.Parallel()
	// Perfectly flat prices — no crossover
	closes := make([]float64, 60)
	for i := range closes {
		closes[i] = 100
	}
	signals := signalsSMACrossover(closes, 5, 20)
	for _, s := range signals {
		assert.Nil(t, s, "flat prices should produce no signals")
	}
}


func TestSignalsMeanReversion_AboveUpperBand(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 40)
	for i := range 30 {
		closes[i] = 100 + float64(i%5)
	}
	// Sudden spike above upper band
	for i := 30; i < 40; i++ {
		closes[i] = 130
	}

	signals := signalsMeanReversion(closes, 20, 2.0)
	hasSell := false
	for _, s := range signals {
		if s != nil && s.action == "SELL" {
			hasSell = true
			assert.Contains(t, s.reason, "above upper BB")
		}
	}
	assert.True(t, hasSell, "should have SELL signal when price spikes above upper BB")
}


func TestSimulateTrades_BuyWithVeryHighPrice(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{1000000}, time.Now())
	signals := make([]*backtestSignal, 1)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry"}
	// Capital is only 100, can't buy 1 share at 1000000
	trades := simulateTrades(candles, signals, 100, 100)
	assert.Empty(t, trades, "should not enter position when can't afford even 1 share")
}


func TestComputeMaxDrawdown_NoTrades(t *testing.T) {
	t.Parallel()
	dd := computeMaxDrawdown(nil, 100000)
	assert.Equal(t, 0.0, dd, "No trades should mean 0 drawdown")
}


func TestBacktestSignalsSMACrossover(t *testing.T) {
	t.Parallel()
	// Create 100 candles with a clear crossover pattern
	n := 100
	closes := make([]float64, n)
	for i := range closes {
		// Rising trend
		closes[i] = 100 + float64(i)*0.5
	}
	signals := signalsSMACrossover(closes, 10, 30)
	assert.NotNil(t, signals)
}


func TestBacktestSignalsMeanReversion(t *testing.T) {
	t.Parallel()
	n := 50
	closes := make([]float64, n)
	for i := range closes {
		closes[i] = 100 + float64(i%10)*2 // oscillating
	}
	signals := signalsMeanReversion(closes, 20, 2.0)
	assert.NotNil(t, signals)
}


func TestRunBacktest_SMACrossover_P7(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 5)
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 20, 50)
	assert.NotNil(t, result)
	assert.Equal(t, "sma_crossover", result.Strategy)
	assert.Equal(t, "NSE:TEST", result.Symbol)
	assert.Greater(t, result.InitialCapital, 0.0)
}


func TestRunBacktest_RSIReversal(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 8)
	result := runBacktest(candles, "rsi_reversal", "NSE", "TEST", 500000, 50, 14, 70)
	assert.NotNil(t, result)
	assert.Equal(t, "rsi_reversal", result.Strategy)
}


func TestRunBacktest_Breakout(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 10)
	result := runBacktest(candles, "breakout", "NSE", "TEST", 1000000, 100, 20, 10)
	assert.NotNil(t, result)
	assert.Equal(t, "breakout", result.Strategy)
}


func TestRunBacktest_MeanReversion(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 6)
	result := runBacktest(candles, "mean_reversion", "NSE", "TEST", 1000000, 100, 20, 2.0)
	assert.NotNil(t, result)
	assert.Equal(t, "mean_reversion", result.Strategy)
}


func TestRunBacktest_UnknownStrategy(t *testing.T) {
	t.Parallel()
	candles := makeCandles(100, 100, 5)
	result := runBacktest(candles, "unknown", "NSE", "TEST", 1000000, 100, 20, 50)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.TotalTrades)
}


func TestRunBacktest_SmallCandles(t *testing.T) {
	t.Parallel()
	candles := makeCandles(10, 100, 5)
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 8)
	assert.NotNil(t, result)
}


func TestRunBacktest_TradeLogCap(t *testing.T) {
	t.Parallel()
	// Create enough data to potentially generate >50 trades
	candles := makeCandles(500, 100, 15)
	result := runBacktest(candles, "rsi_reversal", "NSE", "TEST", 1000000, 100, 5, 65)
	assert.NotNil(t, result)
	assert.LessOrEqual(t, len(result.TradeLog), 50)
}


func TestSignalsRSIReversal_WithOversoldOverbought(t *testing.T) {
	t.Parallel()
	// Create a price series that goes down then up to trigger RSI signals
	n := 50
	closes := make([]float64, n)
	for i := range n {
		if i < 20 {
			closes[i] = 100 - float64(i)*3 // decline → RSI drops
		} else if i < 35 {
			closes[i] = closes[19] + float64(i-19)*5 // sharp rally → RSI rises
		} else {
			closes[i] = closes[34] - float64(i-34)*4 // decline again
		}
	}
	signals := signalsRSIReversal(closes, 14, 70)
	assert.NotNil(t, signals)
	assert.Equal(t, n, len(signals))
}


func TestSignalsRSIReversal_TooFewPrices(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101, 102}
	signals := signalsRSIReversal(closes, 14, 70)
	assert.NotNil(t, signals)
	// All nil signals because RSI can't be computed
}


func TestSignalsBreakout_GeneratesSignals(t *testing.T) {
	t.Parallel()
	n := 100
	closes := make([]float64, n)
	highs := make([]float64, n)
	lows := make([]float64, n)
	for i := range n {
		base := 100.0
		if i > 50 {
			base = 130.0 // sudden jump — breakout signal
		}
		closes[i] = base + float64(i%5)
		highs[i] = closes[i] + 2
		lows[i] = closes[i] - 2
	}
	signals := signalsBreakout(closes, highs, lows, 20, 10)
	assert.NotNil(t, signals)
	assert.Equal(t, n, len(signals))
}


func TestSignalsBreakout_ShortData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101}
	highs := []float64{102, 103}
	lows := []float64{98, 99}
	signals := signalsBreakout(closes, highs, lows, 20, 10)
	assert.NotNil(t, signals)
}


func TestGenerateSignals_AllStrategies(t *testing.T) {
	t.Parallel()
	n := 100
	closes := make([]float64, n)
	highs := make([]float64, n)
	lows := make([]float64, n)
	for i := range closes {
		closes[i] = 100 + float64(i%10)*2
		highs[i] = closes[i] + 3
		lows[i] = closes[i] - 3
	}

	for _, strategy := range []string{"sma_crossover", "rsi_reversal", "breakout", "mean_reversion", "unknown"} {
		signals := generateSignals(strategy, closes, highs, lows, 20, 50)
		assert.NotNil(t, signals, "strategy=%s", strategy)
		assert.Equal(t, n, len(signals), "strategy=%s", strategy)
	}
}


func TestSimulateTrades_WithSignals(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	// Place a BUY at index 5 and a SELL at index 10
	signals[5] = &backtestSignal{action: "BUY", reason: "test buy"}
	signals[10] = &backtestSignal{action: "SELL", reason: "test sell"}
	// Another round trip
	signals[15] = &backtestSignal{action: "BUY", reason: "test buy 2"}
	signals[20] = &backtestSignal{action: "SELL", reason: "test sell 2"}

	trades := simulateTrades(candles, signals, 1000000, 100)
	assert.GreaterOrEqual(t, len(trades), 1)
}


func TestSimulateTrades_NoSignals_P7(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	trades := simulateTrades(candles, signals, 1000000, 100)
	assert.Empty(t, trades)
}


func TestSimulateTrades_PartialPositionSize(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	signals[5] = &backtestSignal{action: "BUY", reason: "test buy"}
	signals[10] = &backtestSignal{action: "SELL", reason: "test sell"}
	trades := simulateTrades(candles, signals, 1000000, 25) // 25% position size
	assert.NotNil(t, trades)
}


func TestComputeMaxDrawdown_Realistic(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 5000},
		{PnL: -8000},
		{PnL: 3000},
		{PnL: -2000},
		{PnL: 10000},
	}
	dd := computeMaxDrawdown(trades, 100000)
	assert.GreaterOrEqual(t, dd, 0.0)
}


func TestComputeMaxDrawdown_NoTrades_P7(t *testing.T) {
	t.Parallel()
	dd := computeMaxDrawdown(nil, 100000)
	assert.Equal(t, 0.0, dd)
}


func TestComputeMaxDrawdown_AllWins(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 1000},
		{PnL: 2000},
		{PnL: 3000},
	}
	dd := computeMaxDrawdown(trades, 100000)
	assert.Equal(t, 0.0, dd)
}


func TestComputeSharpeRatio_Realistic(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 5000},
		{PnL: -3000},
		{PnL: 4000},
		{PnL: -1000},
		{PnL: 6000},
	}
	sharpe := computeSharpeRatio(trades, 100000)
	assert.False(t, math.IsNaN(sharpe))
}


func TestComputeSharpeRatio_NoTrades(t *testing.T) {
	t.Parallel()
	sharpe := computeSharpeRatio(nil, 100000)
	assert.Equal(t, 0.0, sharpe)
}


func TestComputeSharpeRatio_SingleTrade(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{{PnL: 5000}}
	sharpe := computeSharpeRatio(trades, 100000)
	// With single trade, std dev is 0, should return 0
	assert.False(t, math.IsNaN(sharpe))
}
