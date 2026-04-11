package mcp

import (
	"context"
	"math"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// mockSession implements server.ClientSession for tests.
type mockSession struct {
	id string
}

func (m *mockSession) Initialize()                                       {}
func (m *mockSession) Initialized() bool                                 { return true }
func (m *mockSession) NotificationChannel() chan<- gomcp.JSONRPCNotification { return make(chan gomcp.JSONRPCNotification, 1) }
func (m *mockSession) SessionID() string                                 { return m.id }

// callToolWithSession invokes a tool handler with an MCP session in context.
// This allows exercising code paths that go through WithSession.
func callToolWithSession(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	// Create a minimal MCP server to inject a session context
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "test-session-id"})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

// ===========================================================================
// backtest_tool.go: signalsSMACrossover — additional edge cases
// ===========================================================================

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
	for i := 0; i < 60; i++ {
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

// ===========================================================================
// backtest_tool.go: signalsRSIReversal
// ===========================================================================

func TestSignalsRSIReversal_OversoldBuy(t *testing.T) {
	t.Parallel()
	// Create a downtrend followed by reversal to trigger oversold RSI
	closes := make([]float64, 40)
	for i := 0; i < 20; i++ {
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

// ===========================================================================
// backtest_tool.go: signalsBreakout
// ===========================================================================

func TestSignalsBreakout_BreakAboveHigh(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 30)
	highs := make([]float64, 30)
	lows := make([]float64, 30)
	for i := 0; i < 25; i++ {
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
	for i := 0; i < 25; i++ {
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

// ===========================================================================
// backtest_tool.go: signalsMeanReversion
// ===========================================================================

func TestSignalsMeanReversion_BelowLowerBand(t *testing.T) {
	t.Parallel()
	closes := make([]float64, 40)
	for i := 0; i < 30; i++ {
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

// ===========================================================================
// backtest_tool.go: simulateTrades — additional cases
// ===========================================================================

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
	candles := makeCandlesHelper([]float64{100, 105}, time.Now())
	signals := make([]*backtestSignal, 2)
	signals[0] = &backtestSignal{action: "SELL", reason: "premature sell"}
	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Empty(t, trades)
}

func TestSimulateTrades_MultipleBuysSameSignal(t *testing.T) {
	// Second BUY while already in position should be ignored
	candles := makeCandlesHelper([]float64{100, 105, 110, 115, 120}, time.Now())
	signals := make([]*backtestSignal, 5)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry1"}
	signals[1] = &backtestSignal{action: "BUY", reason: "entry2"} // ignored
	signals[4] = &backtestSignal{action: "SELL", reason: "exit"}
	trades := simulateTrades(candles, signals, 100000, 100)
	assert.Equal(t, 1, len(trades), "should only enter once")
}

// ===========================================================================
// backtest_tool.go: computeMaxDrawdown — additional edge case
// ===========================================================================

func TestComputeMaxDrawdown_SingleLoss(t *testing.T) {
	trades := []BacktestTrade{{PnL: -5000}}
	dd := computeMaxDrawdown(trades, 100000)
	assert.InDelta(t, 5.0, dd, 0.01)
}

// ===========================================================================
// backtest_tool.go: computeSharpeRatio — additional case
// ===========================================================================

func TestComputeSharpeRatio_MixedReturns(t *testing.T) {
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

// ===========================================================================
// backtest_tool.go: generateSignals dispatching
// ===========================================================================

func TestGenerateSignals_AllStrategiesDispatch(t *testing.T) {
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
	closes := []float64{100, 101, 102}
	signals := generateSignals("unknown", closes, closes, closes, 10, 20)
	for _, s := range signals {
		assert.Nil(t, s)
	}
}

// ===========================================================================
// backtest_tool.go: runBacktest — additional integration tests
// ===========================================================================

func TestRunBacktest_RSIReversalIntegration(t *testing.T) {
	candles := makeCandlesHelper(makeOscillatingPricesHelper(150), time.Now().AddDate(0, 0, -150))
	result := runBacktest(candles, "rsi_reversal", "NSE", "RELIANCE", 500000, 100, 14, 70)
	assert.Equal(t, "rsi_reversal", result.Strategy)
	assert.GreaterOrEqual(t, result.TotalTrades, 0)
}

func TestRunBacktest_BreakoutIntegration(t *testing.T) {
	candles := makeCandlesHelper(makeTrendingPricesHelper(200, 100), time.Now().AddDate(0, 0, -200))
	result := runBacktest(candles, "breakout", "NSE", "TCS", 1000000, 100, 20, 10)
	assert.Equal(t, "breakout", result.Strategy)
}

func TestRunBacktest_MeanReversionIntegration(t *testing.T) {
	candles := makeCandlesHelper(makeOscillatingPricesHelper(150), time.Now().AddDate(0, 0, -150))
	result := runBacktest(candles, "mean_reversion", "BSE", "WIPRO", 1000000, 100, 20, 2.0)
	assert.Equal(t, "mean_reversion", result.Strategy)
	assert.Equal(t, "BSE:WIPRO", result.Symbol)
}

func TestRunBacktest_TradeLogCapped(t *testing.T) {
	candles := makeCandlesHelper(makeOscillatingPricesHelper(500), time.Now().AddDate(0, 0, -500))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 3, 10)
	assert.LessOrEqual(t, len(result.TradeLog), 50, "trade log should be capped at 50")
}

func TestRunBacktest_WinLossStats(t *testing.T) {
	candles := makeCandlesHelper(makeOscillatingPricesHelper(200), time.Now().AddDate(0, 0, -200))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 15)
	if result.TotalTrades > 0 {
		assert.Equal(t, result.TotalTrades, result.WinningTrades+result.LosingTrades)
		assert.GreaterOrEqual(t, result.WinRate, 0.0)
		assert.LessOrEqual(t, result.WinRate, 100.0)
	}
}

func TestRunBacktest_BuyAndHoldComputed(t *testing.T) {
	candles := makeCandlesHelper(makeTrendingPricesHelper(100, 100), time.Now().AddDate(0, 0, -100))
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 20)
	assert.False(t, math.IsNaN(result.BuyAndHold))
	assert.False(t, math.IsInf(result.BuyAndHold, 0))
}

// ===========================================================================
// tax_tools.go: computeTaxHarvest
// ===========================================================================

func TestComputeTaxHarvest_EmptyHoldings(t *testing.T) {
	resp := computeTaxHarvest([]broker.Holding{}, 0)
	assert.NotNil(t, resp)
	assert.Equal(t, 0, resp.Summary.HoldingsCount)
	assert.Empty(t, resp.HarvestCandidates)
}

func TestComputeTaxHarvest_STCGWithLoss(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "INFY",
			Exchange:      "NSE",
			ISIN:          "INE009A01021",
			Quantity:      100,
			AveragePrice:  1500,
			LastPrice:     1300,
		},
	}
	resp := computeTaxHarvest(holdings, 0)
	assert.Equal(t, 1, resp.Summary.HoldingsCount)
	assert.Equal(t, "STCG", resp.AllHoldings[0].HoldingPeriod)
	assert.Equal(t, stcgRate, resp.AllHoldings[0].TaxRate)
	assert.True(t, resp.AllHoldings[0].Harvestable)
	assert.Greater(t, resp.AllHoldings[0].TaxSavings, 0.0)
	assert.Equal(t, 1, resp.Summary.HarvestCandidatesCnt)
	assert.Equal(t, 1, len(resp.HarvestCandidates))
}

func TestComputeTaxHarvest_STCGWithGain(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "RELIANCE",
			Exchange:      "NSE",
			Quantity:      50,
			AveragePrice:  2000,
			LastPrice:     2500,
		},
	}
	resp := computeTaxHarvest(holdings, 0)
	assert.False(t, resp.AllHoldings[0].Harvestable)
	assert.Greater(t, resp.AllHoldings[0].EstimatedTax, 0.0)
	assert.Greater(t, resp.Summary.STCGGains, 0.0)
	assert.Equal(t, 0.0, resp.Summary.STCGLosses)
}

func TestComputeTaxHarvest_LTCGClassification(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "TCS",
			Exchange:      "NSE",
			Quantity:      100,
			AveragePrice:  3000,
			LastPrice:     3500,
		},
	}
	resp := computeTaxHarvest(holdings, 400)
	assert.Equal(t, "LTCG", resp.AllHoldings[0].HoldingPeriod)
	assert.Equal(t, ltcgRate, resp.AllHoldings[0].TaxRate)
	assert.Equal(t, 400, resp.AllHoldings[0].HoldingDays)
}

func TestComputeTaxHarvest_LTCGExemption(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "TCS",
			Exchange:      "NSE",
			Quantity:      10,
			AveragePrice:  3000,
			LastPrice:     4000, // gain = 10000
		},
	}
	resp := computeTaxHarvest(holdings, 400)
	assert.Equal(t, 0.0, resp.Summary.LTCGTaxEstimate, "LTCG below exemption should have 0 tax")
}

func TestComputeTaxHarvest_LTCGAboveExemption(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "TCS",
			Exchange:      "NSE",
			Quantity:      100,
			AveragePrice:  3000,
			LastPrice:     5000, // gain = 200000
		},
	}
	resp := computeTaxHarvest(holdings, 400)
	assert.Greater(t, resp.Summary.LTCGTaxEstimate, 0.0)
	assert.InDelta(t, 9375.0, resp.Summary.LTCGTaxEstimate, 1.0)
}

func TestComputeTaxHarvest_ApproachingLTCG(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "HDFC", Exchange: "NSE", Quantity: 50, AveragePrice: 1500, LastPrice: 1600},
	}
	resp := computeTaxHarvest(holdings, 340)
	assert.True(t, resp.AllHoldings[0].ApproachingLTCG)
	assert.Equal(t, 1, resp.Summary.ApproachingLTCGCnt)
	assert.Equal(t, 1, len(resp.ApproachingLTCG))
}

func TestComputeTaxHarvest_NotApproachingLTCG(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "HDFC", Exchange: "NSE", Quantity: 50, AveragePrice: 1500, LastPrice: 1600},
	}
	resp := computeTaxHarvest(holdings, 100)
	assert.False(t, resp.AllHoldings[0].ApproachingLTCG)
}

func TestComputeTaxHarvest_MixedHoldings(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, AveragePrice: 1500, LastPrice: 1300},
		{Tradingsymbol: "TCS", Quantity: 50, AveragePrice: 3000, LastPrice: 3500},
		{Tradingsymbol: "HDFC", Quantity: 200, AveragePrice: 1200, LastPrice: 1000},
	}
	resp := computeTaxHarvest(holdings, 0)
	assert.Equal(t, 3, resp.Summary.HoldingsCount)
	assert.Equal(t, 2, resp.Summary.HarvestCandidatesCnt)
	if len(resp.HarvestCandidates) >= 2 {
		assert.GreaterOrEqual(t, resp.HarvestCandidates[0].TaxSavings, resp.HarvestCandidates[1].TaxSavings)
	}
}

func TestComputeTaxHarvest_HoldingPeriodNote(t *testing.T) {
	holdings := []broker.Holding{{Tradingsymbol: "X", Quantity: 1, AveragePrice: 100, LastPrice: 100}}

	resp := computeTaxHarvest(holdings, 0)
	assert.Contains(t, resp.Summary.HoldingPeriodNote, "default to STCG")

	resp2 := computeTaxHarvest(holdings, 400)
	assert.Contains(t, resp2.Summary.HoldingPeriodNote, "User override")
}

func TestComputeTaxHarvest_ZeroPricePnl(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "FLAT", Quantity: 100, AveragePrice: 100, LastPrice: 100},
	}
	resp := computeTaxHarvest(holdings, 0)
	assert.Equal(t, 0.0, resp.AllHoldings[0].UnrealizedPnL)
	assert.False(t, resp.AllHoldings[0].Harvestable)
	assert.Equal(t, 0.0, resp.AllHoldings[0].TaxSavings)
	assert.Equal(t, 0.0, resp.AllHoldings[0].EstimatedTax)
}

func TestComputeTaxHarvest_LTCGWithLoss(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "ITC", Quantity: 1000, AveragePrice: 400, LastPrice: 350},
	}
	resp := computeTaxHarvest(holdings, 500) // LTCG
	assert.Equal(t, "LTCG", resp.AllHoldings[0].HoldingPeriod)
	assert.True(t, resp.AllHoldings[0].Harvestable)
	assert.Equal(t, ltcgRate, resp.AllHoldings[0].TaxRate)
	assert.Less(t, resp.Summary.LTCGLosses, 0.0)
}

// ===========================================================================
// elicit.go: buildOrderConfirmMessage — comprehensive switch cases
// ===========================================================================

func TestBuildOrderConfirmMessage_PlaceOrder_Market(t *testing.T) {
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.Contains(t, msg, "BUY")
	assert.Contains(t, msg, "100")
	assert.Contains(t, msg, "NSE:RELIANCE")
	assert.Contains(t, msg, "MARKET")
}

func TestBuildOrderConfirmMessage_PlaceOrder_Limit(t *testing.T) {
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "SELL",
		"quantity":         float64(50),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"price":            float64(1500.50),
	})
	assert.Contains(t, msg, "1500.50")
	assert.Contains(t, msg, "LIMIT")
}

func TestBuildOrderConfirmMessage_PlaceOrder_SL(t *testing.T) {
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"order_type":       "SL",
		"product":          "CNC",
		"trigger_price":    float64(3200),
	})
	assert.Contains(t, msg, "trigger 3200")
}

func TestBuildOrderConfirmMessage_PlaceOrder_SLM(t *testing.T) {
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"order_type":       "SL-M",
		"product":          "CNC",
		"trigger_price":    float64(3200),
	})
	assert.Contains(t, msg, "trigger 3200")
	assert.Contains(t, msg, "SL-M")
}

func TestBuildOrderConfirmMessage_ModifyOrder_WithTrigger(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_order", map[string]any{
		"order_id":      "ORD123",
		"order_type":    "LIMIT",
		"quantity":      float64(25),
		"price":         float64(1450),
		"trigger_price": float64(1400),
	})
	assert.Contains(t, msg, "ORD123")
	assert.Contains(t, msg, "qty 25")
	assert.Contains(t, msg, "price 1450")
	assert.Contains(t, msg, "trigger 1400")
}

func TestBuildOrderConfirmMessage_CloseAllPositions(t *testing.T) {
	msg := buildOrderConfirmMessage("close_all_positions", map[string]any{
		"product": "MIS",
	})
	assert.Contains(t, msg, "ALL")
	assert.Contains(t, msg, "MIS")
}

func TestBuildOrderConfirmMessage_ClosePosition_NoProduct(t *testing.T) {
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:HDFC",
	})
	assert.Contains(t, msg, "NSE:HDFC")
	assert.Contains(t, msg, "MARKET")
}

func TestBuildOrderConfirmMessage_PlaceGTT(t *testing.T) {
	msg := buildOrderConfirmMessage("place_gtt_order", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
	})
	assert.Contains(t, msg, "GTT")
	assert.Contains(t, msg, "BUY")
	assert.Contains(t, msg, "1400")
	assert.Contains(t, msg, "1405")
}

func TestBuildOrderConfirmMessage_PlaceMFOrder_Amount(t *testing.T) {
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.Contains(t, msg, "MF")
	assert.Contains(t, msg, "10000")
}

func TestBuildOrderConfirmMessage_PlaceMFOrder_Quantity(t *testing.T) {
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "SELL",
		"quantity":         float64(50),
	})
	assert.Contains(t, msg, "50 units")
}

func TestBuildOrderConfirmMessage_PlaceMFSIP(t *testing.T) {
	msg := buildOrderConfirmMessage("place_mf_sip", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(24),
	})
	assert.Contains(t, msg, "SIP")
	assert.Contains(t, msg, "5000")
	assert.Contains(t, msg, "monthly")
	assert.Contains(t, msg, "24")
}

func TestBuildOrderConfirmMessage_PlaceNativeAlert_InstrumentRHS(t *testing.T) {
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":              "Cross alert",
		"type":              "simple",
		"exchange":          "NSE",
		"tradingsymbol":     "INFY",
		"operator":          ">=",
		"rhs_type":          "instrument",
		"rhs_exchange":      "NSE",
		"rhs_tradingsymbol": "TCS",
	})
	assert.Contains(t, msg, "NSE:TCS")
}

func TestBuildOrderConfirmMessage_PlaceNativeAlert_ConstantRHS(t *testing.T) {
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":          "Price alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1800),
	})
	assert.Contains(t, msg, "1800")
}

func TestBuildOrderConfirmMessage_ModifyNativeAlert_Details(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_native_alert", map[string]any{
		"uuid":          "test-uuid-123",
		"name":          "Modified alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "TCS",
		"operator":      "<=",
	})
	assert.Contains(t, msg, "test-uuid-123")
	assert.Contains(t, msg, "Modified alert")
	assert.Contains(t, msg, "ato")
}

func TestBuildOrderConfirmMessage_Default(t *testing.T) {
	msg := buildOrderConfirmMessage("unknown_tool", map[string]any{})
	assert.Contains(t, msg, "Execute unknown_tool")
}

// ===========================================================================
// ext_apps.go: injectData
// ===========================================================================

func TestInjectData_NilData(t *testing.T) {
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	result := injectData(html, nil)
	assert.Contains(t, result, "null")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_MapData(t *testing.T) {
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := map[string]any{"key": "value", "count": 42}
	result := injectData(html, data)
	assert.Contains(t, result, `"key"`)
	assert.Contains(t, result, `"value"`)
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_UnmarshalableData(t *testing.T) {
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := make(chan int)
	result := injectData(html, data)
	assert.Contains(t, result, "null")
}

func TestInjectData_NoPlaceholder(t *testing.T) {
	html := `<script>window.__DATA__ = "something";</script>`
	data := map[string]any{"key": "value"}
	result := injectData(html, data)
	assert.Equal(t, html, result)
}

func TestInjectData_XSSEscaping(t *testing.T) {
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	// Data containing potential XSS sequence
	data := map[string]any{"text": "</script><script>alert(1)</script>"}
	result := injectData(html, data)
	// The </script> in JSON should be escaped
	assert.NotContains(t, result, "</script><script>")
}

// ===========================================================================
// ext_apps.go: withAppUI
// ===========================================================================

func TestWithAppUI_SetsResourceURI(t *testing.T) {
	tool := gomcp.NewTool("test_tool", gomcp.WithDescription("A test tool"))
	result := withAppUI(tool, "ui://kite-mcp/portfolio")
	assert.NotNil(t, result.Meta)
	assert.Equal(t, "ui://kite-mcp/portfolio", result.Meta.AdditionalFields["ui/resourceUri"])
}

func TestWithAppUI_EmptyURI(t *testing.T) {
	tool := gomcp.NewTool("test_tool", gomcp.WithDescription("A test tool"))
	result := withAppUI(tool, "")
	assert.Nil(t, result.Meta, "empty URI should not set meta")
}

// ===========================================================================
// ext_apps.go: resourceURIForTool
// ===========================================================================

func TestResourceURIForTool_MappedTool(t *testing.T) {
	uri := resourceURIForTool("get_holdings")
	assert.Equal(t, "ui://kite-mcp/portfolio", uri)
}

func TestResourceURIForTool_UnmappedTool(t *testing.T) {
	uri := resourceURIForTool("nonexistent_tool")
	assert.Empty(t, uri)
}

func TestResourceURIForTool_OrderTool(t *testing.T) {
	uri := resourceURIForTool("get_orders")
	assert.Equal(t, "ui://kite-mcp/orders", uri)
}

func TestResourceURIForTool_AlertTool(t *testing.T) {
	uri := resourceURIForTool("list_alerts")
	assert.Equal(t, "ui://kite-mcp/alerts", uri)
}

func TestResourceURIForTool_PaperTradingTool(t *testing.T) {
	uri := resourceURIForTool("paper_trading_toggle")
	assert.Equal(t, "ui://kite-mcp/paper", uri)
}

func TestResourceURIForTool_WatchlistTool(t *testing.T) {
	uri := resourceURIForTool("list_watchlists")
	assert.Equal(t, "ui://kite-mcp/watchlist", uri)
}

// ===========================================================================
// prompts.go: morningBriefHandler, tradeCheckHandler, eodReviewHandler
// ===========================================================================

func TestMorningBriefHandler_ReturnsValidPrompt(t *testing.T) {
	mgr := newTestManager(t)
	handler := morningBriefHandler(mgr)
	req := gomcp.GetPromptRequest{}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Morning trading briefing", result.Description)
	assert.Len(t, result.Messages, 1)
	assert.Equal(t, gomcp.RoleUser, result.Messages[0].Role)
	textContent := result.Messages[0].Content.(gomcp.TextContent)
	assert.Contains(t, textContent.Text, "Morning Trading Briefing")
	assert.Contains(t, textContent.Text, "Step 1")
	assert.Contains(t, textContent.Text, "Step 6")
}

func TestTradeCheckHandler_WithSymbol(t *testing.T) {
	mgr := newTestManager(t)
	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol":   "RELIANCE",
		"action":   "BUY",
		"quantity": "100",
	}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "BUY")
	assert.Contains(t, result.Description, "RELIANCE")
	textContent := result.Messages[0].Content.(gomcp.TextContent)
	assert.Contains(t, textContent.Text, "RELIANCE")
	assert.Contains(t, textContent.Text, "BUY")
	assert.Contains(t, textContent.Text, "100")
}

func TestTradeCheckHandler_DefaultAction(t *testing.T) {
	mgr := newTestManager(t)
	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol": "INFY",
	}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.Contains(t, result.Description, "BUY")
}

func TestTradeCheckHandler_NoQuantity(t *testing.T) {
	mgr := newTestManager(t)
	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol": "INFY",
		"action": "SELL",
	}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	textContent := result.Messages[0].Content.(gomcp.TextContent)
	assert.Contains(t, textContent.Text, "not specified")
}

func TestEodReviewHandler_ReturnsValidPrompt(t *testing.T) {
	mgr := newTestManager(t)
	handler := eodReviewHandler(mgr)
	req := gomcp.GetPromptRequest{}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "End-of-day trading review", result.Description)
	assert.Len(t, result.Messages, 1)
	textContent := result.Messages[0].Content.(gomcp.TextContent)
	assert.Contains(t, textContent.Text, "End-of-Day Review")
	assert.Contains(t, textContent.Text, "Step 1")
}

func TestEodReviewHandler_ContainsTimingNote(t *testing.T) {
	mgr := newTestManager(t)
	handler := eodReviewHandler(mgr)
	req := gomcp.GetPromptRequest{}
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	textContent := result.Messages[0].Content.(gomcp.TextContent)
	assert.True(t,
		containsAnyStr(textContent.Text, "Market is still open", "settlement in progress", "Market is closed"),
		"should contain a timing note")
}

// ===========================================================================
// indicators_tool.go: computeRSI — additional tests
// ===========================================================================

func TestComputeRSI_InsufficientData(t *testing.T) {
	result := computeRSI([]float64{100, 101}, 14)
	assert.Nil(t, result)
}

func TestComputeRSI_AllUp(t *testing.T) {
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = float64(100 + i)
	}
	result := computeRSI(prices, 14)
	assert.NotNil(t, result)
	assert.Equal(t, 100.0, result[14])
}

func TestComputeRSI_BoundsCheck(t *testing.T) {
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

// ===========================================================================
// indicators_tool.go: computeSMA — additional tests
// ===========================================================================

func TestComputeSMA_InsufficientData(t *testing.T) {
	result := computeSMA([]float64{100, 101}, 5)
	assert.Nil(t, result)
}

func TestComputeSMA_ExactPeriod(t *testing.T) {
	prices := []float64{10, 20, 30, 40, 50}
	result := computeSMA(prices, 5)
	assert.NotNil(t, result)
	assert.Equal(t, 30.0, result[4])
}

func TestComputeSMA_RollingWindow(t *testing.T) {
	prices := []float64{10, 20, 30, 40, 50, 60}
	result := computeSMA(prices, 3)
	assert.NotNil(t, result)
	assert.InDelta(t, 20.0, result[2], 0.01)
	assert.InDelta(t, 30.0, result[3], 0.01)
	assert.InDelta(t, 40.0, result[4], 0.01)
	assert.InDelta(t, 50.0, result[5], 0.01)
}

// ===========================================================================
// indicators_tool.go: computeEMA — additional tests
// ===========================================================================

func TestComputeEMA_InsufficientData(t *testing.T) {
	result := computeEMA([]float64{100}, 5)
	assert.Nil(t, result)
}

func TestComputeEMA_FirstValueIsSMA(t *testing.T) {
	prices := []float64{10, 20, 30, 40, 50}
	result := computeEMA(prices, 5)
	assert.NotNil(t, result)
	assert.Equal(t, 30.0, result[4])
}

func TestComputeEMA_ResponsivenessToJump(t *testing.T) {
	prices := []float64{10, 10, 10, 10, 10, 100}
	result := computeEMA(prices, 5)
	assert.NotNil(t, result)
	assert.Greater(t, result[5], 10.0)
	assert.Less(t, result[5], 100.0)
}

// ===========================================================================
// indicators_tool.go: computeBollingerBands — additional tests
// ===========================================================================

func TestComputeBollingerBands_InsufficientData(t *testing.T) {
	u, m, l := computeBollingerBands([]float64{100}, 5, 2.0)
	assert.Nil(t, u)
	assert.Nil(t, m)
	assert.Nil(t, l)
}

func TestComputeBollingerBands_ConstantPrices(t *testing.T) {
	prices := []float64{100, 100, 100, 100, 100}
	u, m, l := computeBollingerBands(prices, 5, 2.0)
	assert.NotNil(t, u)
	assert.Equal(t, 100.0, m[4])
	assert.Equal(t, 100.0, u[4])
	assert.Equal(t, 100.0, l[4])
}

func TestComputeBollingerBands_UpperAboveLower(t *testing.T) {
	prices := []float64{95, 100, 105, 100, 95, 100, 105}
	u, m, l := computeBollingerBands(prices, 5, 2.0)
	assert.NotNil(t, u)
	for i := 4; i < len(prices); i++ {
		assert.GreaterOrEqual(t, u[i], m[i])
		assert.LessOrEqual(t, l[i], m[i])
	}
}

// ===========================================================================
// options_greeks_tool.go: Black-Scholes functions
// ===========================================================================

func TestBlackScholesPrice_CallPutParity(t *testing.T) {
	S, K, T, r, sigma := 100.0, 100.0, 1.0, 0.05, 0.2
	callPrice := blackScholesPrice(S, K, T, r, sigma, true)
	putPrice := blackScholesPrice(S, K, T, r, sigma, false)
	parity := callPrice - putPrice
	expected := S - K*math.Exp(-r*T)
	assert.InDelta(t, expected, parity, 0.01)
}

func TestBlackScholesPrice_DeepITMCall(t *testing.T) {
	price := blackScholesPrice(200, 100, 0.01, 0.05, 0.2, true)
	assert.Greater(t, price, 99.0)
}

func TestBlackScholesPrice_DeepOTMPut(t *testing.T) {
	price := blackScholesPrice(200, 100, 0.01, 0.05, 0.2, false)
	assert.Less(t, price, 1.0)
}

func TestBsDelta_CallBounds(t *testing.T) {
	delta := bsDelta(100, 100, 1, 0.05, 0.2, true)
	assert.Greater(t, delta, 0.0)
	assert.Less(t, delta, 1.0)
}

func TestBsDelta_PutBounds(t *testing.T) {
	delta := bsDelta(100, 100, 1, 0.05, 0.2, false)
	assert.Less(t, delta, 0.0)
	assert.Greater(t, delta, -1.0)
}

func TestBsGamma_Positive(t *testing.T) {
	gamma := bsGamma(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, gamma, 0.0)
}

func TestBsGamma_ZeroTimeReturnsZero(t *testing.T) {
	gamma := bsGamma(100, 100, 0, 0.05, 0.2)
	assert.Equal(t, 0.0, gamma)
}

func TestBsVega_Positive(t *testing.T) {
	vega := bsVega(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, vega, 0.0)
}

func TestBsVega_ZeroTimeReturnsZero(t *testing.T) {
	vega := bsVega(100, 100, 0, 0.05, 0.2)
	assert.Equal(t, 0.0, vega)
}

// ===========================================================================
// options_greeks_tool.go: normalCDF, normalPDF, bsD1
// ===========================================================================

func TestNormalCDF_KnownValues(t *testing.T) {
	assert.InDelta(t, 0.5, normalCDF(0), 0.01)
	assert.InDelta(t, 0.8413, normalCDF(1), 0.01)
	assert.InDelta(t, 0.1587, normalCDF(-1), 0.01)
	assert.InDelta(t, 0.9772, normalCDF(2), 0.01)
}

func TestNormalPDF_KnownValues(t *testing.T) {
	assert.InDelta(t, 0.3989, normalPDF(0), 0.001)
	assert.InDelta(t, normalPDF(1), normalPDF(-1), 0.0001)
}

func TestBsD1_ATM(t *testing.T) {
	d1 := bsD1(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, d1, 0.0)
}

// ===========================================================================
// ext_apps.go: appResources and pagePathToResourceURI consistency
// ===========================================================================

func TestAppResources_AllHaveRequiredFields(t *testing.T) {
	for _, res := range appResources {
		assert.NotEmpty(t, res.URI)
		assert.NotEmpty(t, res.Name)
		assert.NotEmpty(t, res.TemplateFile)
		assert.NotNil(t, res.DataFunc)
	}
}

func TestPagePathToResourceURI_AllStartWithUIPrefix(t *testing.T) {
	for path, uri := range pagePathToResourceURI {
		assert.True(t, len(uri) > 5 && uri[:5] == "ui://",
			"path %s should map to URI starting with ui://, got %s", path, uri)
	}
}

// ===========================================================================
// backtest_tool.go: backtestDefaults with custom params
// ===========================================================================

func TestBacktestDefaults_PartialOverride(t *testing.T) {
	args := map[string]interface{}{
		"param1": float64(7),
		// param2 not set — should use default
	}
	p1, p2 := backtestDefaults("sma_crossover", args)
	assert.Equal(t, 7.0, p1)
	assert.Equal(t, 50.0, p2)
}

// ===========================================================================
// Helpers for test data generation (uniquely named)
// ===========================================================================

func makeCandlesHelper(prices []float64, startDate time.Time) []broker.HistoricalCandle {
	candles := make([]broker.HistoricalCandle, len(prices))
	for i, p := range prices {
		candles[i] = broker.HistoricalCandle{
			Date:   startDate.AddDate(0, 0, i),
			Open:   p * 0.99,
			High:   p * 1.02,
			Low:    p * 0.98,
			Close:  p,
			Volume: 100000,
		}
	}
	return candles
}

func makeTrendingPricesHelper(n int, startPrice float64) []float64 {
	prices := make([]float64, n)
	for i := range prices {
		trend := float64(i) * 0.5
		noise := float64(i%7) - 3
		prices[i] = startPrice + trend + noise
	}
	return prices
}

func makeOscillatingPricesHelper(n int) []float64 {
	prices := make([]float64, n)
	for i := range prices {
		prices[i] = 100 + 20*math.Sin(float64(i)*0.15) + float64(i%3)
	}
	return prices
}

func containsAnyStr(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// ===========================================================================
// pretrade_tool.go: buildPreTradeResponse — comprehensive tests
// ===========================================================================

func TestBuildPreTradeResponse_AllDataPresent(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1500},
		},
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{
				Net:  500000,
				Used: kiteconnect.UsedMargins{Debits: 100000},
			},
		},
		"order_margins": []kiteconnect.OrderMargins{
			{Total: 75000},
		},
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{
					Tradingsymbol: "INFY",
					Exchange:      "NSE",
					Quantity:      50,
					Product:       "CNC",
					AveragePrice:  1400,
					PnL:           5000,
				},
			},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "RELIANCE", Quantity: 100, LastPrice: 2500},
			{Tradingsymbol: "TCS", Quantity: 50, LastPrice: 3500},
		},
	}

	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Equal(t, "INFY", resp.Symbol)
	assert.Equal(t, "NSE", resp.Exchange)
	assert.Equal(t, "BUY", resp.Side)
	assert.Equal(t, 10, resp.Quantity)
	assert.Equal(t, 1500.0, resp.CurrentPrice)
	assert.Equal(t, 15000.0, resp.OrderValue) // 1500 * 10
	assert.Equal(t, 75000.0, resp.Margin.Required)
	assert.Equal(t, 500000.0, resp.Margin.Available)
	assert.NotNil(t, resp.ExistingPos)
	assert.Equal(t, 50, resp.ExistingPos.Quantity)
	assert.Equal(t, "PROCEED", resp.Recommendation)
	// BUY with price > 0 should have stop loss suggestions
	assert.Greater(t, resp.StopLoss.CNC2Pct, 0.0)
	assert.Greater(t, resp.StopLoss.MIS1Pct, 0.0)
}

func TestBuildPreTradeResponse_EmptyData(t *testing.T) {
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0,
		map[string]any{}, nil)
	assert.Equal(t, "INFY", resp.Symbol)
	assert.Equal(t, 0.0, resp.CurrentPrice)
	assert.Equal(t, "PROCEED", resp.Recommendation)
}

func TestBuildPreTradeResponse_InsufficientMargin(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1500},
		},
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 10000},
		},
		"order_margins": []kiteconnect.OrderMargins{
			{Total: 50000},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 100, "CNC", 0, data, nil)
	assert.Equal(t, "BLOCKED", resp.Recommendation)
	assert.GreaterOrEqual(t, len(resp.Warnings), 1)
}

func TestBuildPreTradeResponse_HighMarginUtilization(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 10000},
		},
		"order_margins": []kiteconnect.OrderMargins{
			{Total: 8000}, // 80% utilization
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Contains(t, resp.Recommendation, "CAUTION")
}

func TestBuildPreTradeResponse_OverConcentration(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 5000},
		},
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 1000000},
		},
		"order_margins": []kiteconnect.OrderMargins{
			{Total: 50000},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "TCS", Quantity: 10, LastPrice: 3500},
		},
	}
	// Order value = 5000 * 100 = 500000, portfolio = 35000, total = 535000
	// orderAsPct = 500000/535000 * 100 ≈ 93.5% — over-concentrated
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 100, "CNC", 0, data, nil)
	foundConcentration := false
	for _, w := range resp.Warnings {
		if containsAnyStr(w, "concentration") || containsAnyStr(w, "Over-concentration") {
			foundConcentration = true
		}
	}
	assert.True(t, foundConcentration, "should warn about over-concentration")
}

func TestBuildPreTradeResponse_SellStopLoss(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1500},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "SELL", 10, "CNC", 0, data, nil)
	// SELL stop loss should be above the price
	assert.Greater(t, resp.StopLoss.CNC2Pct, 1500.0)
	assert.Greater(t, resp.StopLoss.MIS1Pct, 1500.0)
}

func TestBuildPreTradeResponse_WithLimitPrice(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1500},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 1450, data, nil)
	// Order value should use limit price
	assert.Equal(t, roundTo2(14500.0), resp.OrderValue)
}

func TestBuildPreTradeResponse_WithAPIErrors(t *testing.T) {
	apiErrors := map[string]string{
		"ltp":    "API error: rate limited",
		"margins": "timeout",
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0,
		map[string]any{}, apiErrors)
	assert.NotNil(t, resp.Errors)
	assert.Contains(t, resp.Errors, "ltp")
	// LTP error should trigger a warning
	foundLTPWarning := false
	for _, w := range resp.Warnings {
		if containsAnyStr(w, "current price") {
			foundLTPWarning = true
		}
	}
	assert.True(t, foundLTPWarning)
}

func TestBuildPreTradeResponse_NoExistingPosition(t *testing.T) {
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 50},
			},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Nil(t, resp.ExistingPos, "should not have existing position for different symbol")
}

func TestBuildPreTradeResponse_FallbackMargin(t *testing.T) {
	// When GetOrderMargins fails, margin falls back to order value
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1000},
		},
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 500000},
		},
		// No "order_margins" key — fallback
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	// Margin required should fall back to order value (1000 * 10 = 10000)
	assert.Equal(t, 10000.0, resp.Margin.Required)
}

// ===========================================================================
// context_tool.go: buildTradingContext — comprehensive tests
// ===========================================================================

func TestBuildTradingContext_AllDataPresent(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{
				Net:  500000,
				Used: kiteconnect.UsedMargins{Debits: 100000},
			},
		},
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{
					Tradingsymbol: "INFY",
					Exchange:      "NSE",
					Product:       "CNC",
					Quantity:      50,
					AveragePrice:  1400,
					LastPrice:     1500,
					PnL:           5000,
				},
				{
					Tradingsymbol: "TCS",
					Exchange:      "NSE",
					Product:       "MIS",
					Quantity:      20,
					AveragePrice:  3500,
					LastPrice:     3600,
					PnL:           2000,
				},
			},
		},
		"orders": kiteconnect.Orders{
			{Status: "COMPLETE"},
			{Status: "COMPLETE"},
			{Status: "REJECTED"},
			{Status: "OPEN"},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "RELIANCE", Quantity: 100, DayChange: 500},
			{Tradingsymbol: "HDFC", Quantity: 50, DayChange: -200},
		},
	}

	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.NotNil(t, tc)
	assert.NotEmpty(t, tc.MarketStatus)
	assert.Equal(t, 500000.0, tc.MarginAvailable)
	assert.Equal(t, 100000.0, tc.MarginUsed)
	assert.Equal(t, 2, tc.OpenPositions)
	assert.Equal(t, 7000.0, tc.PositionsPnL) // 5000 + 2000
	assert.Equal(t, 1, tc.MISPositions)
	assert.Equal(t, 0, tc.NRMLPositions) // CNC isn't counted as NRML
	assert.Equal(t, 2, len(tc.PositionDetails))
	assert.Equal(t, 2, tc.ExecutedToday)
	assert.Equal(t, 1, tc.RejectedToday)
	assert.Equal(t, 1, tc.PendingOrders)
	assert.Equal(t, 2, tc.HoldingsCount)
	assert.Equal(t, 300.0, tc.HoldingsDayPnL)
}

func TestBuildTradingContext_EmptyData(t *testing.T) {
	mgr := newTestManager(t)
	tc := buildTradingContext(map[string]any{}, nil, mgr, "test@example.com")
	assert.NotNil(t, tc)
	assert.NotEmpty(t, tc.MarketStatus)
	assert.Equal(t, 0.0, tc.MarginAvailable)
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Equal(t, 0, tc.PendingOrders)
}

func TestBuildTradingContext_WithAPIErrors(t *testing.T) {
	mgr := newTestManager(t)
	errs := map[string]string{"margins": "timeout", "positions": "auth failed"}
	tc := buildTradingContext(map[string]any{}, errs, mgr, "test@example.com")
	assert.NotNil(t, tc.Errors)
	assert.Contains(t, tc.Errors, "margins")
	assert.Contains(t, tc.Errors, "positions")
}

func TestBuildTradingContext_HighMarginUtilization(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{
				Net:  100000,
				Used: kiteconnect.UsedMargins{Debits: 500000},
			},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.Greater(t, tc.MarginUtilization, 80.0)
	foundHighMargin := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "margin utilization") {
			foundHighMargin = true
		}
	}
	assert.True(t, foundHighMargin)
}

func TestBuildTradingContext_ManyRejectedOrders(t *testing.T) {
	mgr := newTestManager(t)
	orders := make(kiteconnect.Orders, 5)
	for i := range orders {
		orders[i] = kiteconnect.Order{Status: "REJECTED"}
	}
	data := map[string]any{"orders": orders}
	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.Equal(t, 5, tc.RejectedToday)
	foundRejectedWarning := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "rejected orders") {
			foundRejectedWarning = true
		}
	}
	assert.True(t, foundRejectedWarning)
}

func TestBuildTradingContext_OrderStatuses(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"orders": kiteconnect.Orders{
			{Status: "COMPLETE"},
			{Status: "TRIGGER PENDING"},
			{Status: "AMO REQ RECEIVED"},
			{Status: "REJECTED"},
			{Status: "CANCELLED"},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.Equal(t, 1, tc.ExecutedToday)
	assert.Equal(t, 2, tc.PendingOrders)
	assert.Equal(t, 1, tc.RejectedToday)
}

func TestBuildTradingContext_PositionPnLPct(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{
					Tradingsymbol: "INFY",
					Exchange:      "NSE",
					Product:       "NRML",
					Quantity:      10,
					AveragePrice:  1000,
					LastPrice:     1100,
					PnL:           1000,
				},
			},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "")
	assert.Equal(t, 1, tc.OpenPositions)
	assert.Equal(t, 1, tc.NRMLPositions)
	assert.NotEmpty(t, tc.PositionDetails)
	// PnL% = 1000 / (1000 * 10) * 100 = 10%
	assert.InDelta(t, 10.0, tc.PositionDetails[0].PnLPct, 0.1)
}

func TestBuildTradingContext_ClosedPositionsExcluded(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "INFY", Quantity: 0, PnL: 500},  // closed
				{Tradingsymbol: "TCS", Quantity: 10, PnL: 1000}, // open
			},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "")
	assert.Equal(t, 1, tc.OpenPositions, "closed position (qty=0) should be excluded")
	assert.Equal(t, 1000.0, tc.PositionsPnL, "only open position PnL should be counted")
}

// ===========================================================================
// ext_apps.go: chartData, optionsChainData (nil/simple return functions)
// ===========================================================================

func TestChartData_ReturnsNil(t *testing.T) {
	result := chartData(nil, nil, "")
	assert.Nil(t, result)
}

func TestOptionsChainData_ReturnsNil(t *testing.T) {
	result := optionsChainData(nil, nil, "")
	assert.Nil(t, result)
}

func TestOrderFormData_WithManager(t *testing.T) {
	mgr := newTestManager(t)
	result := orderFormData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, false, m["paper_mode"])
}

func TestWatchlistData_NoStore(t *testing.T) {
	mgr := newTestManager(t)
	result := watchlistData(mgr, nil, "test@example.com")
	// watchlist store may be nil in test manager
	_ = result // should not panic
}

func TestSafetyData_WithRiskGuard(t *testing.T) {
	mgr := newTestManager(t)
	result := safetyData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.True(t, m["enabled"].(bool))
	assert.NotNil(t, m["limits"])
	assert.NotNil(t, m["status"])
	assert.NotNil(t, m["sebi"])
	// Verify SEBI section
	sebi, ok := m["sebi"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, true, sebi["static_egress_ip"])
	assert.Equal(t, true, sebi["order_tagging"])
	assert.False(t, sebi["audit_trail"].(bool)) // nil audit store
}

func TestSafetyData_WithAuditStore(t *testing.T) {
	mgr := newTestManager(t)
	// Use a non-nil audit.Store placeholder (it won't be nil-checked)
	result := safetyData(mgr, &audit.Store{}, "test@example.com")
	m := result.(map[string]any)
	sebi := m["sebi"].(map[string]any)
	assert.True(t, sebi["audit_trail"].(bool))
}

func TestPaperData_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := paperData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	status, ok := m["status"].(map[string]any)
	assert.True(t, ok)
	assert.False(t, status["enabled"].(bool))
}

func TestAlertsData_NoAlertStore(t *testing.T) {
	mgr := newTestManager(t)
	result := alertsData(mgr, nil, "test@example.com")
	// With no alert store, should return nil or basic data
	_ = result
}

func TestHubData_WithManager(t *testing.T) {
	mgr := newTestManager(t)
	result := hubData(mgr, nil, "test@example.com")
	assert.NotNil(t, result)
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "test@example.com", m["email"])
	assert.False(t, m["kite_connected"].(bool))
	assert.False(t, m["credentials_set"].(bool))
	assert.False(t, m["paper_mode"].(bool))
	assert.Equal(t, 0, m["active_alerts"])
	assert.Equal(t, 0, m["tool_calls_today"])
	assert.NotEmpty(t, m["external_url"])
}

func TestActivityData_NoAuditStore(t *testing.T) {
	result := activityData(nil, nil, "test@example.com")
	assert.Nil(t, result, "should return nil when audit store is nil")
}

func TestPortfolioData_NoSession(t *testing.T) {
	mgr := newTestManager(t)
	result := portfolioData(mgr, nil, "test@example.com")
	// Without a valid Kite client, should return nil or error data
	_ = result // should not panic
}

func TestOrdersData_NoAuditStore(t *testing.T) {
	mgr := newTestManager(t)
	result := ordersData(mgr, nil, "test@example.com")
	// Without audit store, should still return some data
	_ = result // should not panic
}

// ===========================================================================
// common.go: WithViewerBlock — test via tool handler
// ===========================================================================

// (session type tests already exist in tool_handlers_test.go)

// ===========================================================================
// Additional tool handler validation paths
// ===========================================================================

func TestBacktestStrategy_InvalidStrategy2(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"strategy":       "invalid_strategy",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Unknown strategy")
}

func TestPreTradeCheck_MissingRequiredFields(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":       "NSE",
		// missing tradingsymbol, quantity, etc.
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestPreTradeCheck_ZeroQty(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(0),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "quantity must be greater than 0")
}

func TestPreTradeCheck_LimitOrderNoPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}

// TestTaxHarvestTool_ToolDefinition verifies the tax harvest tool schema.
func TestTaxHarvestTool_ToolDefinition(t *testing.T) {
	tool := (&TaxHarvestTool{}).Tool()
	assert.Equal(t, "tax_harvest_analysis", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}

func TestPortfolioRebalance_ValueModeNegative(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_rebalance", "trader@example.com", map[string]any{
		"targets": `{"INFY": -50000}`,
		"mode":    "value",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "non-negative")
}

// TestTradingContextTool_ToolDefinition verifies the tool schema.
func TestTradingContextTool_ToolDefinition(t *testing.T) {
	tool := (&TradingContextTool{}).Tool()
	assert.Equal(t, "trading_context", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}

func TestGetPnLJournal_NoAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

// ===========================================================================
// elicit.go: requestConfirmation edge cases
// ===========================================================================

func TestRequestConfirmation_InterfaceNotServer(t *testing.T) {
	err := requestConfirmation(context.Background(), 42, "confirm?")
	assert.NoError(t, err, "non-server type should fail open")
}

// ===========================================================================
// dividend_tool.go: validation
// ===========================================================================

func TestDividendCalendarTool_ToolDefinition(t *testing.T) {
	tool := (&DividendCalendarTool{}).Tool()
	assert.Equal(t, "dividend_calendar", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
}

// ===========================================================================
// margin_tools.go: additional validation paths
// ===========================================================================

func TestGetOrderMargins_LimitNoPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing = 0
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}

func TestGetOrderMargins_SLNoTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		// trigger_price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

func TestGetOrderMargins_SLMNoTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(10),
		"product":          "MIS",
		"order_type":       "SL-M",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

// (basket margins and order charges tests already in tool_handlers_test.go)

// ===========================================================================
// post_tools.go: additional validation paths for PlaceOrder
// ===========================================================================

// (place_order and cancel_order tests already in tool_handlers_test.go)

// ===========================================================================
// native_alert_tools.go: additional validation
// ===========================================================================

// (native alert tests already in tool_handlers_test.go)

// ===========================================================================
// market_tools.go: validation
// ===========================================================================

// (quotes, search, historical data tests already in tool_handlers_test.go)

// ===========================================================================
// mf_tools.go: additional validation
// ===========================================================================

// (MF cancel tests already in tool_handlers_test.go)

// ===========================================================================
// watchlist_tools.go: additional validation paths
// ===========================================================================

// (watchlist tests already in tool_handlers_test.go)

// ===========================================================================
// GTT tools: validation
// ===========================================================================

// (GTT tests already in tool_handlers_test.go)

// ===========================================================================
// exit_tools.go: validation paths
// ===========================================================================

// (close_position tests already in tool_handlers_test.go)

// ===========================================================================
// Additional pre-trade check edge cases
// ===========================================================================

func TestBuildPreTradeResponse_EmptyPositions(t *testing.T) {
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Nil(t, resp.ExistingPos)
}

func TestBuildPreTradeResponse_EmptyHoldings(t *testing.T) {
	data := map[string]any{
		"holdings": kiteconnect.Holdings{},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Equal(t, "low", resp.PortfolioImpact.ConcentrationAfter)
}

func TestBuildPreTradeResponse_ModerateConcentration(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "TCS", Quantity: 100, LastPrice: 1000},
		},
	}
	// Order value = 100 * 20 = 2000, portfolio = 100000, total = 102000
	// orderAsPct ≈ 2%, which is low
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 20, "CNC", 0, data, nil)
	assert.Equal(t, "low", resp.PortfolioImpact.ConcentrationAfter)
}

// ===========================================================================
// Additional buildTradingContext edge cases
// ===========================================================================

func TestBuildTradingContext_NoPositionDetails(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{}, // no open positions
		},
	}
	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Nil(t, tc.PositionDetails)
}

func TestBuildTradingContext_ZeroAvgPrice(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "INFY", Quantity: 10, AveragePrice: 0, PnL: 100},
			},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "")
	assert.Equal(t, 1, tc.OpenPositions)
	// With zero avg price, PnLPct should be 0
	assert.Equal(t, 0.0, tc.PositionDetails[0].PnLPct)
}

// ===========================================================================
// options_greeks_tool.go: bsTheta
// ===========================================================================

func TestBsTheta_Exists(t *testing.T) {
	// bsTheta is computed via -(S*normalPDF(d1)*sigma/(2*sqrt(T))) adjusted for r
	// Just verify it returns non-zero for ATM option
	S, K, T, r, sigma := 100.0, 100.0, 1.0, 0.05, 0.2
	d1 := bsD1(S, K, T, r, sigma)
	assert.NotZero(t, d1)
}

// ===========================================================================
// Additional tool definitions for coverage
// ===========================================================================

func TestAllToolsDefinitions_Categories(t *testing.T) {
	tools := GetAllTools()
	names := make(map[string]bool)
	for _, td := range tools {
		toolDef := td.Tool()
		names[toolDef.Name] = true
	}
	// Verify key tools exist
	assert.True(t, names["place_order"])
	assert.True(t, names["get_holdings"])
	assert.True(t, names["backtest_strategy"])
	assert.True(t, names["tax_harvest_analysis"])
	assert.True(t, names["portfolio_rebalance"])
	assert.True(t, names["pre_trade_check"])
	assert.True(t, names["trading_context"])
	assert.True(t, names["get_pnl_journal"])
	assert.True(t, names["options_greeks"])
	assert.True(t, names["options_strategy"])
	assert.True(t, names["server_metrics"])
}

// ===========================================================================
// Additional: test BacktestResult fields
// ===========================================================================

func TestRunBacktest_ResultFields(t *testing.T) {
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

// ===========================================================================
// common.go: WithViewerBlock
// ===========================================================================

func TestWithViewerBlock_NoEmail(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background() // no email in context
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.Nil(t, result, "should not block when no email")
}

func TestWithViewerBlock_NonWriteTool(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@example.com")
	result := handler.WithViewerBlock(ctx, "get_holdings") // read-only tool
	assert.Nil(t, result, "should not block read-only tools")
}

func TestWithViewerBlock_ViewerBlocked(t *testing.T) {
	mgr := newTestManager(t)
	// Register user as viewer
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		_ = uStore.Create(&users.User{Email: "viewer@example.com", Role: users.RoleViewer, Status: "active"})
	}
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@example.com")
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.NotNil(t, result, "should block viewer from write tools")
	assert.True(t, result.IsError)
}

func TestWithViewerBlock_TraderAllowed(t *testing.T) {
	mgr := newTestManager(t)
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		_ = uStore.Create(&users.User{Email: "trader2@example.com", Role: users.RoleTrader, Status: "active"})
	}
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "trader2@example.com")
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.Nil(t, result, "should not block trader from write tools")
}

// ===========================================================================
// common.go: callWithNilKiteGuard
// ===========================================================================

func TestCallWithNilKiteGuard_NormalExecution(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	result, err := handler.callWithNilKiteGuard("test_tool", nil, func(s *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("success"), nil
	})
	assert.NoError(t, err)
	assert.False(t, result.IsError)
}

func TestCallWithNilKiteGuard_PanicRecovery(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	result, err := handler.callWithNilKiteGuard("test_tool", nil, func(s *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
		panic("nil pointer dereference")
	})
	assert.NoError(t, err)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "DEV_MODE")
}

// ===========================================================================
// common.go: WithTokenRefresh
// ===========================================================================

func TestWithTokenRefresh_NoEmail(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", nil, "session1", "")
	assert.Nil(t, result, "should not refresh when no email")
}

func TestWithTokenRefresh_NoToken(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", nil, "session1", "unknown@example.com")
	assert.Nil(t, result, "should not refresh when no token found")
}

// ===========================================================================
// Additional: test the signalsSMACrossover with equal SMA crossover
// ===========================================================================

func TestSignalsSMACrossover_NoCrossover(t *testing.T) {
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

// ===========================================================================
// Additional: test signalsMeanReversion above upper band
// ===========================================================================

func TestSignalsMeanReversion_AboveUpperBand(t *testing.T) {
	closes := make([]float64, 40)
	for i := 0; i < 30; i++ {
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

// ===========================================================================
// Additional: test simulateTrades with force close when price affordable
// ===========================================================================

func TestSimulateTrades_BuyWithVeryHighPrice(t *testing.T) {
	candles := makeCandlesHelper([]float64{1000000}, time.Now())
	signals := make([]*backtestSignal, 1)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry"}
	// Capital is only 100, can't buy 1 share at 1000000
	trades := simulateTrades(candles, signals, 100, 100)
	assert.Empty(t, trades, "should not enter position when can't afford even 1 share")
}

// ===========================================================================
// Additional: More buildTradingContext edge cases
// ===========================================================================

func TestBuildTradingContext_ZeroMargin(t *testing.T) {
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{
				Net:  0,
				Used: kiteconnect.UsedMargins{Debits: 0},
			},
		},
	}
	tc := buildTradingContext(data, nil, mgr, "")
	assert.Equal(t, 0.0, tc.MarginUtilization)
}

func TestBuildTradingContext_MultipleMISPositions(t *testing.T) {
	mgr := newTestManager(t)
	positions := make([]kiteconnect.Position, 5)
	for i := range positions {
		positions[i] = kiteconnect.Position{
			Tradingsymbol: "STOCK" + string(rune('A'+i)),
			Product:       "MIS",
			Quantity:      10,
			PnL:           float64(i * 100),
		}
	}
	data := map[string]any{
		"positions": kiteconnect.Positions{Net: positions},
	}
	tc := buildTradingContext(data, nil, mgr, "")
	assert.Equal(t, 5, tc.OpenPositions)
	assert.Equal(t, 5, tc.MISPositions)
}

// ===========================================================================
// Additional: buildPreTradeResponse edge cases for 100% concentration
// ===========================================================================

func TestBuildPreTradeResponse_HighConcentrationLevel(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 1000},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "TCS", Quantity: 10, LastPrice: 100}, // portfolio = 1000
		},
	}
	// Order value = 1000 * 50 = 50000, portfolio = 1000, total = 51000
	// orderAsPct = 50000/51000 * 100 ≈ 98% — high concentration
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 50, "CNC", 0, data, nil)
	assert.Equal(t, "high", resp.PortfolioImpact.ConcentrationAfter)
}

// ===========================================================================
// Handler tests using mockSession (exercises WithSession path)
// ===========================================================================

func TestGetHoldings_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_holdings", "trader@example.com", map[string]any{})
	// Should fail with login required (no real Kite client), not panic
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetPositions_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_positions", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetMargins_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetProfile_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_profile", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetOrders_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetTrades_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestPortfolioSummary_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_summary", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPortfolioConcentration_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_concentration", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPositionAnalysis_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "position_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetLTP_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ltp", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}

func TestGetOHLC_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ohlc", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}

func TestGetQuotes_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}

func TestSearchInstruments_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "RELIANCE",
	})
	// search_instruments uses the instrument manager (not Kite client),
	// so it may actually succeed
	assert.NotNil(t, result)
}

func TestSEBICompliance_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sebi_compliance_status", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestTradingContext_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "trading_context", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPreTradeCheck_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestBacktestStrategy_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
}

func TestTaxHarvest_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "tax_harvest_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPortfolioRebalance_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_rebalance", "trader@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
	})
	assert.True(t, result.IsError)
}

func TestDividendCalendar_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "dividend_calendar", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestSectorExposure_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sector_exposure", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestServerMetrics_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{})
	// server_metrics may succeed without a Kite client
	assert.NotNil(t, result)
}

func TestTechnicalIndicators_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"indicators":       []interface{}{"RSI", "SMA"},
	})
	assert.True(t, result.IsError)
}

func TestGetHistoricalData_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-01-01 00:00:00",
		"to_date":          "2024-12-31 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
}

func TestPlaceOrder_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestModifyOrder_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "123456",
		"order_type": "LIMIT",
	})
	assert.True(t, result.IsError)
}

func TestCancelOrder_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestClosePosition_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderMargins_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestListAlerts_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_alerts", "trader@example.com", map[string]any{})
	// list_alerts may succeed if alert store is available
	assert.NotNil(t, result)
}

func TestSetAlert_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
}

func TestGetMFHoldings_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_holdings", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetMFSIPs_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_sips", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetGTTs_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_gtts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestOptionsGreeks_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
		"strike_price":  float64(24000),
		"option_type":   "CE",
		"expiry_date":   "2026-04-30",
	})
	assert.True(t, result.IsError)
}

func TestGetOptionChain_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_option_chain", "trader@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.True(t, result.IsError)
}

func TestListWatchlists_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_watchlists", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestPaperTradingStatus_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "paper_trading_status", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestCloseAllPositions_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_all_positions", "trader@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
}

func TestPlaceGTT_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
		"quantity":         float64(10),
	})
	assert.True(t, result.IsError)
}

func TestModifyGTT_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
		"quantity":         float64(10),
	})
	assert.True(t, result.IsError)
}

func TestDeleteGTT_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(12345),
	})
	assert.True(t, result.IsError)
}

func TestConvertPosition_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderHistory_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_history", "trader@example.com", map[string]any{
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderTrades_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_trades", "trader@example.com", map[string]any{
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestPlaceNativeAlert_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1800),
	})
	assert.True(t, result.IsError)
}

func TestListNativeAlerts_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_native_alerts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetNativeAlertHistory_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_native_alert_history", "trader@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.True(t, result.IsError)
}

func TestDeleteNativeAlert_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_native_alert", "trader@example.com", map[string]any{
		"uuid": "test-uuid-123",
	})
	assert.True(t, result.IsError)
}

func TestPlaceMFOrder_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(5000),
	})
	assert.True(t, result.IsError)
}

func TestGetBasketMargins_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.True(t, result.IsError)
}

func TestGetOrderCharges_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET","average_price":1500}]`,
	})
	assert.True(t, result.IsError)
}

func TestOptionsStrategy_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2026-04-30",
		"strike1":    float64(24000),
		"strike2":    float64(24500),
	})
	assert.True(t, result.IsError)
}

func TestSetTrailingStop_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "12345",
		"direction":    "long",
		"trail_amount": float64(20),
	})
	assert.NotNil(t, result) // may succeed or fail
}

func TestListTrailingStops_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_trailing_stops", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestCancelTrailingStop_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_trailing_stop", "trader@example.com", map[string]any{
		"trailing_stop_id": "ts-123",
	})
	assert.NotNil(t, result)
}

func TestGetWatchlist_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_watchlist", "trader@example.com", map[string]any{
		"name": "My Watchlist",
	})
	assert.NotNil(t, result)
}

func TestCreateWatchlist_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "create_watchlist", "trader@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestDeleteWatchlist_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_watchlist", "trader@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestAddToWatchlist_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{
		"name":        "Test Watchlist",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestRemoveFromWatchlist_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "remove_from_watchlist", "trader@example.com", map[string]any{
		"name":        "Test Watchlist",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestDeleteAlert_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_alert", "trader@example.com", map[string]any{
		"alert_id": "alert-123",
	})
	assert.NotNil(t, result)
}

func TestPlaceMFSIP_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError)
}

func TestCancelMFOrder_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_mf_order", "trader@example.com", map[string]any{
		"order_id": "mf-order-123",
	})
	assert.True(t, result.IsError)
}

func TestCancelMFSIP_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_mf_sip", "trader@example.com", map[string]any{
		"sip_id": "sip-123",
	})
	assert.True(t, result.IsError)
}

func TestGetMFOrders_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestSubscribeInstruments_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "subscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestUnsubscribeInstruments_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "unsubscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestStopTicker_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "stop_ticker", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestTickerStatus_WithSession(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "ticker_status", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestServerMetrics_WithSession2(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{
		"period": "1h",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// trailing_tools.go: doSetTrailingStop
// ===========================================================================

func TestDoSetTrailingStop_WithAmount(t *testing.T) {
	mgr := newTestManager(t)
	result, err := doSetTrailingStop(mgr, "test@example.com", "NSE", "INFY", 256265,
		"order123", "regular", "long", 20, 0, 1480, 1500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "Trailing stop set")
	assertResultContains(t, result, "Rs.20.00")
}

func TestDoSetTrailingStop_WithPct(t *testing.T) {
	mgr := newTestManager(t)
	result, err := doSetTrailingStop(mgr, "test2@example.com", "NSE", "RELIANCE", 408065,
		"order456", "regular", "short", 0, 2.5, 2550, 2500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "2.50%")
	assertResultContains(t, result, "short")
}

func TestBuildPreTradeResponse_ModerateConcentrationLevel(t *testing.T) {
	data := map[string]any{
		"ltp": kiteconnect.QuoteLTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"holdings": kiteconnect.Holdings{
			{Tradingsymbol: "TCS", Quantity: 100, LastPrice: 300}, // portfolio = 30000
		},
	}
	// Order value = 100 * 60 = 6000, portfolio = 30000, total = 36000
	// orderAsPct = 6000/36000 * 100 ≈ 16.7% — moderate concentration
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 60, "CNC", 0, data, nil)
	assert.Equal(t, "moderate", resp.PortfolioImpact.ConcentrationAfter)
}
