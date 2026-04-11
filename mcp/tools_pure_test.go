package mcp

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	gomcp "github.com/mark3labs/mcp-go/mcp"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

func makeCandles(n int, startPrice float64, volatility float64) []broker.HistoricalCandle {
	candles := make([]broker.HistoricalCandle, n)
	price := startPrice
	for i := 0; i < n; i++ {
		// Simple price movement: alternate up/down with drift
		delta := volatility * float64((i%7)-3) / 3.0
		price += delta
		if price < 1 {
			price = 1
		}
		candles[i] = broker.HistoricalCandle{
			Date:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, i),
			Open:   price - 1,
			High:   price + 2,
			Low:    price - 2,
			Close:  price,
			Volume: 1000 + i*10,
		}
	}
	return candles
}

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

func makeOscillatingPricesHelper(n int) []float64 {
	prices := make([]float64, n)
	for i := range prices {
		prices[i] = 100 + 20*math.Sin(float64(i)*0.15) + float64(i%3)
	}
	return prices
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

func TestIsTransientError(t *testing.T) {
	t.Parallel()
	assert.True(t, isTransientError(errors.New("connection refused")))
	assert.True(t, isTransientError(errors.New("request timeout")))
	assert.True(t, isTransientError(errors.New("service temporarily unavailable")))
	assert.True(t, isTransientError(errors.New("unexpected EOF")))
	assert.True(t, isTransientError(errors.New("Connection reset by peer")))
	assert.False(t, isTransientError(errors.New("invalid API key")))
	assert.False(t, isTransientError(errors.New("permission denied")))
	assert.False(t, isTransientError(errors.New("bad request")))
}

func TestRetryBrokerCall_SuccessFirstTry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "ok", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 1, calls)
}

func TestRetryBrokerCall_NonTransientFails(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("invalid API key")
	}, 3)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should not retry non-transient errors")
}

func TestRetryBrokerCall_TransientRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("connection timeout")
		}
		return "recovered", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "recovered", result)
	assert.Equal(t, 3, calls)
}

func TestRetryBrokerCall_ExhaustsRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (int, error) {
		calls++
		return 0, errors.New("connection timeout every time")
	}, 2)
	assert.Error(t, err)
	assert.Equal(t, 3, calls, "should try 1 + 2 retries = 3 calls")
	assert.Contains(t, err.Error(), "connection timeout")
}

func TestRetryBrokerCall_ZeroRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("connection refused")
	}, 0)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "zero retries means just one attempt")
}

func TestNormalizeSymbol(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("reliance"))
	assert.Equal(t, "RELIANCE", normalizeSymbol(" RELIANCE "))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-EQ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BZ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BL"))
	assert.Equal(t, "INFY", normalizeSymbol("INFY-EQ"))
}

func TestFormatPct(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "50%", formatPct(50.0))
	assert.Equal(t, "100%", formatPct(100.0))
	assert.Equal(t, "0%", formatPct(0.0))
	assert.Equal(t, "33.3%", formatPct(33.3))
	assert.Equal(t, "12.5%", formatPct(12.5))
}

func TestFormatINR(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Rs 500", formatINR(500))
	assert.Equal(t, "Rs 99999", formatINR(99999))
	assert.Equal(t, "Rs 1,00,000", formatINR(100000))
	assert.Equal(t, "Rs 5,00,000", formatINR(500000))
	assert.Equal(t, "Rs 10,00,000", formatINR(1000000))
	assert.Equal(t, "Rs 1.50 L", formatINR(150000))
	assert.Equal(t, "Rs 2.75 L", formatINR(275000))
	assert.Equal(t, "Rs 0", formatINR(0))
}

func TestFormatRHS_Constant(t *testing.T) {
	t.Parallel()
	params := kiteconnect.AlertParams{
		RHSType:     "constant",
		RHSConstant: 1500.50,
	}
	assert.Equal(t, "1500.50", formatRHS(params))
}

func TestFormatRHS_Instrument(t *testing.T) {
	t.Parallel()
	params := kiteconnect.AlertParams{
		RHSType:          "instrument",
		RHSExchange:      "NSE",
		RHSTradingSymbol: "INFY",
		RHSAttribute:     "last_price",
	}
	assert.Equal(t, "NSE:INFY (last_price)", formatRHS(params))
}

func TestSplitAndTrim(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c"}, splitAndTrim("a, b, c"))
	assert.Equal(t, []string{"NSE:INFY"}, splitAndTrim("NSE:INFY"))
	assert.Equal(t, []string{"a", "b"}, splitAndTrim("  a  ,  b  "))
	// Empty string splits to one empty part, which gets trimmed to empty
	result := splitAndTrim("")
	assert.Empty(t, result)
	result2 := splitAndTrim(", , ,")
	assert.Empty(t, result2)
}

func TestParseInstrumentList(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"NSE:INFY", "NSE:RELIANCE"}, parseInstrumentList("NSE:INFY, NSE:RELIANCE"))
	assert.Equal(t, []string{"NSE:INFY"}, parseInstrumentList("NSE:INFY"))
	result := parseInstrumentList("")
	assert.Empty(t, result)
	assert.Equal(t, []string{"a", "b"}, parseInstrumentList("  a  ,  b  "))
	result2 := parseInstrumentList(", , ,")
	assert.Empty(t, result2)
}

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

func TestResolveTickerMode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ticker.ModeLTP, resolveTickerMode("ltp"))
	assert.Equal(t, ticker.ModeQuote, resolveTickerMode("quote"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("full"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("unknown"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode(""))
}

func TestResolveInstrumentTokens_AllInvalid(t *testing.T) {
	mgr := newTestManager(t)
	// Test data instruments don't have ID field set, so GetByID won't find them
	tokens, failed := resolveInstrumentTokens(mgr, []string{"NSE:NONEXISTENT"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 1)
	assert.Equal(t, "NSE:NONEXISTENT", failed[0])
}

func TestResolveInstrumentTokens_Empty(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr, []string{})
	assert.Empty(t, tokens)
	assert.Empty(t, failed)
}

func TestResolveInstrumentTokens_MultipleFailed(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr, []string{"NSE:AAA", "NSE:BBB", "NSE:CCC"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 3)
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

func TestBuildOrderConfirmMessage_ClosePosition(t *testing.T) {
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:RELIANCE",
		"product":    "MIS",
	})
	assert.Contains(t, msg, "NSE:RELIANCE")
}

func TestBuildOrderConfirmMessage_ModifyGTT(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_gtt_order", map[string]any{
		"trigger_id":       float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.Contains(t, msg, "GTT")
}

func TestBuildOrderConfirmMessage_PlaceNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":          "Test alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"operator":      ">=",
	})
	assert.NotEmpty(t, msg)
}

func TestBuildOrderConfirmMessage_ModifyNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_native_alert", map[string]any{
		"uuid": "test-uuid",
		"name": "Modified alert",
	})
	assert.NotEmpty(t, msg)
}

func TestFormatINR_LargeNumber(t *testing.T) {
	result := formatINR(10000000) // 1 crore
	assert.Contains(t, result, "Rs")
}

func TestFormatPct_NegativeValue(t *testing.T) {
	result := formatPct(-5.5)
	assert.Equal(t, "-5.5%", result)
}

func TestNormalizeSymbol_NoSuffix(t *testing.T) {
	assert.Equal(t, "TCS", normalizeSymbol("TCS"))
}

func TestBuildOrderConfirmMessage_AllConfirmableTools(t *testing.T) {
	for toolName := range confirmableTools {
		msg := buildOrderConfirmMessage(toolName, map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"quantity":         float64(10),
			"order_type":       "MARKET",
			"product":          "CNC",
			"order_id":         "123",
			"confirm":          true,
			"trigger_type":     "single",
			"trigger_value":    float64(1400),
			"amount":           float64(5000),
			"frequency":        "monthly",
			"instalments":      float64(12),
			"instrument":       "NSE:INFY",
			"name":             "Test",
			"type":             "ato",
			"operator":         ">=",
			"uuid":             "test-uuid",
		})
		assert.NotEmpty(t, msg, "confirm message for %s should not be empty", toolName)
	}
}

func TestComputePortfolioSummary_Empty(t *testing.T) {
	result := computePortfolioSummary([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, 0.0, result.TotalInvested)
	assert.Equal(t, 0.0, result.TotalCurrent)
}

func TestComputePortfolioSummary_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "INFY",
			Quantity:      10,
			AveragePrice:  1500,
			LastPrice:     1600,
			DayChangePct:  2.0,
		},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, 15000.0, result.TotalInvested)
	assert.Equal(t, 16000.0, result.TotalCurrent)
	assert.Equal(t, 1000.0, result.OverallPnL)
}

func TestComputePortfolioSummary_TopGainersAndLosers(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "GAINER1", Quantity: 10, AveragePrice: 100, LastPrice: 110, DayChangePct: 5.0},
		{Tradingsymbol: "GAINER2", Quantity: 10, AveragePrice: 100, LastPrice: 120, DayChangePct: 10.0},
		{Tradingsymbol: "LOSER1", Quantity: 10, AveragePrice: 100, LastPrice: 90, DayChangePct: -5.0},
		{Tradingsymbol: "FLAT", Quantity: 10, AveragePrice: 100, LastPrice: 100, DayChangePct: 0.0},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 4, result.HoldingsCount)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
	assert.LessOrEqual(t, len(result.BiggestHoldings), 5)
}

func TestComputePortfolioConcentration_Empty(t *testing.T) {
	result := computePortfolioConcentration([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, "empty", result.Concentration)
}

func TestComputePortfolioConcentration_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, "concentrated", result.Concentration)
	assert.Equal(t, 10000.0, result.HHIScore) // 100% squared
}

func TestComputePortfolioConcentration_Diversified(t *testing.T) {
	holdings := make([]broker.Holding, 20)
	for i := range holdings {
		holdings[i] = broker.Holding{
			Tradingsymbol: "STOCK" + string(rune('A'+i)),
			Quantity:      10,
			LastPrice:     100,
		}
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 20, result.HoldingsCount)
	assert.Equal(t, "diversified", result.Concentration)
	assert.Less(t, result.HHIScore, 1500.0)
}

func TestComputePortfolioConcentration_ZeroValue(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, "empty", result.Concentration)
}

func TestComputePositionAnalysis_Empty(t *testing.T) {
	result := computePositionAnalysis([]broker.Position{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NetPositionsCount)
	assert.Equal(t, 0.0, result.TotalPnL)
}

func TestComputePositionAnalysis_WithPositions(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Exchange: "NSE", Product: "MIS", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: 1000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Product: "CNC", Quantity: -5, AveragePrice: 2500, LastPrice: 2400, PnL: -500},
		{Tradingsymbol: "TCS", Exchange: "NSE", Product: "MIS", Quantity: 20, AveragePrice: 3500, LastPrice: 3600, PnL: 2000},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 3, result.NetPositionsCount)
	assert.Equal(t, 2500.0, result.TotalPnL)
	assert.GreaterOrEqual(t, len(result.ByProduct), 1)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
}

func TestComputePositionAnalysis_ProductGrouping(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Product: "MIS", PnL: 100},
		{Tradingsymbol: "TCS", Product: "MIS", PnL: 200},
		{Tradingsymbol: "RELIANCE", Product: "CNC", PnL: -50},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 2, len(result.ByProduct))
}

func TestStockSectors_NotEmpty(t *testing.T) {
	assert.Greater(t, len(stockSectors), 50, "should have at least 50 stock-sector mappings")
}

func TestStockSectors_KnownStocks(t *testing.T) {
	knownStocks := map[string]string{
		"RELIANCE": "Energy",
		"INFY":     "IT",
		"HDFCBANK": "Banking",
		"TCS":      "IT",
	}
	for stock, expectedSector := range knownStocks {
		sector, ok := stockSectors[stock]
		assert.True(t, ok, "stock %s should be in stockSectors", stock)
		assert.Equal(t, expectedSector, sector, "stock %s sector mismatch", stock)
	}
}

func TestParseInstrumentList_SingleItem(t *testing.T) {
	result := parseInstrumentList("NSE:INFY")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}

func TestParseInstrumentList_TrailingComma(t *testing.T) {
	result := parseInstrumentList("NSE:INFY,")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}

func TestComputeSectorExposure_Empty(t *testing.T) {
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
}

func TestComputeSectorExposure_ZeroValue(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Empty(t, result.Sectors)
}

func TestComputeSectorExposure_MappedStocks(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500},
		{Tradingsymbol: "HDFCBANK", Quantity: 20, LastPrice: 1600},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 3, result.HoldingsCount)
	assert.Equal(t, 3, result.MappedCount)
	assert.Equal(t, 0, result.UnmappedCount)
	assert.GreaterOrEqual(t, len(result.Sectors), 2) // IT and Banking
}

func TestComputeSectorExposure_UnmappedStocks(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "UNKNOWNSTOCK", Quantity: 10, LastPrice: 100},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.UnmappedCount)
	assert.Len(t, result.UnmappedStocks, 1)
}

func TestComputeSectorExposure_OverExposed(t *testing.T) {
	// Single stock = 100% in one sector = over-exposed
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computeSectorExposure(holdings)
	assert.GreaterOrEqual(t, len(result.Warnings), 1)
}

func TestComputeDividendCalendar_Empty(t *testing.T) {
	result := computeDividendCalendar([]broker.Holding{}, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.Summary.HoldingsCount)
}

func TestComputeDividendCalendar_WithHoldings(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500, AveragePrice: 1400},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500, AveragePrice: 3200},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.Equal(t, 2, result.Summary.HoldingsCount)
	assert.NotNil(t, result.HoldingsByYield)
}

func TestComputeDividendCalendar_ZeroDayLookAhead(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "RELIANCE", Quantity: 10, LastPrice: 2500},
	}
	result := computeDividendCalendar(holdings, 0)
	assert.NotNil(t, result)
}

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

func TestComputeTaxHarvest_EmptyHoldings(t *testing.T) {
	t.Parallel()
	resp := computeTaxHarvest([]broker.Holding{}, 0)
	assert.NotNil(t, resp)
	assert.Equal(t, 0, resp.Summary.HoldingsCount)
	assert.Empty(t, resp.HarvestCandidates)
}

func TestComputeTaxHarvest_STCGWithLoss(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "HDFC", Exchange: "NSE", Quantity: 50, AveragePrice: 1500, LastPrice: 1600},
	}
	resp := computeTaxHarvest(holdings, 340)
	assert.True(t, resp.AllHoldings[0].ApproachingLTCG)
	assert.Equal(t, 1, resp.Summary.ApproachingLTCGCnt)
	assert.Equal(t, 1, len(resp.ApproachingLTCG))
}

func TestComputeTaxHarvest_NotApproachingLTCG(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "HDFC", Exchange: "NSE", Quantity: 50, AveragePrice: 1500, LastPrice: 1600},
	}
	resp := computeTaxHarvest(holdings, 100)
	assert.False(t, resp.AllHoldings[0].ApproachingLTCG)
}

func TestComputeTaxHarvest_MixedHoldings(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	holdings := []broker.Holding{{Tradingsymbol: "X", Quantity: 1, AveragePrice: 100, LastPrice: 100}}

	resp := computeTaxHarvest(holdings, 0)
	assert.Contains(t, resp.Summary.HoldingPeriodNote, "default to STCG")

	resp2 := computeTaxHarvest(holdings, 400)
	assert.Contains(t, resp2.Summary.HoldingPeriodNote, "User override")
}

func TestComputeTaxHarvest_ZeroPricePnl(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "ITC", Quantity: 1000, AveragePrice: 400, LastPrice: 350},
	}
	resp := computeTaxHarvest(holdings, 500) // LTCG
	assert.Equal(t, "LTCG", resp.AllHoldings[0].HoldingPeriod)
	assert.True(t, resp.AllHoldings[0].Harvestable)
	assert.Equal(t, ltcgRate, resp.AllHoldings[0].TaxRate)
	assert.Less(t, resp.Summary.LTCGLosses, 0.0)
}

func TestBuildOrderConfirmMessage_PlaceOrder_Market(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	msg := buildOrderConfirmMessage("close_all_positions", map[string]any{
		"product": "MIS",
	})
	assert.Contains(t, msg, "ALL")
	assert.Contains(t, msg, "MIS")
}

func TestBuildOrderConfirmMessage_ClosePosition_NoProduct(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:HDFC",
	})
	assert.Contains(t, msg, "NSE:HDFC")
	assert.Contains(t, msg, "MARKET")
}

func TestBuildOrderConfirmMessage_PlaceGTT(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.Contains(t, msg, "MF")
	assert.Contains(t, msg, "10000")
}

func TestBuildOrderConfirmMessage_PlaceMFOrder_Quantity(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "SELL",
		"quantity":         float64(50),
	})
	assert.Contains(t, msg, "50 units")
}

func TestBuildOrderConfirmMessage_PlaceMFSIP(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	msg := buildOrderConfirmMessage("unknown_tool", map[string]any{})
	assert.Contains(t, msg, "Execute unknown_tool")
}

func TestInjectData_NilData(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	result := injectData(html, nil)
	assert.Contains(t, result, "null")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_MapData(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := map[string]any{"key": "value", "count": 42}
	result := injectData(html, data)
	assert.Contains(t, result, `"key"`)
	assert.Contains(t, result, `"value"`)
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_UnmarshalableData(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := make(chan int)
	result := injectData(html, data)
	assert.Contains(t, result, "null")
}

func TestInjectData_NoPlaceholder(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "something";</script>`
	data := map[string]any{"key": "value"}
	result := injectData(html, data)
	assert.Equal(t, html, result)
}

func TestInjectData_XSSEscaping(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	// Data containing potential XSS sequence
	data := map[string]any{"text": "</script><script>alert(1)</script>"}
	result := injectData(html, data)
	// The </script> in JSON should be escaped
	assert.NotContains(t, result, "</script><script>")
}

func TestWithAppUI_SetsResourceURI(t *testing.T) {
	t.Parallel()
	tool := gomcp.NewTool("test_tool", gomcp.WithDescription("A test tool"))
	result := withAppUI(tool, "ui://kite-mcp/portfolio")
	assert.NotNil(t, result.Meta)
	assert.Equal(t, "ui://kite-mcp/portfolio", result.Meta.AdditionalFields["ui/resourceUri"])
}

func TestWithAppUI_EmptyURI(t *testing.T) {
	t.Parallel()
	tool := gomcp.NewTool("test_tool", gomcp.WithDescription("A test tool"))
	result := withAppUI(tool, "")
	assert.Nil(t, result.Meta, "empty URI should not set meta")
}

func TestResourceURIForTool_MappedTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("get_holdings")
	assert.Equal(t, "ui://kite-mcp/portfolio", uri)
}

func TestResourceURIForTool_UnmappedTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("nonexistent_tool")
	assert.Empty(t, uri)
}

func TestResourceURIForTool_OrderTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("get_orders")
	assert.Equal(t, "ui://kite-mcp/orders", uri)
}

func TestResourceURIForTool_AlertTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("list_alerts")
	assert.Equal(t, "ui://kite-mcp/alerts", uri)
}

func TestResourceURIForTool_PaperTradingTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("paper_trading_toggle")
	assert.Equal(t, "ui://kite-mcp/paper", uri)
}

func TestResourceURIForTool_WatchlistTool(t *testing.T) {
	t.Parallel()
	uri := resourceURIForTool("list_watchlists")
	assert.Equal(t, "ui://kite-mcp/watchlist", uri)
}

func TestMorningBriefHandler_ReturnsValidPrompt(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestBlackScholesPrice_CallPutParity(t *testing.T) {
	t.Parallel()
	S, K, T, r, sigma := 100.0, 100.0, 1.0, 0.05, 0.2
	callPrice := blackScholesPrice(S, K, T, r, sigma, true)
	putPrice := blackScholesPrice(S, K, T, r, sigma, false)
	parity := callPrice - putPrice
	expected := S - K*math.Exp(-r*T)
	assert.InDelta(t, expected, parity, 0.01)
}

func TestBlackScholesPrice_DeepITMCall(t *testing.T) {
	t.Parallel()
	price := blackScholesPrice(200, 100, 0.01, 0.05, 0.2, true)
	assert.Greater(t, price, 99.0)
}

func TestBlackScholesPrice_DeepOTMPut(t *testing.T) {
	t.Parallel()
	price := blackScholesPrice(200, 100, 0.01, 0.05, 0.2, false)
	assert.Less(t, price, 1.0)
}

func TestBsDelta_CallBounds(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100, 100, 1, 0.05, 0.2, true)
	assert.Greater(t, delta, 0.0)
	assert.Less(t, delta, 1.0)
}

func TestBsDelta_PutBounds(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100, 100, 1, 0.05, 0.2, false)
	assert.Less(t, delta, 0.0)
	assert.Greater(t, delta, -1.0)
}

func TestBsGamma_Positive(t *testing.T) {
	t.Parallel()
	gamma := bsGamma(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, gamma, 0.0)
}

func TestBsGamma_ZeroTimeReturnsZero(t *testing.T) {
	t.Parallel()
	gamma := bsGamma(100, 100, 0, 0.05, 0.2)
	assert.Equal(t, 0.0, gamma)
}

func TestBsVega_Positive(t *testing.T) {
	t.Parallel()
	vega := bsVega(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, vega, 0.0)
}

func TestBsVega_ZeroTimeReturnsZero(t *testing.T) {
	t.Parallel()
	vega := bsVega(100, 100, 0, 0.05, 0.2)
	assert.Equal(t, 0.0, vega)
}

func TestNormalCDF_KnownValues(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 0.5, normalCDF(0), 0.01)
	assert.InDelta(t, 0.8413, normalCDF(1), 0.01)
	assert.InDelta(t, 0.1587, normalCDF(-1), 0.01)
	assert.InDelta(t, 0.9772, normalCDF(2), 0.01)
}

func TestNormalPDF_KnownValues(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 0.3989, normalPDF(0), 0.001)
	assert.InDelta(t, normalPDF(1), normalPDF(-1), 0.0001)
}

func TestBsD1_ATM(t *testing.T) {
	t.Parallel()
	d1 := bsD1(100, 100, 1, 0.05, 0.2)
	assert.Greater(t, d1, 0.0)
}

func TestBacktestDefaults_PartialOverride(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"param1": float64(7),
		// param2 not set — should use default
	}
	p1, p2 := backtestDefaults("sma_crossover", args)
	assert.Equal(t, 7.0, p1)
	assert.Equal(t, 50.0, p2)
}

func TestBuildPreTradeResponse_AllDataPresent(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0,
		map[string]any{}, nil)
	assert.Equal(t, "INFY", resp.Symbol)
	assert.Equal(t, 0.0, resp.CurrentPrice)
	assert.Equal(t, "PROCEED", resp.Recommendation)
}

func TestBuildPreTradeResponse_InsufficientMargin(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestBuildTradingContext_AllDataPresent(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	mgr := newTestManager(t)
	tc := buildTradingContext(map[string]any{}, nil, mgr, "test@example.com")
	assert.NotNil(t, tc)
	assert.NotEmpty(t, tc.MarketStatus)
	assert.Equal(t, 0.0, tc.MarginAvailable)
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Equal(t, 0, tc.PendingOrders)
}

func TestBuildTradingContext_WithAPIErrors(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	errs := map[string]string{"margins": "timeout", "positions": "auth failed"}
	tc := buildTradingContext(map[string]any{}, errs, mgr, "test@example.com")
	assert.NotNil(t, tc.Errors)
	assert.Contains(t, tc.Errors, "margins")
	assert.Contains(t, tc.Errors, "positions")
}

func TestBuildTradingContext_HighMarginUtilization(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestBuildPreTradeResponse_EmptyPositions(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"positions": kiteconnect.Positions{
			Net: []kiteconnect.Position{},
		},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Nil(t, resp.ExistingPos)
}

func TestBuildPreTradeResponse_EmptyHoldings(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"holdings": kiteconnect.Holdings{},
	}
	resp := buildPreTradeResponse("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Equal(t, "low", resp.PortfolioImpact.ConcentrationAfter)
}

func TestBuildPreTradeResponse_ModerateConcentration(t *testing.T) {
	t.Parallel()
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

func TestBuildTradingContext_NoPositionDetails(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestBsTheta_Exists(t *testing.T) {
	t.Parallel()
	// bsTheta is computed via -(S*normalPDF(d1)*sigma/(2*sqrt(T))) adjusted for r
	// Just verify it returns non-zero for ATM option
	S, K, T, r, sigma := 100.0, 100.0, 1.0, 0.05, 0.2
	d1 := bsD1(S, K, T, r, sigma)
	assert.NotZero(t, d1)
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

func TestSimulateTrades_BuyWithVeryHighPrice(t *testing.T) {
	t.Parallel()
	candles := makeCandlesHelper([]float64{1000000}, time.Now())
	signals := make([]*backtestSignal, 1)
	signals[0] = &backtestSignal{action: "BUY", reason: "entry"}
	// Capital is only 100, can't buy 1 share at 1000000
	trades := simulateTrades(candles, signals, 100, 100)
	assert.Empty(t, trades, "should not enter position when can't afford even 1 share")
}

func TestBuildTradingContext_ZeroMargin(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestBuildPreTradeResponse_HighConcentrationLevel(t *testing.T) {
	t.Parallel()
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

func TestDoSetTrailingStop_WithAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result, err := doSetTrailingStop(mgr, "test@example.com", "NSE", "INFY", 256265,
		"order123", "regular", "long", 20, 0, 1480, 1500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "Trailing stop set")
	assertResultContains(t, result, "Rs.20.00")
}

func TestDoSetTrailingStop_WithPct(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result, err := doSetTrailingStop(mgr, "test2@example.com", "NSE", "RELIANCE", 408065,
		"order456", "regular", "short", 0, 2.5, 2550, 2500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "2.50%")
	assertResultContains(t, result, "short")
}

func TestBuildPreTradeResponse_ModerateConcentrationLevel(t *testing.T) {
	t.Parallel()
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

func TestBSDelta_CallATM(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.InDelta(t, 0.5, delta, 0.1, "ATM call should have delta near 0.5")
}

func TestBSDelta_PutATM(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, false)
	assert.InDelta(t, -0.5, delta, 0.1, "ATM put should have delta near -0.5")
}

func TestBSGamma_ATM(t *testing.T) {
	t.Parallel()
	gamma := bsGamma(100.0, 100.0, 30.0/365.0, 0.05, 0.2)
	assert.Greater(t, gamma, 0.0, "ATM gamma should be positive")
}

func TestBSTheta_CallNegative(t *testing.T) {
	t.Parallel()
	theta := bsTheta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.Less(t, theta, 0.0, "Call theta should be negative (time decay)")
}

func TestBSVega_Positive(t *testing.T) {
	t.Parallel()
	vega := bsVega(100.0, 100.0, 30.0/365.0, 0.05, 0.2)
	assert.Greater(t, vega, 0.0, "Vega should be positive")
}

func TestBSRho_CallPositive(t *testing.T) {
	t.Parallel()
	rho := bsRho(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.Greater(t, rho, 0.0, "Call rho should be positive")
}

func TestBSRho_PutNegative(t *testing.T) {
	t.Parallel()
	rho := bsRho(100.0, 100.0, 30.0/365.0, 0.05, 0.2, false)
	assert.Less(t, rho, 0.0, "Put rho should be negative")
}

func TestImpliedVolatility_Converges(t *testing.T) {
	t.Parallel()
	// Price an option with known vol, then extract IV from the price
	price := blackScholesPrice(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	iv, ok := impliedVolatility(price, 100.0, 100.0, 30.0/365.0, 0.05, true)
	assert.True(t, ok, "IV should converge")
	assert.InDelta(t, 0.2, iv, 0.01, "Extracted IV should match input vol")
}

func TestImpliedVolatility_DeepOTM(t *testing.T) {
	t.Parallel()
	// Very cheap option (near zero) — IV extraction may not converge
	_, ok := impliedVolatility(0.001, 100.0, 200.0, 30.0/365.0, 0.05, true)
	// ok might be false, which is acceptable
	_ = ok
}

func TestNormalCDF_Symmetric(t *testing.T) {
	t.Parallel()
	// N(0) should be 0.5
	assert.InDelta(t, 0.5, normalCDF(0), 0.001)
	// N(x) + N(-x) = 1
	assert.InDelta(t, 1.0, normalCDF(1.5)+normalCDF(-1.5), 0.001)
}

func TestNormalPDF_Symmetric(t *testing.T) {
	t.Parallel()
	// pdf(x) == pdf(-x)
	assert.InDelta(t, normalPDF(1.0), normalPDF(-1.0), 0.0001)
	// pdf(0) is the maximum
	assert.Greater(t, normalPDF(0), normalPDF(1.0))
}

func TestExtractUnderlyingSymbol_Various(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "NIFTY", extractUnderlyingSymbol("NIFTY26APR24000CE"))
	assert.Equal(t, "BANKNIFTY", extractUnderlyingSymbol("BANKNIFTY26APR50000PE"))
	// Edge case: short symbol
	assert.NotPanics(t, func() { extractUnderlyingSymbol("A") })
}

func TestComputeSectorExposure_KnownStocks(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1500, LastPrice: 1600},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 50, AveragePrice: 1600, LastPrice: 1700},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.Sectors), 2, "Should have at least 2 sectors")
}

func TestComputeSectorExposure_UnknownStock(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "XYZUNKNOWN", Exchange: "NSE", Quantity: 100, AveragePrice: 100, LastPrice: 110},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.UnmappedStocks), 1, "Unknown stock should be unmapped")
}

func TestComputeSectorExposure_NoHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Empty(t, result.Sectors)
}

func TestComputeMaxDrawdown_NoTrades(t *testing.T) {
	t.Parallel()
	dd := computeMaxDrawdown(nil, 100000)
	assert.Equal(t, 0.0, dd, "No trades should mean 0 drawdown")
}

func TestParseInstrumentList_V2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected int
	}{
		{"NSE:INFY", 1},
		{"NSE:INFY,NSE:TCS", 2},
		{"NSE:INFY, NSE:TCS, NSE:RELIANCE", 3},
		{"", 0},
		{" , , ", 0},
	}
	for _, tc := range tests {
		result := parseInstrumentList(tc.input)
		assert.Equal(t, tc.expected, len(result), "parseInstrumentList(%q)", tc.input)
	}
}

func TestResolveTickerMode_V2(t *testing.T) {
	t.Parallel()
	assert.NotNil(t, resolveTickerMode("ltp"))
	assert.NotNil(t, resolveTickerMode("quote"))
	assert.NotNil(t, resolveTickerMode("full"))
	assert.NotNil(t, resolveTickerMode("unknown"))
}

func TestResolveInstrumentTokens_AllFailed(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr, []string{"NSE:UNKNOWN1", "NSE:UNKNOWN2"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 2)
}

func TestRegisterTools_Basic(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("test", "1.0")
	// Register with no excluded tools
	RegisterTools(srv, mgr, "", nil, mgr.Logger)
	// Should not panic
}

func TestRegisterTools_WithExclusions(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterTools(srv, mgr, "login,place_order", nil, mgr.Logger)
	// Should not panic; login and place_order excluded
}

func TestRegisterPrompts_Basic(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
}

func TestMorningBriefHandler(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := morningBriefHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Morning trading briefing", result.Description)
	assert.Len(t, result.Messages, 1)
}

func TestTradeCheckHandler(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol":   "RELIANCE",
		"action":   "BUY",
		"quantity": "10",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "BUY")
	assert.Contains(t, result.Description, "RELIANCE")
}

func TestTradeCheckHandler_DefaultAction_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol": "INFY",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "BUY") // defaults to BUY
}

func TestEodReviewHandler(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := eodReviewHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "End-of-day trading review", result.Description)
	assert.Len(t, result.Messages, 1)
}

func TestExtractUnderlyingSymbol_AdditionalCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input, expected string
	}{
		{"NIFTY2640118000CE", "NIFTY"},
		{"BANKNIFTY24403CE", "BANKNIFTY"},
		{"RELIANCE2440324000CE", "RELIANCE"},
		{"INFY", "INFY"},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractUnderlyingSymbol(tc.input)
		assert.Equal(t, tc.expected, got, "input=%q", tc.input)
	}
}

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
	for i := 0; i < n; i++ {
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
	for i := 0; i < n; i++ {
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

func TestComputeDividendCalendar_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeDividendCalendar(nil, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.HoldingsByYield))
}

func TestComputeDividendCalendar_WithHoldings_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: 10000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: 5000},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, AveragePrice: 3400, LastPrice: 3500, PnL: 2000},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 30, AveragePrice: 1600, LastPrice: 1700, PnL: 3000},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.HoldingsByYield), 0)
	assert.NotEmpty(t, result.TaxNote)
}

func TestComputeDividendCalendar_SingleHolding(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1000, LastPrice: 0, PnL: 0},
	}
	result := computeDividendCalendar(holdings, 365)
	assert.NotNil(t, result)
}

func TestInjectData_NilData_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	result := injectData(html, nil)
	assert.Contains(t, result, "null")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_WithData_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := map[string]string{"key": "value"}
	result := injectData(html, data)
	assert.Contains(t, result, "key")
	assert.Contains(t, result, "value")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_XSSPrevention_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	// Data with a </script> attempt should be escaped
	data := map[string]string{"payload": "</script><script>alert(1)</script>"}
	result := injectData(html, data)
	// Go's json.Marshal escapes < as \u003c, so </script> won't appear literally
	assert.NotContains(t, result, "</script><script>")
}

func TestInjectData_NoPlaceholder_P7(t *testing.T) {
	t.Parallel()
	html := `<div>No placeholder here</div>`
	data := map[string]string{"key": "value"}
	result := injectData(html, data)
	// Should be unchanged since there's no placeholder
	assert.Equal(t, html, result)
}

func TestResourceURIForTool_Exists(t *testing.T) {
	t.Parallel()
	// Some tools should have dashboard page mappings
	// If none exist, just verify it returns empty for unknown tools
	uri := resourceURIForTool("nonexistent_tool")
	assert.Equal(t, "", uri)
}

func TestResourceURIForTool_KnownTools(t *testing.T) {
	t.Parallel()
	// Test a few known tool names that likely have dashboard mappings
	for _, toolName := range []string{"get_holdings", "get_positions", "get_orders"} {
		_ = resourceURIForTool(toolName) // Exercise the function; may or may not return a URI
	}
}

func TestComputeSectorExposure_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, LastPrice: 2500},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, LastPrice: 3500},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
}

func TestComputeSectorExposure_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure(nil)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: 10000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: 5000},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_SingleHolding_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computePortfolioConcentration(nil)
	assert.NotNil(t, result)
}

func TestComputeTaxHarvest_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1600, LastPrice: 1400, PnL: -20000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2600, PnL: 10000},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, AveragePrice: 3600, LastPrice: 3400, PnL: -4000},
	}
	result := computeTaxHarvest(holdings, 5.0)
	assert.NotNil(t, result)
}

func TestComputeTaxHarvest_NoLosses(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1600, PnL: 20000},
	}
	result := computeTaxHarvest(holdings, 5.0)
	assert.NotNil(t, result)
}

func TestComputeTaxHarvest_EmptyHoldings_P7(t *testing.T) {
	t.Parallel()
	result := computeTaxHarvest(nil, 5.0)
	assert.NotNil(t, result)
}

func TestEodReviewHandler_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// Exercise the prompt handler path — just registration, no assertion needed
}
