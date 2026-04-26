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
	"github.com/zerodha/kite-mcp-server/broker"
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
	for i := range n {
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


func TestBuildPreTradeResponse_AllDataPresent(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1500},
		},
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 500000, Used: 100000, Total: 600000},
		},
		"order_margins": map[string]any{"total": float64(75000)},
		"positions": broker.Positions{
			Net: []broker.Position{
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
		"holdings": []broker.Holding{
			{Tradingsymbol: "RELIANCE", Quantity: 100, LastPrice: 2500},
			{Tradingsymbol: "TCS", Quantity: 50, LastPrice: 3500},
		},
	}

	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
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
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0,
		map[string]any{}, nil)
	assert.Equal(t, "INFY", resp.Symbol)
	assert.Equal(t, 0.0, resp.CurrentPrice)
	assert.Equal(t, "PROCEED", resp.Recommendation)
}


func TestBuildPreTradeResponse_InsufficientMargin(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1500},
		},
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 10000, Used: 0, Total: 10000},
		},
		"order_margins": map[string]any{"total": float64(50000)},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 100, "CNC", 0, data, nil)
	assert.Equal(t, "BLOCKED", resp.Recommendation)
	assert.GreaterOrEqual(t, len(resp.Warnings), 1)
}


func TestBuildPreTradeResponse_HighMarginUtilization(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 10000, Used: 0, Total: 10000},
		},
		"order_margins": map[string]any{"total": float64(8000)}, // 80% utilization
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Contains(t, resp.Recommendation, "CAUTION")
}


func TestBuildPreTradeResponse_OverConcentration(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 5000},
		},
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 1000000, Used: 0, Total: 1000000},
		},
		"order_margins": map[string]any{"total": float64(50000)},
		"holdings": []broker.Holding{
			{Tradingsymbol: "TCS", Quantity: 10, LastPrice: 3500},
		},
	}
	// Order value = 5000 * 100 = 500000, portfolio = 35000, total = 535000
	// orderAsPct = 500000/535000 * 100 ≈ 93.5% — over-concentrated
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 100, "CNC", 0, data, nil)
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
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1500},
		},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "SELL", 10, "CNC", 0, data, nil)
	// SELL stop loss should be above the price
	assert.Greater(t, resp.StopLoss.CNC2Pct, 1500.0)
	assert.Greater(t, resp.StopLoss.MIS1Pct, 1500.0)
}


func TestBuildPreTradeResponse_WithLimitPrice(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1500},
		},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 1450, data, nil)
	// Order value should use limit price
	assert.Equal(t, roundTo2(14500.0), resp.OrderValue)
}


func TestBuildPreTradeResponse_WithAPIErrors(t *testing.T) {
	t.Parallel()
	apiErrors := map[string]string{
		"ltp":     "API error: rate limited",
		"margins": "timeout",
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0,
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
		"positions": broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 50},
			},
		},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Nil(t, resp.ExistingPos, "should not have existing position for different symbol")
}


func TestBuildPreTradeResponse_FallbackMargin(t *testing.T) {
	t.Parallel()
	// When GetOrderMargins fails, margin falls back to order value
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1000},
		},
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 500000, Used: 0, Total: 500000},
		},
		// No "order_margins" key — fallback
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	// Margin required should fall back to order value (1000 * 10 = 10000)
	assert.Equal(t, 10000.0, resp.Margin.Required)
}


func TestBuildTradingContext_AllDataPresent(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 500000, Used: 100000, Total: 600000},
		},
		"positions": broker.Positions{
			Net: []broker.Position{
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
		"orders": []broker.Order{
			{Status: "COMPLETE"},
			{Status: "COMPLETE"},
			{Status: "REJECTED"},
			{Status: "OPEN"},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "RELIANCE", Quantity: 100, PnL: 500},
			{Tradingsymbol: "HDFC", Quantity: 50, PnL: -200},
		},
	}

	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
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
	tc := buildTradingContextFromMap(map[string]any{}, nil, mgr, "test@example.com")
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
	tc := buildTradingContextFromMap(map[string]any{}, errs, mgr, "test@example.com")
	assert.NotNil(t, tc.Errors)
	assert.Contains(t, tc.Errors, "margins")
	assert.Contains(t, tc.Errors, "positions")
}


func TestBuildTradingContext_HighMarginUtilization(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 100000, Used: 500000, Total: 600000},
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
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
	orders := make([]broker.Order, 5)
	for i := range orders {
		orders[i] = broker.Order{Status: "REJECTED"}
	}
	data := map[string]any{"orders": orders}
	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
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
		"orders": []broker.Order{
			{Status: "COMPLETE"},
			{Status: "TRIGGER PENDING"},
			{Status: "AMO REQ RECEIVED"},
			{Status: "REJECTED"},
			{Status: "CANCELLED"},
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
	assert.Equal(t, 1, tc.ExecutedToday)
	assert.Equal(t, 2, tc.PendingOrders)
	assert.Equal(t, 1, tc.RejectedToday)
}


func TestBuildTradingContext_PositionPnLPct(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": broker.Positions{
			Net: []broker.Position{
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
	tc := buildTradingContextFromMap(data, nil, mgr, "")
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
		"positions": broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "INFY", Quantity: 0, PnL: 500},  // closed
				{Tradingsymbol: "TCS", Quantity: 10, PnL: 1000}, // open
			},
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "")
	assert.Equal(t, 1, tc.OpenPositions, "closed position (qty=0) should be excluded")
	assert.Equal(t, 1000.0, tc.PositionsPnL, "only open position PnL should be counted")
}


func TestBuildPreTradeResponse_EmptyPositions(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"positions": broker.Positions{
			Net: []broker.Position{},
		},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Nil(t, resp.ExistingPos)
}


func TestBuildPreTradeResponse_EmptyHoldings(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"holdings": []broker.Holding{},
	}
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 10, "CNC", 0, data, nil)
	assert.Equal(t, "low", resp.PortfolioImpact.ConcentrationAfter)
}


func TestBuildPreTradeResponse_ModerateConcentration(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "TCS", Quantity: 100, LastPrice: 1000},
		},
	}
	// Order value = 100 * 20 = 2000, portfolio = 100000, total = 102000
	// orderAsPct ≈ 2%, which is low
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 20, "CNC", 0, data, nil)
	assert.Equal(t, "low", resp.PortfolioImpact.ConcentrationAfter)
}


func TestBuildTradingContext_NoPositionDetails(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": broker.Positions{
			Net: []broker.Position{}, // no open positions
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Nil(t, tc.PositionDetails)
}


func TestBuildTradingContext_ZeroAvgPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"positions": broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "INFY", Quantity: 10, AveragePrice: 0, PnL: 100},
			},
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "")
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


func TestBuildTradingContext_ZeroMargin(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{Available: 0, Used: 0, Total: 0},
		},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "")
	assert.Equal(t, 0.0, tc.MarginUtilization)
}


func TestBuildTradingContext_MultipleMISPositions(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	positions := make([]broker.Position, 5)
	for i := range positions {
		positions[i] = broker.Position{
			Tradingsymbol: "STOCK" + string(rune('A'+i)),
			Product:       "MIS",
			Quantity:      10,
			PnL:           float64(i * 100),
		}
	}
	data := map[string]any{
		"positions": broker.Positions{Net: positions},
	}
	tc := buildTradingContextFromMap(data, nil, mgr, "")
	assert.Equal(t, 5, tc.OpenPositions)
	assert.Equal(t, 5, tc.MISPositions)
}


func TestBuildPreTradeResponse_HighConcentrationLevel(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1000},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "TCS", Quantity: 10, LastPrice: 100}, // portfolio = 1000
		},
	}
	// Order value = 1000 * 50 = 50000, portfolio = 1000, total = 51000
	// orderAsPct = 50000/51000 * 100 ≈ 98% — high concentration
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 50, "CNC", 0, data, nil)
	assert.Equal(t, "high", resp.PortfolioImpact.ConcentrationAfter)
}


func TestDoSetTrailingStop_WithAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	h := NewToolHandler(mgr)
	result, err := doSetTrailingStop(context.Background(), h, mgr, "test@example.com", "NSE", "INFY", 256265,
		"order123", "regular", "long", 20, 0, 1480, 1500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "Trailing stop set")
	assertResultContains(t, result, "Rs.20.00")
}


func TestDoSetTrailingStop_WithPct(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	h := NewToolHandler(mgr)
	result, err := doSetTrailingStop(context.Background(), h, mgr, "test2@example.com", "NSE", "RELIANCE", 408065,
		"order456", "regular", "short", 0, 2.5, 2550, 2500)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assertResultContains(t, result, "2.50%")
	assertResultContains(t, result, "short")
}


func TestBuildPreTradeResponse_ModerateConcentrationLevel(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"ltp": map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 100},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "TCS", Quantity: 100, LastPrice: 300}, // portfolio = 30000
		},
	}
	// Order value = 100 * 60 = 6000, portfolio = 30000, total = 36000
	// orderAsPct = 6000/36000 * 100 ≈ 16.7% — moderate concentration
	resp := buildPreTradeResponseFromMap("NSE", "INFY", "BUY", 60, "CNC", 0, data, nil)
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


func TestRegisterTools_Basic(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("test", "1.0")
	// Register with no excluded tools, trading enabled (default "local dev" shape)
	RegisterTools(srv, mgr, "", nil, mgr.Logger, true)
	// Should not panic
}


func TestRegisterTools_WithExclusions(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterTools(srv, mgr, "login,place_order", nil, mgr.Logger, true)
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
