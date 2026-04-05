package mcp

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/mock"
)

// ---------------------------------------------------------------------------
// Mock broker: read tool business logic
// These tests verify that the mock broker correctly returns configured data,
// which is what the tool handlers delegate to under the hood.
// ---------------------------------------------------------------------------

func TestMockBroker_GetHoldings(t *testing.T) {
	t.Run("returns configured holdings", func(t *testing.T) {
		client := mock.New()
		holdings := []broker.Holding{
			{
				Tradingsymbol: "RELIANCE",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  2400,
				LastPrice:     2500,
				PnL:           1000,
			},
			{
				Tradingsymbol: "INFY",
				Exchange:      "NSE",
				Quantity:      50,
				AveragePrice:  1500,
				LastPrice:     1800,
				PnL:           15000,
			},
		}
		client.SetHoldings(holdings)

		result, err := client.GetHoldings()
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "RELIANCE", result[0].Tradingsymbol)
		assert.Equal(t, 10, result[0].Quantity)
		assert.Equal(t, 2500.0, result[0].LastPrice)
		assert.Equal(t, "INFY", result[1].Tradingsymbol)
		assert.Equal(t, 50, result[1].Quantity)
	})

	t.Run("returns empty slice for no holdings", func(t *testing.T) {
		client := mock.New()
		// Don't set any holdings
		result, err := client.GetHoldings()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetHoldingsErr = assert.AnError
		result, err := client.GetHoldings()
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestMockBroker_GetPositions(t *testing.T) {
	t.Run("returns configured positions", func(t *testing.T) {
		client := mock.New()
		positions := broker.Positions{
			Day: []broker.Position{
				{
					Tradingsymbol: "RELIANCE",
					Exchange:      "NSE",
					Product:       "MIS",
					Quantity:      10,
					AveragePrice:  2400,
					LastPrice:     2450,
					PnL:           500,
				},
			},
			Net: []broker.Position{
				{
					Tradingsymbol: "INFY",
					Exchange:      "NSE",
					Product:       "CNC",
					Quantity:      -20,
					AveragePrice:  1500,
					LastPrice:     1480,
					PnL:           400,
				},
			},
		}
		client.SetPositions(positions)

		result, err := client.GetPositions()
		require.NoError(t, err)
		assert.Len(t, result.Day, 1)
		assert.Len(t, result.Net, 1)
		assert.Equal(t, "RELIANCE", result.Day[0].Tradingsymbol)
		assert.Equal(t, 10, result.Day[0].Quantity)
		assert.Equal(t, "INFY", result.Net[0].Tradingsymbol)
		assert.Equal(t, -20, result.Net[0].Quantity)
	})

	t.Run("returns empty positions", func(t *testing.T) {
		client := mock.New()
		result, err := client.GetPositions()
		require.NoError(t, err)
		assert.Empty(t, result.Day)
		assert.Empty(t, result.Net)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetPositionsErr = assert.AnError
		_, err := client.GetPositions()
		assert.Error(t, err)
	})
}

func TestMockBroker_GetMargins(t *testing.T) {
	t.Run("returns default margins", func(t *testing.T) {
		client := mock.New()
		result, err := client.GetMargins()
		require.NoError(t, err)
		assert.Equal(t, 1_00_00_000.0, result.Equity.Available)
		assert.Equal(t, 0.0, result.Equity.Used)
		assert.Equal(t, 1_00_00_000.0, result.Equity.Total)
	})

	t.Run("returns custom margins", func(t *testing.T) {
		client := mock.New()
		client.SetMargins(broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 50000,
				Used:      25000,
				Total:     75000,
			},
			Commodity: broker.SegmentMargin{
				Available: 10000,
				Used:      5000,
				Total:     15000,
			},
		})

		result, err := client.GetMargins()
		require.NoError(t, err)
		assert.Equal(t, 50000.0, result.Equity.Available)
		assert.Equal(t, 25000.0, result.Equity.Used)
		assert.Equal(t, 10000.0, result.Commodity.Available)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetMarginsErr = assert.AnError
		_, err := client.GetMargins()
		assert.Error(t, err)
	})
}

func TestMockBroker_GetProfile(t *testing.T) {
	t.Run("returns default profile", func(t *testing.T) {
		client := mock.New()
		result, err := client.GetProfile()
		require.NoError(t, err)
		assert.Equal(t, "MOCK01", result.UserID)
		assert.Equal(t, "Mock User", result.UserName)
		assert.Equal(t, "mock@example.com", result.Email)
		assert.Contains(t, result.Exchanges, "NSE")
		assert.Contains(t, result.Exchanges, "BSE")
	})

	t.Run("returns custom profile", func(t *testing.T) {
		client := mock.New()
		client.SetProfile(broker.Profile{
			UserID:    "TRADER01",
			UserName:  "Test Trader",
			Email:     "trader@example.com",
			Broker:    broker.Zerodha,
			Exchanges: []string{"NSE", "BSE", "NFO"},
			Products:  []string{"CNC", "MIS"},
		})

		result, err := client.GetProfile()
		require.NoError(t, err)
		assert.Equal(t, "TRADER01", result.UserID)
		assert.Equal(t, "Test Trader", result.UserName)
		assert.Equal(t, broker.Zerodha, result.Broker)
		assert.Len(t, result.Exchanges, 3)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetProfileErr = assert.AnError
		_, err := client.GetProfile()
		assert.Error(t, err)
	})
}

func TestMockBroker_GetOrders(t *testing.T) {
	t.Run("returns configured orders", func(t *testing.T) {
		client := mock.New()
		orders := []broker.Order{
			{
				OrderID:         "ORD001",
				Exchange:        "NSE",
				Tradingsymbol:   "RELIANCE",
				TransactionType: "BUY",
				OrderType:       "LIMIT",
				Quantity:        10,
				Price:           2400,
				Status:          "COMPLETE",
				FilledQuantity:  10,
				AveragePrice:    2399.5,
			},
		}
		client.SetOrders(orders)

		result, err := client.GetOrders()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "ORD001", result[0].OrderID)
		assert.Equal(t, "COMPLETE", result[0].Status)
		assert.Equal(t, 10, result[0].FilledQuantity)
	})

	t.Run("returns empty orders", func(t *testing.T) {
		client := mock.New()
		result, err := client.GetOrders()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetOrdersErr = assert.AnError
		result, err := client.GetOrders()
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestMockBroker_GetTrades(t *testing.T) {
	t.Run("returns configured trades", func(t *testing.T) {
		client := mock.New()
		trades := []broker.Trade{
			{
				TradeID:         "TRD001",
				OrderID:         "ORD001",
				Exchange:        "NSE",
				Tradingsymbol:   "INFY",
				TransactionType: "BUY",
				Quantity:        50,
				Price:           1500,
				Product:         "CNC",
			},
		}
		client.SetTrades(trades)

		result, err := client.GetTrades()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "TRD001", result[0].TradeID)
		assert.Equal(t, 50, result[0].Quantity)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.GetTradesErr = assert.AnError
		result, err := client.GetTrades()
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestMockBroker_PlaceOrder(t *testing.T) {
	t.Run("MARKET order fills immediately", func(t *testing.T) {
		client := mock.New()
		client.SetPrices(map[string]float64{
			"NSE:RELIANCE": 2500.0,
		})

		resp, err := client.PlaceOrder(broker.OrderParams{
			Exchange:        "NSE",
			Tradingsymbol:   "RELIANCE",
			TransactionType: "BUY",
			OrderType:       "MARKET",
			Product:         "CNC",
			Quantity:        10,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.OrderID)

		// Verify the order was filled
		orders := client.Orders()
		assert.Len(t, orders, 1)
		assert.Equal(t, "COMPLETE", orders[0].Status)
		assert.Equal(t, 10, orders[0].FilledQuantity)
		assert.Equal(t, 2500.0, orders[0].AveragePrice)

		// Verify a trade was created
		trades := client.Trades()
		assert.Len(t, trades, 1)
		assert.Equal(t, resp.OrderID, trades[0].OrderID)
		assert.Equal(t, 2500.0, trades[0].Price)
	})

	t.Run("LIMIT order stays open", func(t *testing.T) {
		client := mock.New()

		resp, err := client.PlaceOrder(broker.OrderParams{
			Exchange:        "NSE",
			Tradingsymbol:   "INFY",
			TransactionType: "BUY",
			OrderType:       "LIMIT",
			Product:         "CNC",
			Quantity:        50,
			Price:           1500,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.OrderID)

		orders := client.Orders()
		assert.Len(t, orders, 1)
		assert.Equal(t, "OPEN", orders[0].Status)
		assert.Equal(t, 0, orders[0].FilledQuantity)
	})

	t.Run("handles broker error", func(t *testing.T) {
		client := mock.New()
		client.PlaceOrderErr = assert.AnError
		_, err := client.PlaceOrder(broker.OrderParams{
			Exchange:      "NSE",
			Tradingsymbol: "INFY",
			OrderType:     "MARKET",
			Quantity:      1,
		})
		assert.Error(t, err)
	})
}

func TestMockBroker_CancelOrder(t *testing.T) {
	t.Run("cancels open order", func(t *testing.T) {
		client := mock.New()

		resp, err := client.PlaceOrder(broker.OrderParams{
			Exchange:      "NSE",
			Tradingsymbol: "INFY",
			OrderType:     "LIMIT",
			Quantity:      10,
			Price:         1500,
		})
		require.NoError(t, err)

		_, err = client.CancelOrder(resp.OrderID)
		require.NoError(t, err)

		orders := client.Orders()
		assert.Equal(t, "CANCELLED", orders[0].Status)
	})

	t.Run("cannot cancel completed order", func(t *testing.T) {
		client := mock.New()
		client.SetPrices(map[string]float64{"NSE:INFY": 1500})

		resp, err := client.PlaceOrder(broker.OrderParams{
			Exchange:      "NSE",
			Tradingsymbol: "INFY",
			OrderType:     "MARKET",
			Quantity:      10,
		})
		require.NoError(t, err)

		_, err = client.CancelOrder(resp.OrderID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "COMPLETE")
	})
}

func TestMockBroker_GetHistoricalData(t *testing.T) {
	t.Run("generates daily candles", func(t *testing.T) {
		client := mock.New()
		from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		to := time.Date(2025, 1, 31, 0, 0, 0, 0, time.UTC)

		candles, err := client.GetHistoricalData(256265, "day", from, to)
		require.NoError(t, err)
		assert.Greater(t, len(candles), 20, "should generate ~31 daily candles")

		// Verify candle structure
		for _, c := range candles {
			assert.True(t, c.High >= c.Open, "high >= open")
			assert.True(t, c.High >= c.Close, "high >= close")
			assert.True(t, c.Low <= c.Open, "low <= open")
			assert.True(t, c.Low <= c.Close, "low <= close")
			assert.Greater(t, c.Volume, 0, "volume > 0")
		}
	})

	t.Run("handles error injection", func(t *testing.T) {
		client := mock.New()
		client.GetHistoricalErr = assert.AnError
		_, err := client.GetHistoricalData(256265, "day", time.Now(), time.Now())
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Tool definitions: verify metadata and annotations
// ---------------------------------------------------------------------------

func TestReadToolDefinitions(t *testing.T) {
	readTools := []struct {
		tool     Tool
		name     string
		readOnly bool
	}{
		{&ProfileTool{}, "get_profile", true},
		{&MarginsTool{}, "get_margins", true},
		{&HoldingsTool{}, "get_holdings", true},
		{&PositionsTool{}, "get_positions", true},
		{&TradesTool{}, "get_trades", true},
		{&OrdersTool{}, "get_orders", true},
		{&OrderHistoryTool{}, "get_order_history", true},
	}

	for _, tc := range readTools {
		t.Run(tc.name, func(t *testing.T) {
			tool := tc.tool.Tool()
			assert.Equal(t, tc.name, tool.Name)
			assert.NotEmpty(t, tool.Description)

			// All read tools should be annotated as read-only
			require.NotNil(t, tool.Annotations.ReadOnlyHint)
			assert.True(t, *tool.Annotations.ReadOnlyHint,
				"tool %s should be read-only", tc.name)

			// Read tools should NOT be in the writeTools set
			assert.False(t, writeTools[tc.name],
				"read tool %s should not be in writeTools", tc.name)
		})
	}
}

func TestWriteToolDefinitions(t *testing.T) {
	writeToolDefs := []struct {
		tool Tool
		name string
	}{
		{&PlaceOrderTool{}, "place_order"},
		{&ModifyOrderTool{}, "modify_order"},
		{&CancelOrderTool{}, "cancel_order"},
	}

	for _, tc := range writeToolDefs {
		t.Run(tc.name, func(t *testing.T) {
			tool := tc.tool.Tool()
			assert.Equal(t, tc.name, tool.Name)
			assert.NotEmpty(t, tool.Description)

			// Write tools should be in writeTools set
			assert.True(t, writeTools[tc.name],
				"tool %s should be in writeTools", tc.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Backtest engine: pure function tests with mock data
// ---------------------------------------------------------------------------

func TestRunBacktest_SMACrossover(t *testing.T) {
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

func TestExtractUnderlyingSymbol(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"NIFTY2440324000CE", "NIFTY"},
		{"BANKNIFTY24403CE", "BANKNIFTY"},
		{"RELIANCE2440324000CE", "RELIANCE"},
		{"RELIANCE2440324000PE", "RELIANCE"},
		{"SBIN25APR600CE", "SBIN"},
		{"NIFTY", "NIFTY"}, // no digits
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := extractUnderlyingSymbol(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBacktestDefaults(t *testing.T) {
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

func TestMockBroker_GetLTP(t *testing.T) {
	t.Run("returns configured prices", func(t *testing.T) {
		client := mock.New()
		client.SetPrices(map[string]float64{
			"NSE:RELIANCE": 2500.0,
			"NSE:INFY":     1800.0,
		})

		result, err := client.GetLTP("NSE:RELIANCE", "NSE:INFY")
		require.NoError(t, err)
		assert.Equal(t, 2500.0, result["NSE:RELIANCE"].LastPrice)
		assert.Equal(t, 1800.0, result["NSE:INFY"].LastPrice)
	})

	t.Run("missing instrument returns empty", func(t *testing.T) {
		client := mock.New()
		result, err := client.GetLTP("NSE:UNKNOWN")
		require.NoError(t, err)
		_, exists := result["NSE:UNKNOWN"]
		assert.False(t, exists)
	})
}

func TestMockBroker_GetOHLC(t *testing.T) {
	t.Run("returns configured OHLC", func(t *testing.T) {
		client := mock.New()
		client.SetOHLC(map[string]broker.OHLC{
			"NSE:RELIANCE": {
				Open:      2400,
				High:      2550,
				Low:       2380,
				Close:     2500,
				LastPrice: 2500,
			},
		})

		result, err := client.GetOHLC("NSE:RELIANCE")
		require.NoError(t, err)
		assert.Equal(t, 2400.0, result["NSE:RELIANCE"].Open)
		assert.Equal(t, 2550.0, result["NSE:RELIANCE"].High)
		assert.Equal(t, 2500.0, result["NSE:RELIANCE"].LastPrice)
	})
}

// ---------------------------------------------------------------------------
// Backtest signal generation tests
// ---------------------------------------------------------------------------

func TestGenerateSignals_SMACrossover(t *testing.T) {
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
