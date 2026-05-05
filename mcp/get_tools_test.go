package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-broker/mock"
	"github.com/zerodha/kite-mcp-server/kc/money"
	"github.com/zerodha/kite-mcp-server/mcp/portfolio"
	"github.com/zerodha/kite-mcp-server/mcp/trade"
)

// ---------------------------------------------------------------------------
// Mock broker: read tool business logic
// These tests verify that the mock broker correctly returns configured data,
// which is what the tool handlers delegate to under the hood.
// ---------------------------------------------------------------------------

func TestMockBroker_GetHoldings(t *testing.T) {
	t.Parallel()
	t.Run("returns configured holdings", func(t *testing.T) {
		client := mock.New()
		holdings := []broker.Holding{
			{
				Tradingsymbol: "RELIANCE",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  2400,
				LastPrice:     2500,
				PnL: money.NewINR(1000),
			},
			{
				Tradingsymbol: "INFY",
				Exchange:      "NSE",
				Quantity:      50,
				AveragePrice:  1500,
				LastPrice:     1800,
				PnL: money.NewINR(15000),
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
	t.Parallel()
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
					PnL: money.NewINR(500),
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
					PnL: money.NewINR(400),
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

		_, err = client.CancelOrder(resp.OrderID, "regular")
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

		_, err = client.CancelOrder(resp.OrderID, "regular")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "COMPLETE")
	})
}

func TestMockBroker_GetHistoricalData(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	readTools := []struct {
		tool     Tool
		name     string
		readOnly bool
	}{
		{&portfolio.ProfileTool{}, "get_profile", true},
		{&portfolio.MarginsTool{}, "get_margins", true},
		{&portfolio.HoldingsTool{}, "get_holdings", true},
		{&portfolio.PositionsTool{}, "get_positions", true},
		{&portfolio.TradesTool{}, "get_trades", true},
		{&portfolio.OrdersTool{}, "get_orders", true},
		{&portfolio.OrderHistoryTool{}, "get_order_history", true},
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

			// Read tools should NOT be in the WriteToolsSnapshot() set
			assert.False(t, isWriteTool(tc.name),
				"read tool %s should not be in WriteToolsSnapshot()", tc.name)
		})
	}
}

func TestWriteToolDefinitions(t *testing.T) {
	t.Parallel()
	writeToolDefs := []struct {
		tool Tool
		name string
	}{
		{&trade.PlaceOrderTool{}, "place_order"},
		{&trade.ModifyOrderTool{}, "modify_order"},
		{&trade.CancelOrderTool{}, "cancel_order"},
	}

	for _, tc := range writeToolDefs {
		t.Run(tc.name, func(t *testing.T) {
			tool := tc.tool.Tool()
			assert.Equal(t, tc.name, tool.Name)
			assert.NotEmpty(t, tool.Description)

			// Write tools should be in WriteToolsSnapshot() set
			assert.True(t, isWriteTool(tc.name),
				"tool %s should be in WriteToolsSnapshot()", tc.name)
		})
	}
}

// Anchor 1 PR 1.7: backtest-internals tests (TestRunBacktest_*, TestComputeMaxDrawdown,
// TestComputeSharpeRatio, TestBacktestDefaults, TestGenerateSignals_SMACrossover,
// TestSimulateTrades_ForcesCloseAtEnd) moved to mcp/analytics/get_tools_backtest_test.go
// because they reference unexported analytics-package symbols (runBacktest,
// computeMaxDrawdown, computeSharpeRatio, BacktestTrade, generateSignals,
// simulateTrades, backtestDefaults, backtestSignal).

func TestExtractUnderlyingSymbol(t *testing.T) {
	t.Parallel()
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
			result := trade.ExtractUnderlyingSymbol(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMockBroker_GetLTP(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

