package usecases

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// Shared mocks (mockBrokerResolver, mockBrokerClient, mockAlertStore,
// mockInstrumentResolver) and test helpers (testLogger, testPlaceCmd) now
// live in mocks_test.go.

// --- PlaceOrderUseCase tests ---


// --- GetOrdersUseCase tests ---
func TestGetOrders_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		orders: []broker.Order{
			{OrderID: "ORD-1", Tradingsymbol: "RELIANCE", Status: "COMPLETE"},
			{OrderID: "ORD-2", Tradingsymbol: "INFY", Status: "OPEN"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrdersUseCase(resolver, testLogger())

	orders, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Len(t, orders, 2)
	assert.Equal(t, "ORD-1", orders[0].OrderID)
}


func TestGetOrders_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetOrdersUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetOrders_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOrdersUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetProfileUseCase tests ---
func TestGetProfile_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		profile: broker.Profile{
			UserID:    "AB1234",
			UserName:  "Test User",
			Email:     "test@test.com",
			Broker:    "kite",
			Exchanges: []string{"NSE", "BSE"},
			Products:  []string{"CNC", "MIS"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetProfileUseCase(resolver, testLogger())

	profile, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "test@test.com"})

	require.NoError(t, err)
	assert.Equal(t, "AB1234", profile.UserID)
	assert.Equal(t, "Test User", profile.UserName)
	assert.Equal(t, "test@test.com", profile.Email)
	assert.Equal(t, []string{"NSE", "BSE"}, profile.Exchanges)
}


func TestGetProfile_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetProfileUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetProfile_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		profileErr: fmt.Errorf("token expired"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetProfileUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}


func TestGetProfile_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetProfileUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetMarginsUseCase tests ---
func TestGetMargins_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		margins: broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 100000.0,
				Used:      25000.0,
				Total:     125000.0,
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetMarginsUseCase(resolver, testLogger())

	margins, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "test@test.com"})

	require.NoError(t, err)
	assert.Equal(t, 100000.0, margins.Equity.Available)
	assert.Equal(t, 25000.0, margins.Equity.Used)
	assert.Equal(t, 125000.0, margins.Equity.Total)
}


func TestGetMargins_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMarginsUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetMargins_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		marginsErr: fmt.Errorf("service unavailable"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetMarginsUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service unavailable")
}


func TestGetMargins_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetMarginsUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetTradesUseCase tests ---
func TestGetTrades_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		trades: []broker.Trade{
			{TradeID: "T1", OrderID: "ORD-1", Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY", Quantity: 10, Price: 2500.0, Product: "CNC"},
			{TradeID: "T2", OrderID: "ORD-2", Exchange: "NSE", Tradingsymbol: "INFY", TransactionType: "SELL", Quantity: 5, Price: 1400.0, Product: "MIS"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetTradesUseCase(resolver, testLogger())

	trades, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{Email: "test@test.com"})

	require.NoError(t, err)
	assert.Len(t, trades, 2)
	assert.Equal(t, "T1", trades[0].TradeID)
	assert.Equal(t, "RELIANCE", trades[0].Tradingsymbol)
	assert.Equal(t, "SELL", trades[1].TransactionType)
}


func TestGetTrades_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetTradesUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetTrades_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		tradesErr: fmt.Errorf("API rate limited"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetTradesUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API rate limited")
}


func TestGetTrades_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetTradesUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetOrderHistoryUseCase tests ---
func TestGetOrderHistory_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		orderHistory: []broker.Order{
			{OrderID: "ORD-1", Tradingsymbol: "RELIANCE", Status: "OPEN"},
			{OrderID: "ORD-1", Tradingsymbol: "RELIANCE", Status: "COMPLETE"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrderHistoryUseCase(resolver, testLogger())

	history, err := uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{
		Email: "test@test.com", OrderID: "ORD-1",
	})

	require.NoError(t, err)
	assert.Len(t, history, 2)
	assert.Equal(t, "OPEN", history[0].Status)
	assert.Equal(t, "COMPLETE", history[1].Status)
}


func TestGetOrderHistory_ValidationFailures(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderHistoryUseCase(nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{OrderID: "ORD-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	_, err = uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order_id is required")
}


func TestGetOrderHistory_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		orderHistoryErr: fmt.Errorf("order not found"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrderHistoryUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{
		Email: "test@test.com", OrderID: "ORD-999",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order not found")
}


func TestGetOrderHistory_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOrderHistoryUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{
		Email: "test@test.com", OrderID: "ORD-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetLTPUseCase tests ---
func TestGetLTP_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{
			"NSE:RELIANCE": {LastPrice: 2500.50},
			"NSE:INFY":     {LastPrice: 1400.25},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetLTPUseCase(resolver, testLogger())

	ltp, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetLTPQuery{
		Instruments: []string{"NSE:RELIANCE", "NSE:INFY"},
	})

	require.NoError(t, err)
	assert.Len(t, ltp, 2)
	assert.Equal(t, 2500.50, ltp["NSE:RELIANCE"].LastPrice)
	assert.Equal(t, 1400.25, ltp["NSE:INFY"].LastPrice)
}


func TestGetLTP_EmptyInstruments(t *testing.T) {
	t.Parallel()
	uc := NewGetLTPUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetLTPQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one instrument is required")
}


func TestGetLTP_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ltpErr: fmt.Errorf("invalid instrument"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetLTPUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetLTPQuery{
		Instruments: []string{"NSE:INVALID"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid instrument")
}


func TestGetLTP_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetLTPUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetLTPQuery{
		Instruments: []string{"NSE:RELIANCE"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetOHLCUseCase tests ---
func TestGetOHLC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ohlcMap: map[string]broker.OHLC{
			"NSE:RELIANCE": {Open: 2480, High: 2520, Low: 2470, Close: 2500, LastPrice: 2505},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOHLCUseCase(resolver, testLogger())

	ohlc, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetOHLCQuery{
		Instruments: []string{"NSE:RELIANCE"},
	})

	require.NoError(t, err)
	assert.Len(t, ohlc, 1)
	assert.Equal(t, 2480.0, ohlc["NSE:RELIANCE"].Open)
	assert.Equal(t, 2520.0, ohlc["NSE:RELIANCE"].High)
	assert.Equal(t, 2470.0, ohlc["NSE:RELIANCE"].Low)
	assert.Equal(t, 2500.0, ohlc["NSE:RELIANCE"].Close)
	assert.Equal(t, 2505.0, ohlc["NSE:RELIANCE"].LastPrice)
}


func TestGetOHLC_EmptyInstruments(t *testing.T) {
	t.Parallel()
	uc := NewGetOHLCUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetOHLCQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one instrument is required")
}


func TestGetOHLC_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ohlcErr: fmt.Errorf("service down"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOHLCUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetOHLCQuery{
		Instruments: []string{"NSE:RELIANCE"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service down")
}


func TestGetOHLC_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOHLCUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetOHLCQuery{
		Instruments: []string{"NSE:RELIANCE"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetHistoricalDataUseCase tests ---
func TestGetHistoricalData_Success(t *testing.T) {
	t.Parallel()
	now := time.Now()
	from := now.Add(-24 * time.Hour)
	client := &mockBrokerClient{
		historicalData: []broker.HistoricalCandle{
			{Date: from, Open: 2480, High: 2520, Low: 2470, Close: 2500, Volume: 100000},
			{Date: now, Open: 2500, High: 2550, Low: 2490, Close: 2530, Volume: 120000},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetHistoricalDataUseCase(resolver, testLogger())

	candles, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetHistoricalDataQuery{
		InstrumentToken: 738561,
		Interval:        "day",
		From:            from,
		To:              now,
	})

	require.NoError(t, err)
	assert.Len(t, candles, 2)
	assert.Equal(t, 2480.0, candles[0].Open)
	assert.Equal(t, 100000, candles[0].Volume)
	assert.Equal(t, 2530.0, candles[1].Close)
}


func TestGetHistoricalData_ValidationFailures(t *testing.T) {
	t.Parallel()
	uc := NewGetHistoricalDataUseCase(nil, testLogger())
	now := time.Now()
	from := now.Add(-24 * time.Hour)

	tests := []struct {
		name  string
		query cqrs.GetHistoricalDataQuery
		want  string
	}{
		{
			name:  "zero instrument token",
			query: cqrs.GetHistoricalDataQuery{Interval: "day", From: from, To: now},
			want:  "instrument_token is required",
		},
		{
			name:  "empty interval",
			query: cqrs.GetHistoricalDataQuery{InstrumentToken: 738561, From: from, To: now},
			want:  "interval is required",
		},
		{
			name:  "zero from date",
			query: cqrs.GetHistoricalDataQuery{InstrumentToken: 738561, Interval: "day", To: now},
			want:  "from and to dates are required",
		},
		{
			name:  "zero to date",
			query: cqrs.GetHistoricalDataQuery{InstrumentToken: 738561, Interval: "day", From: from},
			want:  "from and to dates are required",
		},
		{
			name:  "from after to",
			query: cqrs.GetHistoricalDataQuery{InstrumentToken: 738561, Interval: "day", From: now, To: from},
			want:  "from must be before to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), "test@test.com", tt.query)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}


func TestGetHistoricalData_BrokerError(t *testing.T) {
	t.Parallel()
	now := time.Now()
	from := now.Add(-24 * time.Hour)
	client := &mockBrokerClient{
		historicalErr: fmt.Errorf("too many candles requested"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetHistoricalDataUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetHistoricalDataQuery{
		InstrumentToken: 738561,
		Interval:        "day",
		From:            from,
		To:              now,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many candles requested")
}


func TestGetHistoricalData_ResolveError(t *testing.T) {
	t.Parallel()
	now := time.Now()
	from := now.Add(-24 * time.Hour)
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetHistoricalDataUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetHistoricalDataQuery{
		InstrumentToken: 738561,
		Interval:        "day",
		From:            from,
		To:              now,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- GetQuotesUseCase tests ---
func TestGetQuotes_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		quotesMap: map[string]broker.Quote{
			"NSE:RELIANCE": {LastPrice: 2500.0, Volume: 100000},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetQuotesUseCase(resolver, testLogger())

	quotes, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetQuotesQuery{
		Instruments: []string{"NSE:RELIANCE"},
	})
	require.NoError(t, err)
	assert.Len(t, quotes, 1)
	assert.Equal(t, 2500.0, quotes["NSE:RELIANCE"].LastPrice)
}


func TestGetQuotes_EmptyInstruments(t *testing.T) {
	t.Parallel()
	uc := NewGetQuotesUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetQuotesQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one instrument")
}


func TestGetQuotes_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetQuotesUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetQuotesQuery{
		Instruments: []string{"NSE:INFY"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestGetQuotes_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{quotesErr: fmt.Errorf("rate limited")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetQuotesUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetQuotesQuery{
		Instruments: []string{"NSE:INFY"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get quotes")
}


// --- GetOrderTradesUseCase tests ---
func TestGetOrderTrades_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		orderTrades: []broker.Trade{
			{TradeID: "T1", OrderID: "ORD-1", Tradingsymbol: "INFY", Quantity: 10, Price: 1500.0},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrderTradesUseCase(resolver, testLogger())

	trades, err := uc.Execute(context.Background(), cqrs.GetOrderTradesQuery{
		Email:   "test@test.com",
		OrderID: "ORD-1",
	})
	require.NoError(t, err)
	assert.Len(t, trades, 1)
	assert.Equal(t, "T1", trades[0].TradeID)
	assert.Equal(t, "ORD-1", client.lastOrderTradesID)
}


func TestGetOrderTrades_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderTradesUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderTradesQuery{OrderID: "ORD-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetOrderTrades_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderTradesUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderTradesQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order_id is required")
}


func TestGetOrderTrades_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOrderTradesUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderTradesQuery{
		Email: "test@test.com", OrderID: "ORD-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestGetOrderTrades_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{orderTradesErr: fmt.Errorf("not found")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrderTradesUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderTradesQuery{
		Email: "test@test.com", OrderID: "ORD-999",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get order trades")
}


// --- GetGTTsUseCase tests ---
func TestGetGTTs_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		gtts: []broker.GTTOrder{
			{ID: 1, Type: "single", Status: "active"},
			{ID: 2, Type: "two-leg", Status: "active"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetGTTsUseCase(resolver, testLogger())

	gtts, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Len(t, gtts, 2)
	assert.Equal(t, 1, gtts[0].ID)
}


func TestGetGTTs_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetGTTsUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetGTTs_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetGTTsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestGetGTTs_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{gttsErr: fmt.Errorf("api error")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetGTTsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get gtts")
}


func TestGetOrders_GetOrdersError(t *testing.T) {
	t.Parallel()
	client := &ordersErrClient{}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrdersUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get orders")
}
