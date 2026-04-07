package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// --- Mock implementations ---

// mockBrokerResolver resolves a mock broker client.
type mockBrokerResolver struct {
	client    broker.Client
	resolveErr error
}

func (m *mockBrokerResolver) GetBrokerForEmail(email string) (broker.Client, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	return m.client, nil
}

// mockBrokerClient is a minimal in-memory broker for testing.
type mockBrokerClient struct {
	placedOrders []broker.OrderParams
	orders       []broker.Order
	holdings     []broker.Holding
	positions    broker.Positions
	placeErr     error

	// Configurable return values for all broker methods.
	profile        broker.Profile
	profileErr     error
	margins        broker.Margins
	marginsErr     error
	trades         []broker.Trade
	tradesErr      error
	orderHistory   []broker.Order
	orderHistoryErr error
	positionsErr   error
	ltpMap         map[string]broker.LTP
	ltpErr         error
	ohlcMap        map[string]broker.OHLC
	ohlcErr        error
	historicalData []broker.HistoricalCandle
	historicalErr  error
	modifyResp     broker.OrderResponse
	modifyErr      error
	cancelResp     broker.OrderResponse
	cancelErr      error

	// Capture arguments for assertions.
	lastModifyOrderID string
	lastModifyParams  broker.OrderParams
	lastCancelOrderID string
	lastCancelVariety string
}

func (m *mockBrokerClient) BrokerName() broker.Name { return "mock" }
func (m *mockBrokerClient) GetProfile() (broker.Profile, error) {
	return m.profile, m.profileErr
}
func (m *mockBrokerClient) GetMargins() (broker.Margins, error) {
	return m.margins, m.marginsErr
}
func (m *mockBrokerClient) GetHoldings() ([]broker.Holding, error) { return m.holdings, nil }
func (m *mockBrokerClient) GetPositions() (broker.Positions, error) {
	if m.positionsErr != nil {
		return broker.Positions{}, m.positionsErr
	}
	return m.positions, nil
}
func (m *mockBrokerClient) GetOrders() ([]broker.Order, error) { return m.orders, nil }
func (m *mockBrokerClient) GetOrderHistory(orderID string) ([]broker.Order, error) {
	return m.orderHistory, m.orderHistoryErr
}
func (m *mockBrokerClient) GetTrades() ([]broker.Trade, error) {
	return m.trades, m.tradesErr
}
func (m *mockBrokerClient) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	if m.placeErr != nil {
		return broker.OrderResponse{}, m.placeErr
	}
	m.placedOrders = append(m.placedOrders, params)
	return broker.OrderResponse{OrderID: fmt.Sprintf("ORD-%d", len(m.placedOrders))}, nil
}
func (m *mockBrokerClient) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	m.lastModifyOrderID = orderID
	m.lastModifyParams = params
	return m.modifyResp, m.modifyErr
}
func (m *mockBrokerClient) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
	m.lastCancelOrderID = orderID
	m.lastCancelVariety = variety
	return m.cancelResp, m.cancelErr
}
func (m *mockBrokerClient) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	return m.ltpMap, m.ltpErr
}
func (m *mockBrokerClient) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	return m.ohlcMap, m.ohlcErr
}
func (m *mockBrokerClient) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	return m.historicalData, m.historicalErr
}
func (m *mockBrokerClient) GetQuotes(instruments ...string) (map[string]broker.Quote, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetOrderTrades(orderID string) ([]broker.Trade, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetGTTs() ([]broker.GTTOrder, error) {
	return nil, nil
}
func (m *mockBrokerClient) PlaceGTT(params broker.GTTParams) (broker.GTTResponse, error) {
	return broker.GTTResponse{TriggerID: 1}, nil
}
func (m *mockBrokerClient) ModifyGTT(triggerID int, params broker.GTTParams) (broker.GTTResponse, error) {
	return broker.GTTResponse{TriggerID: triggerID}, nil
}
func (m *mockBrokerClient) DeleteGTT(triggerID int) (broker.GTTResponse, error) {
	return broker.GTTResponse{TriggerID: triggerID}, nil
}

// mockAlertStore is a minimal in-memory alert store.
type mockAlertStore struct {
	alerts map[string]string // alertID -> tradingsymbol
	addErr error
}

func (m *mockAlertStore) Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction) (string, error) {
	if m.addErr != nil {
		return "", m.addErr
	}
	id := fmt.Sprintf("ALT-%d", len(m.alerts)+1)
	m.alerts[id] = tradingsymbol
	return id, nil
}

func (m *mockAlertStore) AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction, referencePrice float64) (string, error) {
	return m.Add(email, tradingsymbol, exchange, instrumentToken, targetPrice, direction)
}

// mockInstrumentResolver returns a fixed token.
type mockInstrumentResolver struct {
	token uint32
	err   error
}

func (m *mockInstrumentResolver) GetInstrumentToken(exchange, tradingsymbol string) (uint32, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.token, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// --- PlaceOrderUseCase tests ---

func TestPlaceOrder_Success(t *testing.T) {
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("order.placed", func(e domain.Event) {
		captured = e
	})

	uc := NewPlaceOrderUseCase(resolver, nil, events, testLogger())

	orderID, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email:           "test@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           2500.0,
	})

	require.NoError(t, err)
	assert.Equal(t, "ORD-1", orderID)
	assert.Len(t, client.placedOrders, 1)
	assert.Equal(t, "RELIANCE", client.placedOrders[0].Tradingsymbol)
	assert.Equal(t, 10, client.placedOrders[0].Quantity)

	// Verify domain event was dispatched.
	require.NotNil(t, captured)
	orderEvent, ok := captured.(domain.OrderPlacedEvent)
	require.True(t, ok)
	assert.Equal(t, "test@example.com", orderEvent.Email)
	assert.Equal(t, "ORD-1", orderEvent.OrderID)
}

func TestPlaceOrder_ValidationFailures(t *testing.T) {
	uc := NewPlaceOrderUseCase(nil, nil, nil, testLogger())

	tests := []struct {
		name string
		cmd  cqrs.PlaceOrderCommand
		want string
	}{
		{
			name: "empty email",
			cmd:  cqrs.PlaceOrderCommand{Tradingsymbol: "INFY", Quantity: 10},
			want: "email is required",
		},
		{
			name: "empty tradingsymbol",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Quantity: 10},
			want: "tradingsymbol is required",
		},
		{
			name: "zero quantity",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Tradingsymbol: "INFY", Quantity: 0},
			want: "quantity must be positive",
		},
		{
			name: "negative quantity",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Tradingsymbol: "INFY", Quantity: -5},
			want: "quantity must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), tt.cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestPlaceOrder_BrokerResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no token for user")}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email: "test@test.com", Tradingsymbol: "INFY", Quantity: 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

func TestPlaceOrder_BrokerPlaceError(t *testing.T) {
	client := &mockBrokerClient{placeErr: fmt.Errorf("insufficient margin")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email: "test@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", Quantity: 10, Price: 2500,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient margin")
}

func TestPlaceOrder_NoEventsDispatcher(t *testing.T) {
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	// nil events dispatcher — should not panic.
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	orderID, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email: "test@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "MARKET", Quantity: 5,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, orderID)
}

// --- GetPortfolioUseCase tests ---

func TestGetPortfolio_Success(t *testing.T) {
	client := &mockBrokerClient{
		holdings: []broker.Holding{
			{Tradingsymbol: "RELIANCE", Quantity: 10, AveragePrice: 2400, LastPrice: 2500},
			{Tradingsymbol: "INFY", Quantity: 20, AveragePrice: 1400, LastPrice: 1500},
		},
		positions: broker.Positions{
			Day: []broker.Position{
				{Tradingsymbol: "HDFCBANK", Quantity: 5, PnL: 150},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioUseCase(resolver, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Len(t, result.Holdings, 2)
	assert.Len(t, result.Positions.Day, 1)
	assert.Equal(t, "RELIANCE", result.Holdings[0].Tradingsymbol)
}

func TestGetPortfolio_EmptyEmail(t *testing.T) {
	uc := NewGetPortfolioUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetPortfolio_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no token")}
	uc := NewGetPortfolioUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- CreateAlertUseCase tests ---

func TestCreateAlert_Success(t *testing.T) {
	store := &mockAlertStore{alerts: make(map[string]string)}
	instruments := &mockInstrumentResolver{token: 738561}
	uc := NewCreateAlertUseCase(store, instruments, testLogger())

	alertID, err := uc.Execute(context.Background(), cqrs.CreateAlertCommand{
		Email:         "test@test.com",
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		TargetPrice:   2600.0,
		Direction:     "above",
	})
	require.NoError(t, err)
	assert.Equal(t, "ALT-1", alertID)
	assert.Equal(t, "RELIANCE", store.alerts["ALT-1"])
}

func TestCreateAlert_ValidationFailures(t *testing.T) {
	uc := NewCreateAlertUseCase(nil, nil, testLogger())

	tests := []struct {
		name string
		cmd  cqrs.CreateAlertCommand
		want string
	}{
		{
			name: "empty email",
			cmd:  cqrs.CreateAlertCommand{Tradingsymbol: "INFY", TargetPrice: 1500, Direction: "above"},
			want: "email is required",
		},
		{
			name: "empty tradingsymbol",
			cmd:  cqrs.CreateAlertCommand{Email: "test@test.com", TargetPrice: 1500, Direction: "above"},
			want: "tradingsymbol is required",
		},
		{
			name: "zero target price",
			cmd:  cqrs.CreateAlertCommand{Email: "test@test.com", Tradingsymbol: "INFY", Direction: "above"},
			want: "target_price must be positive",
		},
		{
			name: "empty direction",
			cmd:  cqrs.CreateAlertCommand{Email: "test@test.com", Tradingsymbol: "INFY", TargetPrice: 1500},
			want: "direction is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), tt.cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestCreateAlert_InstrumentResolveError(t *testing.T) {
	instruments := &mockInstrumentResolver{err: fmt.Errorf("instrument not found")}
	uc := NewCreateAlertUseCase(nil, instruments, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.CreateAlertCommand{
		Email: "test@test.com", Tradingsymbol: "UNKNOWN", Exchange: "NSE",
		TargetPrice: 100, Direction: "above",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve instrument")
}

func TestCreateAlert_StoreError(t *testing.T) {
	store := &mockAlertStore{alerts: make(map[string]string), addErr: fmt.Errorf("db error")}
	instruments := &mockInstrumentResolver{token: 12345}
	uc := NewCreateAlertUseCase(store, instruments, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.CreateAlertCommand{
		Email: "test@test.com", Tradingsymbol: "RELIANCE", Exchange: "NSE",
		TargetPrice: 2600, Direction: "above",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create alert")
}

// --- GetOrdersUseCase tests ---

func TestGetOrders_Success(t *testing.T) {
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
	uc := NewGetOrdersUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetOrders_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOrdersUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrdersQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- ModifyOrderUseCase tests ---

func TestModifyOrder_Success(t *testing.T) {
	client := &mockBrokerClient{
		modifyResp: broker.OrderResponse{OrderID: "ORD-42"},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("order.modified", func(e domain.Event) {
		captured = e
	})

	uc := NewModifyOrderUseCase(resolver, nil, events, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email:    "test@example.com",
		OrderID:  "ORD-42",
		Quantity: 20,
		Price:    2600.0,
	})

	require.NoError(t, err)
	assert.Equal(t, "ORD-42", resp.OrderID)
	assert.Equal(t, "ORD-42", client.lastModifyOrderID)
	assert.Equal(t, 20, client.lastModifyParams.Quantity)
	assert.Equal(t, 2600.0, client.lastModifyParams.Price)

	// Verify domain event was dispatched.
	require.NotNil(t, captured)
	modEvent, ok := captured.(domain.OrderModifiedEvent)
	require.True(t, ok)
	assert.Equal(t, "test@example.com", modEvent.Email)
	assert.Equal(t, "ORD-42", modEvent.OrderID)
}

func TestModifyOrder_ValidationFailures(t *testing.T) {
	uc := NewModifyOrderUseCase(nil, nil, nil, testLogger())

	tests := []struct {
		name string
		cmd  cqrs.ModifyOrderCommand
		want string
	}{
		{
			name: "empty email",
			cmd:  cqrs.ModifyOrderCommand{OrderID: "ORD-1"},
			want: "email is required",
		},
		{
			name: "empty order_id",
			cmd:  cqrs.ModifyOrderCommand{Email: "test@test.com"},
			want: "order_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), tt.cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestModifyOrder_BrokerError(t *testing.T) {
	client := &mockBrokerClient{
		modifyErr: fmt.Errorf("order not found"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email: "test@test.com", OrderID: "ORD-999", Quantity: 5,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order not found")
}

func TestModifyOrder_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no token")}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email: "test@test.com", OrderID: "ORD-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- CancelOrderUseCase tests ---

func TestCancelOrder_Success(t *testing.T) {
	client := &mockBrokerClient{
		cancelResp: broker.OrderResponse{OrderID: "ORD-55"},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("order.cancelled", func(e domain.Event) {
		captured = e
	})

	uc := NewCancelOrderUseCase(resolver, events, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email:   "test@example.com",
		OrderID: "ORD-55",
		Variety: "regular",
	})

	require.NoError(t, err)
	assert.Equal(t, "ORD-55", resp.OrderID)
	assert.Equal(t, "ORD-55", client.lastCancelOrderID)
	assert.Equal(t, "regular", client.lastCancelVariety)

	// Verify domain event was dispatched.
	require.NotNil(t, captured)
	cancelEvent, ok := captured.(domain.OrderCancelledEvent)
	require.True(t, ok)
	assert.Equal(t, "test@example.com", cancelEvent.Email)
	assert.Equal(t, "ORD-55", cancelEvent.OrderID)
}

func TestCancelOrder_DefaultVariety(t *testing.T) {
	client := &mockBrokerClient{
		cancelResp: broker.OrderResponse{OrderID: "ORD-10"},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCancelOrderUseCase(resolver, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email:   "test@test.com",
		OrderID: "ORD-10",
		// Variety left empty — should default to "regular"
	})

	require.NoError(t, err)
	assert.Equal(t, "regular", client.lastCancelVariety)
}

func TestCancelOrder_ValidationFailures(t *testing.T) {
	uc := NewCancelOrderUseCase(nil, nil, testLogger())

	tests := []struct {
		name string
		cmd  cqrs.CancelOrderCommand
		want string
	}{
		{
			name: "empty email",
			cmd:  cqrs.CancelOrderCommand{OrderID: "ORD-1"},
			want: "email is required",
		},
		{
			name: "empty order_id",
			cmd:  cqrs.CancelOrderCommand{Email: "test@test.com"},
			want: "order_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Execute(context.Background(), tt.cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestCancelOrder_BrokerError(t *testing.T) {
	client := &mockBrokerClient{
		cancelErr: fmt.Errorf("order already executed"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCancelOrderUseCase(resolver, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email: "test@test.com", OrderID: "ORD-99",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order already executed")
}

func TestCancelOrder_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("expired session")}
	uc := NewCancelOrderUseCase(resolver, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email: "test@test.com", OrderID: "ORD-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- ClosePositionUseCase tests ---

func TestClosePosition_Success(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{
					Exchange:      "NSE",
					Tradingsymbol: "RELIANCE",
					Quantity:      10,
					Product:       "MIS",
					PnL:           250.0,
				},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ORD-1", result.OrderID)
	assert.Equal(t, "NSE:RELIANCE", result.Instrument)
	assert.Equal(t, 10, result.Quantity)
	assert.Equal(t, "SELL", result.Direction) // Opposite of long position
	assert.Equal(t, "MIS", result.Product)
	assert.Equal(t, 250.0, result.PositionPnL)

	// Verify the order was placed with correct params.
	require.Len(t, client.placedOrders, 1)
	assert.Equal(t, "SELL", client.placedOrders[0].TransactionType)
	assert.Equal(t, 10, client.placedOrders[0].Quantity)
	assert.Equal(t, "MARKET", client.placedOrders[0].OrderType)
}

func TestClosePosition_ShortPosition(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{
					Exchange:      "NSE",
					Tradingsymbol: "INFY",
					Quantity:      -5, // Short position
					Product:       "MIS",
					PnL:           -100.0,
				},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "NSE", "INFY", "")

	require.NoError(t, err)
	assert.Equal(t, "BUY", result.Direction) // Opposite of short position
	assert.Equal(t, 5, result.Quantity)
}

func TestClosePosition_NotFound(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "INFY", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no open position found")
}

func TestClosePosition_ZeroQuantitySkipped(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 0, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no open position found")
}

func TestClosePosition_ValidationFailures(t *testing.T) {
	uc := NewClosePositionUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	_, err = uc.Execute(context.Background(), "test@test.com", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchange and symbol are required")
}

func TestClosePosition_BrokerPlaceError(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "MIS"},
			},
		},
		placeErr: fmt.Errorf("market closed"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "market closed")
}

func TestClosePosition_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

func TestClosePosition_ProductFilter(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "CNC"},
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 5, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "MIS")

	require.NoError(t, err)
	assert.Equal(t, 5, result.Quantity) // Matched the MIS position, not CNC
	assert.Equal(t, "MIS", result.Product)
}

// --- CloseAllPositionsUseCase tests ---

func TestCloseAllPositions_ZeroPositions(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.Total)
	assert.Equal(t, 0, result.SuccessCount)
	assert.Equal(t, 0, result.ErrorCount)
	assert.Empty(t, result.Results)
}

func TestCloseAllPositions_TwoPositions(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "MIS"},
				{Exchange: "NSE", Tradingsymbol: "INFY", Quantity: -5, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 2, result.SuccessCount)
	assert.Equal(t, 0, result.ErrorCount)
	assert.Len(t, result.Results, 2)

	// First position (long) should produce SELL order.
	assert.Equal(t, "RELIANCE", result.Results[0].Tradingsymbol)
	assert.Equal(t, "SELL", result.Results[0].Direction)
	assert.Equal(t, 10, result.Results[0].Quantity)
	assert.NotEmpty(t, result.Results[0].OrderID)

	// Second position (short) should produce BUY order.
	assert.Equal(t, "INFY", result.Results[1].Tradingsymbol)
	assert.Equal(t, "BUY", result.Results[1].Direction)
	assert.Equal(t, 5, result.Results[1].Quantity)
	assert.NotEmpty(t, result.Results[1].OrderID)
}

func TestCloseAllPositions_SkipsZeroQuantity(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 0, Product: "MIS"},
				{Exchange: "NSE", Tradingsymbol: "INFY", Quantity: 10, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	assert.Equal(t, 1, result.Total) // Only INFY (RELIANCE has qty 0)
	assert.Equal(t, 1, result.SuccessCount)
}

func TestCloseAllPositions_ProductFilter(t *testing.T) {
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "CNC"},
				{Exchange: "NSE", Tradingsymbol: "INFY", Quantity: 5, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "MIS")

	require.NoError(t, err)
	assert.Equal(t, 1, result.Total) // Only INFY matches MIS filter
	assert.Equal(t, "MIS", result.ProductFilter)
	assert.Equal(t, "INFY", result.Results[0].Tradingsymbol)
}

func TestCloseAllPositions_ValidationFailure(t *testing.T) {
	uc := NewCloseAllPositionsUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestCloseAllPositions_ResolveError(t *testing.T) {
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

func TestCloseAllPositions_FetchPositionsError(t *testing.T) {
	client := &mockBrokerClient{
		positionsErr: fmt.Errorf("API timeout"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch positions")
}

func TestCloseAllPositions_PartialFailure(t *testing.T) {
	// placeErr causes ALL PlaceOrder calls to fail.
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 10, Product: "MIS"},
			},
		},
		placeErr: fmt.Errorf("insufficient margin"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err) // CloseAll itself does not fail; it reports per-entry errors.
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, 0, result.SuccessCount)
	assert.Equal(t, 1, result.ErrorCount)
	assert.Contains(t, result.Results[0].Error, "insufficient margin")
}

// --- GetProfileUseCase tests ---

func TestGetProfile_Success(t *testing.T) {
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
	uc := NewGetProfileUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetProfile_BrokerError(t *testing.T) {
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
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetProfileUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- GetMarginsUseCase tests ---

func TestGetMargins_Success(t *testing.T) {
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
	uc := NewGetMarginsUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetMargins_BrokerError(t *testing.T) {
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
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetMarginsUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- GetTradesUseCase tests ---

func TestGetTrades_Success(t *testing.T) {
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
	uc := NewGetTradesUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetTrades_BrokerError(t *testing.T) {
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
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetTradesUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetTradesQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

// --- GetOrderHistoryUseCase tests ---

func TestGetOrderHistory_Success(t *testing.T) {
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
	uc := NewGetOrderHistoryUseCase(nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{OrderID: "ORD-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	_, err = uc.Execute(context.Background(), cqrs.GetOrderHistoryQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order_id is required")
}

func TestGetOrderHistory_BrokerError(t *testing.T) {
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
	uc := NewGetLTPUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetLTPQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one instrument is required")
}

func TestGetLTP_BrokerError(t *testing.T) {
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
	uc := NewGetOHLCUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), "test@test.com", cqrs.GetOHLCQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one instrument is required")
}

func TestGetOHLC_BrokerError(t *testing.T) {
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
