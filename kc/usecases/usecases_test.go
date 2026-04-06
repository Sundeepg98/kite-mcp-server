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
}

func (m *mockBrokerClient) BrokerName() broker.Name              { return "mock" }
func (m *mockBrokerClient) GetProfile() (broker.Profile, error)  { return broker.Profile{}, nil }
func (m *mockBrokerClient) GetMargins() (broker.Margins, error)  { return broker.Margins{}, nil }
func (m *mockBrokerClient) GetHoldings() ([]broker.Holding, error) { return m.holdings, nil }
func (m *mockBrokerClient) GetPositions() (broker.Positions, error) { return m.positions, nil }
func (m *mockBrokerClient) GetOrders() ([]broker.Order, error)    { return m.orders, nil }
func (m *mockBrokerClient) GetOrderHistory(orderID string) ([]broker.Order, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetTrades() ([]broker.Trade, error) { return nil, nil }
func (m *mockBrokerClient) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	if m.placeErr != nil {
		return broker.OrderResponse{}, m.placeErr
	}
	m.placedOrders = append(m.placedOrders, params)
	return broker.OrderResponse{OrderID: fmt.Sprintf("ORD-%d", len(m.placedOrders))}, nil
}
func (m *mockBrokerClient) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	return broker.OrderResponse{}, nil
}
func (m *mockBrokerClient) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
	return broker.OrderResponse{}, nil
}
func (m *mockBrokerClient) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	return nil, nil
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
