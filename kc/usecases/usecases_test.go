package usecases

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// Shared mocks (mockBrokerResolver, mockBrokerClient, mockAlertStore,
// mockInstrumentResolver) and test helpers (testLogger, testPlaceCmd) now
// live in mocks_test.go.

// --- PlaceOrderUseCase tests ---


// --- GetPortfolioUseCase tests ---
func TestGetPortfolio_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	uc := NewGetPortfolioUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestGetPortfolio_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no token")}
	uc := NewGetPortfolioUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


// --- CreateAlertUseCase tests ---
func TestCreateAlert_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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


// --- CloseAllPositionsUseCase tests ---
func TestCloseAllPositions_ZeroPositions(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	uc := NewCloseAllPositionsUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestCloseAllPositions_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestCloseAllPositions_FetchPositionsError(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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


func TestCloseAllPositions_WithRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 1, Product: "MIS"},
				{Exchange: "NSE", Tradingsymbol: "INFY", Quantity: -1, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()
	guard := newTestGuard(t)

	uc := NewCloseAllPositionsUseCase(resolver, guard, events, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 2, result.SuccessCount)
}


func TestCloseAllPositions_WithEvents(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 5, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("position.closed", func(e domain.Event) {
		captured = e
	})

	uc := NewCloseAllPositionsUseCase(resolver, nil, events, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	assert.Equal(t, 1, result.SuccessCount)
	require.NotNil(t, captured)
}


func TestGetPortfolio_HoldingsError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	// Override GetHoldings to return error.
	client.holdings = nil
	resolver := &mockBrokerResolver{client: &holdingsErrClient{}}
	uc := NewGetPortfolioUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get holdings")
}


func TestGetPortfolio_PositionsError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		holdings:     []broker.Holding{{Tradingsymbol: "A"}},
		positionsErr: fmt.Errorf("positions API down"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioUseCase(resolver, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.GetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get positions")
}


func TestCreateAlert_WithReferencePrice(t *testing.T) {
	t.Parallel()
	store := &mockAlertStore{alerts: make(map[string]string)}
	instruments := &mockInstrumentResolver{token: 738561}
	uc := NewCreateAlertUseCase(store, instruments, testLogger())

	alertID, err := uc.Execute(context.Background(), cqrs.CreateAlertCommand{
		Email:          "test@test.com",
		Tradingsymbol:  "RELIANCE",
		Exchange:       "NSE",
		TargetPrice:    2600.0,
		Direction:      "above",
		ReferencePrice: 2500.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "ALT-1", alertID)
}


func TestCloseAllPositions_EmptyProductFilter(t *testing.T) {
	t.Parallel()
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

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err)
	assert.Equal(t, 2, result.Total) // Both products included with empty filter
	assert.Equal(t, "ALL", result.ProductFilter)
}


// ordersErrClient is a broker client that returns an error on GetOrders.
type ordersErrClient struct {
	mockBrokerClient
}

func (c *ordersErrClient) GetOrders() ([]broker.Order, error) {
	return nil, fmt.Errorf("orders API error")
}

// newTestGuard creates a riskguard with default limits for testing. The
// clock is pinned to the most recent weekday at 10:30 IST so the off-hours
// (02:00–06:00 IST) and market-hours (T1: weekday 09:15–15:30 IST) checks
// don't reject orders during weekend or deep-night CI runs.
func newTestGuard(t *testing.T) *riskguard.Guard {
	t.Helper()
	g := riskguard.NewGuard(testLogger())
	riskguard.PinClockToMarketHoursForTest(g)
	return g
}


// newFrozenGuard creates a riskguard with global freeze enabled. The
// market-hours pin is applied for parity, though the global freeze short-
// circuits the chain ahead of the time-based checks.
func newFrozenGuard(t *testing.T) *riskguard.Guard {
	t.Helper()
	g := riskguard.NewGuard(testLogger())
	riskguard.PinClockToMarketHoursForTest(g)
	g.FreezeGlobal("test", "test freeze")
	return g
}


func TestCloseAllPositions_BlockedByRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 1, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	guard := newFrozenGuard(t)
	uc := NewCloseAllPositionsUseCase(resolver, guard, nil, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "")

	require.NoError(t, err) // CloseAll doesn't fail overall, it reports per-entry errors.
	assert.Equal(t, 1, result.ErrorCount)
	assert.Contains(t, result.Results[0].Error, "riskguard")
}
