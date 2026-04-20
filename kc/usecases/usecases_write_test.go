package usecases

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Shared mocks (mockBrokerResolver, mockBrokerClient, mockAlertStore,
// mockInstrumentResolver) and test helpers (testLogger, testPlaceCmd) now
// live in mocks_test.go.

// --- PlaceOrderUseCase tests ---

func TestPlaceOrder_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("order.placed", func(e domain.Event) {
		captured = e
	})

	uc := NewPlaceOrderUseCase(resolver, nil, events, testLogger())

	orderID, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "RELIANCE", "BUY", "LIMIT", "CNC", 10, 2500.0,
	))

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
	t.Parallel()
	uc := NewPlaceOrderUseCase(nil, nil, nil, testLogger())

	qty10, _ := domain.NewQuantity(10)
	tests := []struct {
		name string
		cmd  cqrs.PlaceOrderCommand
		want string
	}{
		// Task #34: validation is delegated to domain.NewOrderPlacement.
		// Test expectations match the aggregate's error text (the use
		// case wraps with "usecases:").
		{
			name: "empty email",
			cmd:  cqrs.PlaceOrderCommand{Instrument: domain.NewInstrumentKey("NSE", "INFY"), Qty: qty10, TransactionType: "BUY", OrderType: "MARKET"},
			want: "email is required",
		},
		{
			name: "invalid instrument (empty exchange)",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Instrument: domain.NewInstrumentKey("", "INFY"), Qty: qty10, TransactionType: "BUY", OrderType: "MARKET"},
			want: "requires a valid instrument",
		},
		{
			name: "missing instrument entirely",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Qty: qty10, TransactionType: "BUY", OrderType: "MARKET"},
			want: "requires a valid instrument",
		},
		{
			name: "zero quantity",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Instrument: domain.NewInstrumentKey("NSE", "INFY"), TransactionType: "BUY", OrderType: "MARKET"},
			want: "requires a positive quantity",
		},
		{
			name: "invalid transaction type",
			cmd:  cqrs.PlaceOrderCommand{Email: "test@test.com", Instrument: domain.NewInstrumentKey("NSE", "INFY"), TransactionType: "HOLD", Qty: qty10, OrderType: "MARKET"},
			want: "transaction_type must be BUY or SELL",
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
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no token for user")}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	// Task #34: exchange must now be populated (domain aggregate rejects
	// empty exchange). Use NSE to exercise broker-resolve failure path.
	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@test.com", "NSE", "INFY", "BUY", "MARKET", "", 10, 0,
	))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestPlaceOrder_BrokerPlaceError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeErr: fmt.Errorf("insufficient margin")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@test.com", "NSE", "RELIANCE", "BUY", "", "", 10, 2500,
	))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient margin")
}


func TestPlaceOrder_NoEventsDispatcher(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	// nil events dispatcher — should not panic.
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())

	orderID, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@test.com", "NSE", "RELIANCE", "BUY", "MARKET", "", 5, 0,
	))
	require.NoError(t, err)
	assert.NotEmpty(t, orderID)
}


// --- ModifyOrderUseCase tests ---
func TestModifyOrder_Success(t *testing.T) {
	t.Parallel()
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
		Price:    domain.NewINR(2600.0),
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	uc := NewClosePositionUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	_, err = uc.Execute(context.Background(), "test@test.com", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchange and symbol are required")
}


func TestClosePosition_BrokerPlaceError(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestClosePosition_ProductFilter(t *testing.T) {
	t.Parallel()
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


// --- PlaceGTTUseCase tests ---
func TestPlaceGTT_SingleLeg(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeGTTResp: broker.GTTResponse{TriggerID: 42}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceGTTUseCase(resolver, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email:           "test@test.com",
		Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
		LastPrice:       domain.NewINR(2500.0),
		TransactionType: "BUY",
		Product:         "CNC",
		Type:            "single",
		TriggerValue:    2400.0,
		Quantity:        10,
		LimitPrice:      domain.NewINR(2390.0),
	})
	require.NoError(t, err)
	assert.Equal(t, 42, resp.TriggerID)
	assert.Equal(t, 2400.0, client.lastGTTParams.TriggerValue)
}


func TestPlaceGTT_TwoLeg(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeGTTResp: broker.GTTResponse{TriggerID: 43}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceGTTUseCase(resolver, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email:             "test@test.com",
		Instrument:        domain.NewInstrumentKey("NSE", "INFY"),
		LastPrice:         domain.NewINR(1500.0),
		TransactionType:   "SELL",
		Product:           "CNC",
		Type:              "two-leg",
		UpperTriggerValue: 1600.0,
		UpperQuantity:     5,
		UpperLimitPrice:   domain.NewINR(1595.0),
		LowerTriggerValue: 1400.0,
		LowerQuantity:     5,
		LowerLimitPrice:   domain.NewINR(1405.0),
	})
	require.NoError(t, err)
	assert.Equal(t, 43, resp.TriggerID)
}


func TestPlaceGTT_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPlaceGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Instrument: domain.NewInstrumentKey("", "INFY"), Type: "single",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestPlaceGTT_EmptyTradingsymbol(t *testing.T) {
	t.Parallel()
	uc := NewPlaceGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "test@test.com", Type: "single",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tradingsymbol is required")
}


func TestPlaceGTT_InvalidType(t *testing.T) {
	t.Parallel()
	uc := NewPlaceGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "test@test.com", Instrument: domain.NewInstrumentKey("", "INFY"), Type: "triple",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid GTT type")
}


func TestPlaceGTT_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewPlaceGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "test@test.com", Instrument: domain.NewInstrumentKey("", "INFY"), Type: "single", Quantity: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestPlaceGTT_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeGTTErr: fmt.Errorf("insufficient funds")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "test@test.com", Instrument: domain.NewInstrumentKey("", "INFY"), Type: "single", Quantity: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "place gtt")
}


// --- ModifyGTTUseCase tests ---
func TestModifyGTT_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyGTTResp: broker.GTTResponse{TriggerID: 42}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyGTTUseCase(resolver, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		Email:        "test@test.com",
		TriggerID:    42,
		Instrument:   domain.NewInstrumentKey("", "RELIANCE"),
		Type:         "single",
		TriggerValue: 2450.0,
		Quantity:     15,
		LimitPrice:   domain.NewINR(2440.0),
	})
	require.NoError(t, err)
	assert.Equal(t, 42, resp.TriggerID)
	assert.Equal(t, 42, client.lastModifyGTTID)
	assert.Equal(t, 2450.0, client.lastGTTParams.TriggerValue)
}


func TestModifyGTT_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewModifyGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		TriggerID: 1, Type: "single",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestModifyGTT_ZeroTriggerID(t *testing.T) {
	t.Parallel()
	uc := NewModifyGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		Email: "test@test.com", Type: "single",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trigger_id is required")
}


func TestModifyGTT_InvalidType(t *testing.T) {
	t.Parallel()
	uc := NewModifyGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		Email: "test@test.com", TriggerID: 1, Type: "invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid GTT type")
}


func TestModifyGTT_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewModifyGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		Email: "test@test.com", TriggerID: 1, Type: "single", Quantity: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestModifyGTT_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyGTTErr: fmt.Errorf("trigger not found")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{
		Email: "test@test.com", TriggerID: 99, Type: "two-leg", UpperQuantity: 1, LowerQuantity: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "modify gtt")
}


// --- DeleteGTTUseCase tests ---
func TestDeleteGTT_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{deleteGTTResp: broker.GTTResponse{TriggerID: 42}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewDeleteGTTUseCase(resolver, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{
		Email:     "test@test.com",
		TriggerID: 42,
	})
	require.NoError(t, err)
	assert.Equal(t, 42, resp.TriggerID)
	assert.Equal(t, 42, client.lastDeleteGTTID)
}


func TestDeleteGTT_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{TriggerID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}


func TestDeleteGTT_ZeroTriggerID(t *testing.T) {
	t.Parallel()
	uc := NewDeleteGTTUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trigger_id is required")
}


func TestDeleteGTT_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewDeleteGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{
		Email: "test@test.com", TriggerID: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}


func TestDeleteGTT_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{deleteGTTErr: fmt.Errorf("trigger not found")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewDeleteGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{
		Email: "test@test.com", TriggerID: 999,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete gtt")
}


// ---------------------------------------------------------------------------
// Additional coverage: riskguard branches, event dispatching, error combination paths
// ---------------------------------------------------------------------------
func TestPlaceOrder_WithRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	// Create a riskguard that allows all orders (not frozen, high limits).
	guard := newTestGuard(t)

	uc := NewPlaceOrderUseCase(resolver, guard, events, testLogger())

	orderID, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "RELIANCE", "BUY", "MARKET", "CNC", 1, 0,
	))

	require.NoError(t, err)
	assert.NotEmpty(t, orderID)
}


func TestModifyOrder_WithRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		modifyResp: broker.OrderResponse{OrderID: "ORD-42"},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()
	guard := newTestGuard(t)

	uc := NewModifyOrderUseCase(resolver, guard, events, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email:     "test@example.com",
		OrderID:   "ORD-42",
		Quantity:  1,
		Price:     domain.NewINR(100.0),
		Confirmed: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "ORD-42", resp.OrderID)
}


func TestClosePosition_WithRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 1, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()
	guard := newTestGuard(t)

	uc := NewClosePositionUseCase(resolver, guard, events, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")

	require.NoError(t, err)
	assert.Equal(t, "ORD-1", result.OrderID)
}


func TestClosePosition_WithEvents(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "INFY", Quantity: 3, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("position.closed", func(e domain.Event) {
		captured = e
	})

	uc := NewClosePositionUseCase(resolver, nil, events, testLogger())

	result, err := uc.Execute(context.Background(), "test@test.com", "NSE", "INFY", "")

	require.NoError(t, err)
	assert.Equal(t, "ORD-1", result.OrderID)
	require.NotNil(t, captured)
}


func TestClosePosition_FetchPositionsError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positionsErr: fmt.Errorf("network timeout"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch positions")
}


func TestModifyOrder_NoEventsDispatcher(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		modifyResp: broker.OrderResponse{OrderID: "ORD-99"},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())

	resp, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email: "test@test.com", OrderID: "ORD-99", Quantity: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "ORD-99", resp.OrderID)
}


func TestClosePosition_ExchangeEmptySymbolPresent(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "", "RELIANCE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchange and symbol are required")
}


func TestClosePosition_SymbolEmptyExchangePresent(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(nil, nil, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchange and symbol are required")
}


func TestPlaceOrder_BlockedByRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("risk.limit_breached", func(e domain.Event) {
		captured = e
	})

	guard := newFrozenGuard(t)
	uc := NewPlaceOrderUseCase(resolver, guard, events, testLogger())

	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "RELIANCE", "BUY", "MARKET", "CNC", 1, 0,
	))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
	require.NotNil(t, captured, "RiskLimitBreachedEvent should be dispatched")
}


func TestPlaceOrder_BlockedByRiskguard_NoEvents(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	guard := newFrozenGuard(t)
	uc := NewPlaceOrderUseCase(resolver, guard, nil, testLogger())

	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "RELIANCE", "BUY", "MARKET", "", 1, 0,
	))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
}


func TestModifyOrder_BlockedByRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("risk.limit_breached", func(e domain.Event) {
		captured = e
	})

	guard := newFrozenGuard(t)
	uc := NewModifyOrderUseCase(resolver, guard, events, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email:    "test@example.com",
		OrderID:  "ORD-1",
		Quantity: 1,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
	require.NotNil(t, captured, "RiskLimitBreachedEvent should be dispatched")
}


func TestModifyOrder_BlockedByRiskguard_NoEvents(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	guard := newFrozenGuard(t)
	uc := NewModifyOrderUseCase(resolver, guard, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email:   "test@example.com",
		OrderID: "ORD-1",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
}


func TestClosePosition_BlockedByRiskguard(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 1, Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	events := domain.NewEventDispatcher()

	var captured domain.Event
	events.Subscribe("risk.limit_breached", func(e domain.Event) {
		captured = e
	})

	guard := newFrozenGuard(t)
	uc := NewClosePositionUseCase(resolver, guard, events, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
	require.NotNil(t, captured, "RiskLimitBreachedEvent should be dispatched")
}


func TestClosePosition_BlockedByRiskguard_NoEvents(t *testing.T) {
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
	uc := NewClosePositionUseCase(resolver, guard, nil, testLogger())

	_, err := uc.Execute(context.Background(), "test@test.com", "NSE", "RELIANCE", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "riskguard")
}

// --- Phase C ES: order lifecycle audit-log append ---

// TestPlaceOrder_EmitsEventOnSuccess verifies the use case appends an
// order.placed StoredEvent to the audit log after broker success. Payload
// matches OrderPlacedPayload for round-trip through LoadOrderFromEvents.
func TestPlaceOrder_EmitsEventOnSuccess(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := &mockEventAppender{}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	uc.SetEventStore(events)

	orderID, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "RELIANCE", "BUY", "LIMIT", "CNC", 10, 2500.0,
	))
	require.NoError(t, err)
	require.Len(t, events.appended, 1)
	got := events.appended[0]
	assert.Equal(t, orderID, got.AggregateID)
	assert.Equal(t, "Order", got.AggregateType)
	assert.Equal(t, "order.placed", got.EventType)
	assert.Contains(t, string(got.Payload), "RELIANCE")
	assert.Contains(t, string(got.Payload), "BUY")
}

// TestPlaceOrder_EventStoreFailureDoesNotRollback: the broker has already
// placed the order; an audit-append failure must not surface to the caller.
func TestPlaceOrder_EventStoreFailureDoesNotRollback(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := &mockEventAppender{appendErr: errors.New("disk full")}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	uc.SetEventStore(events)

	orderID, err := uc.Execute(context.Background(), testPlaceCmd(
		"test@example.com", "NSE", "INFY", "BUY", "LIMIT", "CNC", 5, 1500.0,
	))
	require.NoError(t, err, "audit append failure must not rollback the broker order")
	assert.NotEmpty(t, orderID)
}

// TestModifyOrder_EmitsEventOnSuccess verifies the use case appends an
// order.modified StoredEvent after broker success.
func TestModifyOrder_EmitsEventOnSuccess(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := &mockEventAppender{}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())
	uc.SetEventStore(events)

	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email:     "test@example.com",
		OrderID:   "ORD-99",
		Quantity:  15,
		Price:     domain.NewINR(2550.0),
		OrderType: "LIMIT",
		Variety:   "regular",
	})
	require.NoError(t, err)
	require.Len(t, events.appended, 1)
	got := events.appended[0]
	assert.Equal(t, "ORD-99", got.AggregateID)
	assert.Equal(t, "Order", got.AggregateType)
	assert.Equal(t, "order.modified", got.EventType)
}

// TestCancelOrder_EmitsEventOnSuccess verifies the use case appends an
// order.cancelled StoredEvent after broker success.
func TestCancelOrder_EmitsEventOnSuccess(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := &mockEventAppender{}
	uc := NewCancelOrderUseCase(resolver, nil, testLogger())
	uc.SetEventStore(events)

	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email:   "test@example.com",
		OrderID: "ORD-100",
		Variety: "regular",
	})
	require.NoError(t, err)
	require.Len(t, events.appended, 1)
	got := events.appended[0]
	assert.Equal(t, "ORD-100", got.AggregateID)
	assert.Equal(t, "Order", got.AggregateType)
	assert.Equal(t, "order.cancelled", got.EventType)
}

// TestCancelOrder_EventStoreFailureDoesNotRollback: the cancel has already
// gone through to the broker; audit failure must not surface.
func TestCancelOrder_EventStoreFailureDoesNotRollback(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	events := &mockEventAppender{appendErr: errors.New("disk full")}
	uc := NewCancelOrderUseCase(resolver, nil, testLogger())
	uc.SetEventStore(events)

	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{
		Email:   "test@example.com",
		OrderID: "ORD-101",
	})
	require.NoError(t, err)
}
