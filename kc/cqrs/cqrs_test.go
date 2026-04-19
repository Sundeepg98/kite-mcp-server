package cqrs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// --- Command serialization tests ---

func TestPlaceOrderCommandSerialize(t *testing.T) {
	t.Parallel()
	qty, _ := domain.NewQuantity(10)
	cmd := PlaceOrderCommand{
		Email:           "test@example.com",
		Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
		TransactionType: "BUY",
		Qty:             qty,
		Price:           domain.NewINR(2500.50),
		OrderType:       "LIMIT",
		Product:         "CNC",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded PlaceOrderCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestCancelOrderCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := CancelOrderCommand{
		Email:   "test@example.com",
		OrderID: "order-123",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded CancelOrderCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestModifyOrderCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := ModifyOrderCommand{
		Email:        "test@example.com",
		OrderID:      "order-456",
		Quantity:     20,
		Price:        domain.NewINR(2600.0),
		TriggerPrice: 2550.0,
		OrderType:    "SL",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded ModifyOrderCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestCreateAlertCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := CreateAlertCommand{
		Email:          "test@example.com",
		Tradingsymbol:  "INFY",
		Exchange:       "NSE",
		TargetPrice:    1500.0,
		Direction:      "above",
		ReferencePrice: 1450.0,
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded CreateAlertCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestDeleteAlertCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := DeleteAlertCommand{
		Email:   "test@example.com",
		AlertID: "alert-789",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded DeleteAlertCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestFreezeUserCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := FreezeUserCommand{
		Email:    "test@example.com",
		FrozenBy: "admin",
		Reason:   "suspicious activity",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded FreezeUserCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

func TestCreateWatchlistCommandSerialize(t *testing.T) {
	t.Parallel()
	cmd := CreateWatchlistCommand{
		Email: "test@example.com",
		Name:  "My Watchlist",
	}

	b, err := json.Marshal(cmd)
	require.NoError(t, err)

	var decoded CreateWatchlistCommand
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cmd, decoded)
}

// --- Query serialization tests ---

func TestGetPortfolioQuerySerialize(t *testing.T) {
	t.Parallel()
	q := GetPortfolioQuery{Email: "test@example.com"}

	b, err := json.Marshal(q)
	require.NoError(t, err)

	var decoded GetPortfolioQuery
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, q, decoded)
}

func TestGetOrdersQuerySerialize(t *testing.T) {
	t.Parallel()
	q := GetOrdersQuery{Email: "test@example.com"}

	b, err := json.Marshal(q)
	require.NoError(t, err)

	var decoded GetOrdersQuery
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, q, decoded)
}

func TestGetAlertsQuerySerialize(t *testing.T) {
	t.Parallel()
	q := GetAlertsQuery{Email: "test@example.com"}

	b, err := json.Marshal(q)
	require.NoError(t, err)

	var decoded GetAlertsQuery
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, q, decoded)
}

func TestGetHistoricalDataQuerySerialize(t *testing.T) {
	t.Parallel()
	q := GetHistoricalDataQuery{
		InstrumentToken: 738561,
		Interval:        "day",
		From:            time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:              time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}

	b, err := json.Marshal(q)
	require.NoError(t, err)

	var decoded GetHistoricalDataQuery
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, q.InstrumentToken, decoded.InstrumentToken)
	assert.Equal(t, q.Interval, decoded.Interval)
}

func TestGetAuditTrailQuerySerialize(t *testing.T) {
	t.Parallel()
	q := GetAuditTrailQuery{
		Email:      "test@example.com",
		Limit:      50,
		Offset:     10,
		OnlyErrors: true,
	}

	b, err := json.Marshal(q)
	require.NoError(t, err)

	var decoded GetAuditTrailQuery
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, q, decoded)
}

// --- Handler interface tests (mock implementations) ---

// mockCommandHandler is a test implementation of CommandHandler.
type mockCommandHandler struct {
	called bool
	cmd    PlaceOrderCommand
}

func (m *mockCommandHandler) Handle(_ context.Context, cmd PlaceOrderCommand) error {
	m.called = true
	m.cmd = cmd
	return nil
}

func TestCommandHandlerInterface(t *testing.T) {
	t.Parallel()
	handler := &mockCommandHandler{}
	var _ CommandHandler[PlaceOrderCommand] = handler // compile-time check

	qty, _ := domain.NewQuantity(10)
	cmd := PlaceOrderCommand{
		Email:      "test@example.com",
		Instrument: domain.NewInstrumentKey("NSE", "RELIANCE"),
		Qty:        qty,
	}

	err := handler.Handle(context.Background(), cmd)
	require.NoError(t, err)
	assert.True(t, handler.called)
	assert.Equal(t, cmd.Email, handler.cmd.Email)
	assert.Equal(t, cmd.Instrument.Tradingsymbol, handler.cmd.Instrument.Tradingsymbol)
}

// mockCommandHandlerWithResult tests the result-returning variant.
type mockPlaceOrderHandler struct {
	orderID string
}

func (m *mockPlaceOrderHandler) Handle(_ context.Context, cmd PlaceOrderCommand) (string, error) {
	return m.orderID, nil
}

func TestCommandHandlerWithResultInterface(t *testing.T) {
	t.Parallel()
	handler := &mockPlaceOrderHandler{orderID: "ORD-123"}
	var _ CommandHandlerWithResult[PlaceOrderCommand, string] = handler

	qty5, _ := domain.NewQuantity(5)
	id, err := handler.Handle(context.Background(), PlaceOrderCommand{
		Email: "test@example.com", Instrument: domain.NewInstrumentKey("NSE", "INFY"), Qty: qty5,
	})
	require.NoError(t, err)
	assert.Equal(t, "ORD-123", id)
}

// mockQueryHandler is a test implementation of QueryHandler.
type mockQueryHandler struct {
	result []string
}

func (m *mockQueryHandler) Handle(_ context.Context, _ GetOrdersQuery) ([]string, error) {
	return m.result, nil
}

func TestQueryHandlerInterface(t *testing.T) {
	t.Parallel()
	handler := &mockQueryHandler{result: []string{"order-1", "order-2"}}
	var _ QueryHandler[GetOrdersQuery, []string] = handler

	results, err := handler.Handle(context.Background(), GetOrdersQuery{Email: "test@example.com"})
	require.NoError(t, err)
	assert.Equal(t, []string{"order-1", "order-2"}, results)
}
