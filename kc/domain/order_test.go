package domain

// order_test.go — unit tests for the rich Order domain entity.
//
// The Order entity wraps the broker.Order DTO and provides lifecycle
// behavior: CanCancel, IsTerminal, FillPercentage. These methods replace
// inline status-string checks scattered across riskguard, pnl_tools,
// ops handlers, and paper-trading engine.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
)

func TestOrder_CanCancel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{"open", "OPEN", true},
		{"trigger pending", "TRIGGER PENDING", true},
		{"validation pending", "VALIDATION PENDING", false},
		{"complete", "COMPLETE", false},
		{"cancelled", "CANCELLED", false},
		{"rejected", "REJECTED", false},
		{"empty", "", false},
		{"lowercase open", "open", true},  // case-insensitive
		{"mixed case", "Trigger Pending", true}, // case-insensitive
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewOrderFromBroker(broker.Order{Status: tc.status})
			assert.Equal(t, tc.want, o.CanCancel())
		})
	}
}

func TestOrder_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{"complete", "COMPLETE", true},
		{"cancelled", "CANCELLED", true},
		{"rejected", "REJECTED", true},
		{"open", "OPEN", false},
		{"trigger pending", "TRIGGER PENDING", false},
		{"validation pending", "VALIDATION PENDING", false},
		{"empty", "", false},
		{"lowercase complete", "complete", true}, // case-insensitive
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewOrderFromBroker(broker.Order{Status: tc.status})
			assert.Equal(t, tc.want, o.IsTerminal())
		})
	}
}

func TestOrder_FillPercentage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		quantity       int
		filledQuantity int
		want           float64
	}{
		{"not filled", 100, 0, 0},
		{"half filled", 100, 50, 50},
		{"fully filled", 100, 100, 100},
		{"over filled guard", 100, 150, 100}, // clamped to 100
		{"zero quantity", 0, 0, 0},           // avoid divide-by-zero
		{"zero quantity with fills", 0, 5, 0},
		{"one unit full", 1, 1, 100},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewOrderFromBroker(broker.Order{
				Quantity:       tc.quantity,
				FilledQuantity: tc.filledQuantity,
			})
			assert.InDelta(t, tc.want, o.FillPercentage(), 0.001)
		})
	}
}

func TestOrder_DTO(t *testing.T) {
	t.Parallel()

	dto := broker.Order{
		OrderID:         "ORD123",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           2500.0,
		Status:          "OPEN",
		FilledQuantity:  5,
		OrderTimestamp:  time.Now(),
	}
	o := NewOrderFromBroker(dto)
	assert.Equal(t, dto, o.DTO(), "DTO getter should return the underlying broker.Order")
}

func TestOrder_Status(t *testing.T) {
	t.Parallel()

	o := NewOrderFromBroker(broker.Order{Status: "OPEN"})
	assert.Equal(t, "OPEN", o.Status())

	empty := NewOrderFromBroker(broker.Order{})
	assert.Equal(t, "", empty.Status())
}

func TestOrder_ID(t *testing.T) {
	t.Parallel()

	o := NewOrderFromBroker(broker.Order{OrderID: "ORD-42"})
	assert.Equal(t, "ORD-42", o.ID())
}

func TestOrder_IsPending(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{"open is pending", "OPEN", true},
		{"trigger pending is pending", "TRIGGER PENDING", true},
		{"validation pending is pending", "VALIDATION PENDING", true},
		{"amo req received is pending", "AMO REQ RECEIVED", true},
		{"complete is not pending", "COMPLETE", false},
		{"cancelled is not pending", "CANCELLED", false},
		{"rejected is not pending", "REJECTED", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewOrderFromBroker(broker.Order{Status: tc.status})
			assert.Equal(t, tc.want, o.IsPending())
		})
	}
}

func TestOrder_IsComplete_IsRejected_IsCancelled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    string
		complete  bool
		rejected  bool
		cancelled bool
	}{
		{"complete", "COMPLETE", true, false, false},
		{"rejected", "REJECTED", false, true, false},
		{"cancelled", "CANCELLED", false, false, true},
		{"open", "OPEN", false, false, false},
		{"trigger pending", "TRIGGER PENDING", false, false, false},
		{"lowercase complete", "complete", true, false, false}, // case-insensitive
		{"lowercase rejected", "rejected", false, true, false},
		{"lowercase cancelled", "cancelled", false, false, true},
		{"padded complete", "  COMPLETE  ", true, false, false}, // trimmed
		{"empty", "", false, false, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewOrderFromBroker(broker.Order{Status: tc.status})
			assert.Equal(t, tc.complete, o.IsComplete(), "IsComplete")
			assert.Equal(t, tc.rejected, o.IsRejected(), "IsRejected")
			assert.Equal(t, tc.cancelled, o.IsCancelled(), "IsCancelled")
		})
	}
}

func TestToDomainOrder(t *testing.T) {
	t.Parallel()

	bo := broker.Order{OrderID: "X", Status: "OPEN", Quantity: 10, FilledQuantity: 3}
	d := ToDomainOrder(bo)
	assert.Equal(t, "X", d.ID())
	assert.True(t, d.CanCancel())
	assert.False(t, d.IsTerminal())
	assert.InDelta(t, 30.0, d.FillPercentage(), 0.001)
}
