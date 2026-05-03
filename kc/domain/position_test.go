package domain

// position_test.go — unit tests for the rich Position domain entity.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
)

func TestPosition_IsIntraday(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		product string
		want    bool
	}{
		{"MIS upper", "MIS", true},
		{"MIS lower", "mis", true}, // case-insensitive
		{"CNC", "CNC", false},
		{"NRML", "NRML", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPositionFromBroker(broker.Position{Product: tc.product})
			assert.Equal(t, tc.want, p.IsIntraday())
		})
	}
}

func TestPosition_Direction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		quantity int
		want     string
	}{
		{"long", 10, "LONG"},
		{"short", -10, "SHORT"},
		{"flat", 0, "FLAT"},
		{"long one", 1, "LONG"},
		{"short one", -1, "SHORT"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPositionFromBroker(broker.Position{Quantity: tc.quantity})
			assert.Equal(t, tc.want, p.Direction())
		})
	}
}

func TestPosition_UnrealizedPnL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		quantity     int
		averagePrice float64
		ltp          float64
		want         float64
	}{
		{"long profit", 10, 100.0, 120.0, 200.0},  // (120-100)*10 = 200
		{"long loss", 10, 100.0, 80.0, -200.0},    // (80-100)*10 = -200
		{"short profit", -10, 100.0, 80.0, 200.0}, // (80-100)*(-10) = 200
		{"short loss", -10, 100.0, 120.0, -200.0}, // (120-100)*(-10) = -200
		{"flat", 0, 100.0, 120.0, 0},
		{"no change", 10, 100.0, 100.0, 0},
		{"tight decimals", 5, 150.25, 151.75, 7.5}, // (151.75-150.25)*5 = 7.5
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPositionFromBroker(broker.Position{
				Quantity:     tc.quantity,
				AveragePrice: tc.averagePrice,
			})
			got := p.UnrealizedPnL(NewINR(tc.ltp))
			assert.InDelta(t, tc.want, got.Amount, 0.001, "TestPosition_UnrealizedPnL: want=%v got=%v", tc.want, got.Amount, 0.001)
			assert.Equal(t, "INR", got.Currency)
		})
	}
}

func TestPosition_PnL(t *testing.T) {
	t.Parallel()

	p := NewPositionFromBroker(broker.Position{PnL: NewINR(1234.5)})
	got := p.PnL()
	assert.InDelta(t, 1234.5, got.Amount, 0.001, "TestPosition_PnL: want=%v got=%v", 1234.5, got.Amount, 0.001)
	assert.Equal(t, "INR", got.Currency)
}

func TestPosition_DTO(t *testing.T) {
	t.Parallel()

	dto := broker.Position{
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		Product:       "MIS",
		Quantity:      10,
		AveragePrice:  2500.0,
		LastPrice:     2600.0,
		PnL: NewINR(1000.0),
	}
	p := NewPositionFromBroker(dto)
	assert.Equal(t, dto, p.DTO())
}

func TestPosition_InstrumentKey(t *testing.T) {
	t.Parallel()

	p := NewPositionFromBroker(broker.Position{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	k := p.InstrumentKey()
	assert.Equal(t, "NSE", k.Exchange)
	assert.Equal(t, "RELIANCE", k.Tradingsymbol)
	assert.Equal(t, "NSE:RELIANCE", k.String())
}

func TestPosition_IsOpen(t *testing.T) {
	t.Parallel()

	long := NewPositionFromBroker(broker.Position{Quantity: 10})
	assert.True(t, long.IsOpen())

	short := NewPositionFromBroker(broker.Position{Quantity: -10})
	assert.True(t, short.IsOpen())

	flat := NewPositionFromBroker(broker.Position{Quantity: 0})
	assert.False(t, flat.IsOpen())
}

func TestToDomainPosition(t *testing.T) {
	t.Parallel()

	bp := broker.Position{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Product:       "MIS",
		Quantity:      5,
		AveragePrice:  1500,
		LastPrice:     1520,
		PnL: NewINR(100),
	}
	d := ToDomainPosition(bp)
	assert.True(t, d.IsIntraday())
	assert.Equal(t, "LONG", d.Direction())
	got := d.UnrealizedPnL(NewINR(1520))
	assert.InDelta(t, 100.0, got.Amount, 0.001) // (1520-1500)*5 = 100
}
