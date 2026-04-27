package usecases

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Slice 6 of the Money VO sweep — accessor migration on
// Position.PnL consumers (commit lineage: 5ce3eb0 -> 0e516e7 ->
// 5b5a54e -> fb4ff33 -> aeb6f6a -> [Slice 6]).
//
// Slice 6 keeps the broker DTO PnL float64 (Option A from
// .research/money-vo-slice6-scoping.md) — only the JSON-emit
// boundaries inside use cases / tools are migrated to read
// through domain.Position.PnL() Money. The wire format stays
// identical: the float that lands in the JSON payload is the same
// float the DTO carries; the migration is purely a typing
// discipline so that anywhere a PnL number gets compared,
// summed, or otherwise reasoned about it can be done through a
// currency-aware Money rather than a bare float.
//
// These tests pin two contracts:
//
//  1. The accessor returns INR-tagged Money matching the DTO's
//     PnL value exactly. This is the keystone domain.Position
//     test (covered separately in kc/domain/position_test.go);
//     re-asserted here to make Slice 6's intent local-to-the-slice.
//
//  2. The widget / close-position / pretrade JSON-emit boundary
//     reads via the accessor without disturbing the float wire
//     value. Negative PnL (short positions, loss days) round-
//     trips through Money correctly, INR-tagged.

// TestSlice6_PositionPnLAccessor_PositiveINR verifies the basic
// happy path: a positive PnL value lifts to INR-tagged Money and
// .Float64() returns the same magnitude. Sanity check that the
// accessor pattern doesn't drift from the DTO's value.
func TestSlice6_PositionPnLAccessor_PositiveINR(t *testing.T) {
	t.Parallel()
	dto := broker.Position{
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		Product:       "CNC",
		Quantity:      10,
		AveragePrice:  2500.0,
		LastPrice:     2600.0,
		PnL: domain.NewINR(1000.0),
	}
	pos := domain.NewPositionFromBroker(dto)

	got := pos.PnL()
	assert.Equal(t, "INR", got.Currency,
		"all broker-sourced Position PnL is INR-denominated")
	assert.Equal(t, 1000.0, got.Float64(),
		"accessor must return DTO PnL value unchanged")
	assert.True(t, got.IsPositive(),
		"a winning long position has positive Money")
}

// TestSlice6_PositionPnLAccessor_NegativeINR pins the negative-
// signed path. Short positions with adverse mark-to-market and
// long positions on losing days both surface as negative PnL.
// domain.Money carries the sign; IsNegative is the explicit
// loss-day sentinel that downstream Money-aware code can branch
// on without comparing against a bare float zero.
func TestSlice6_PositionPnLAccessor_NegativeINR(t *testing.T) {
	t.Parallel()
	dto := broker.Position{
		Tradingsymbol: "INFY",
		Exchange:      "NSE",
		Product:       "MIS",
		Quantity:      -5,
		AveragePrice:  1500.0,
		LastPrice:     1520.0, // adverse for short
		PnL: domain.NewINR(-100.0),
	}
	pos := domain.NewPositionFromBroker(dto)

	got := pos.PnL()
	assert.Equal(t, "INR", got.Currency)
	assert.Equal(t, -100.0, got.Float64(),
		"negative PnL must round-trip through Money with sign")
	assert.True(t, got.IsNegative(),
		"loss-day Position has IsNegative true")
	assert.False(t, got.IsZero(),
		"non-zero PnL is not the zero-Money sentinel")
}

// TestSlice6_PositionPnLAccessor_ZeroIsSentinel verifies the
// zero-Money sentinel: a flat position (no realised P&L for
// the day, no mark-to-market) returns the zero Money. This is
// the same IsZero() sentinel Slices 1+5 use for "unset / no
// data". Slice 6 doesn't introduce new sentinel semantics —
// just preserves them at the accessor boundary.
func TestSlice6_PositionPnLAccessor_ZeroIsSentinel(t *testing.T) {
	t.Parallel()
	dto := broker.Position{
		Tradingsymbol: "TCS",
		Exchange:      "NSE",
		Product:       "CNC",
		Quantity:      0, // flat
		PnL: domain.NewINR(0),
	}
	pos := domain.NewPositionFromBroker(dto)

	got := pos.PnL()
	assert.True(t, got.IsZero(),
		"zero PnL surfaces as zero Money (sentinel)")
	assert.Equal(t, "INR", got.Currency,
		"even zero Money carries the INR currency tag so cross-"+
			"currency Money.Add against it produces consistent semantics")
}

// TestSlice6_PositionPnLAccessor_RejectsCrossCurrencyAdd is the
// type-safety win for Slice 6: once a Position's PnL is read
// through the accessor, attempting to Add a non-INR Money to it
// returns an error rather than silently coercing. Same property
// Slices 1+2+3+4+5 surface for limits, prices, daily values,
// tier amounts, and paper cash — extended here to per-position
// PnL so any future cross-currency arithmetic at this surface
// trips the type guard.
func TestSlice6_PositionPnLAccessor_RejectsCrossCurrencyAdd(t *testing.T) {
	t.Parallel()
	pos := domain.NewPositionFromBroker(broker.Position{PnL: domain.NewINR(1000)})
	pnl := pos.PnL()

	usd := domain.Money{Amount: 12, Currency: "USD"}
	_, err := pnl.Add(usd)
	require.Error(t, err,
		"Position.PnL().Add(USD) must reject; cross-currency math "+
			"on broker PnL may not silently coerce")

	_, err = pnl.GreaterThan(usd)
	require.Error(t, err,
		"Position.PnL().GreaterThan(USD) must reject for the same reason")
}

// TestSlice6_ClosePositionResult_PreservesWireValue is the
// regression-style guard: the ClosePositionResult.PositionPnL
// JSON field, post-migration, MUST contain exactly the same
// float64 the broker DTO supplied. Goes through
// domain.NewPositionFromBroker(matched).PnL().Float64() in the
// production code; this test pins the round-trip identity for
// the wire format so external consumers (claude.ai, Telegram,
// Apps SDK widgets) see no drift.
func TestSlice6_ClosePositionResult_PreservesWireValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dto  broker.Position
		want float64
	}{
		{
			"positive PnL on long position",
			broker.Position{
				Exchange: "NSE", Tradingsymbol: "RELIANCE",
				Quantity: 10, Product: "MIS", PnL: domain.NewINR(250.0),
			},
			250.0,
		},
		{
			"negative PnL on short position",
			broker.Position{
				Exchange: "NSE", Tradingsymbol: "INFY",
				Quantity: -5, Product: "MIS", PnL: domain.NewINR(-100.0),
			},
			-100.0,
		},
		{
			"fractional PnL (rupees+paise)",
			broker.Position{
				Exchange: "NSE", Tradingsymbol: "TCS",
				Quantity: 3, Product: "CNC", PnL: domain.NewINR(1234.56),
			},
			1234.56,
		},
		{
			"zero PnL (flat position carried for residual reporting)",
			broker.Position{
				Exchange: "NSE", Tradingsymbol: "HDFC",
				Quantity: 1, Product: "CNC", PnL: domain.NewINR(0),
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &mockBrokerClient{
				positions: broker.Positions{Net: []broker.Position{tc.dto}},
			}
			resolver := &mockBrokerResolver{client: client}
			uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())

			result, err := uc.Execute(context.Background(),
				"trader@example.com", tc.dto.Exchange, tc.dto.Tradingsymbol, "")
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.want, result.PositionPnL,
				"wire value must equal DTO PnL exactly post-migration")
		})
	}
}

// TestSlice6_WidgetPositionItem_PreservesWireValue covers the
// widget JSON-emit boundary. WidgetPositionItem.PnL is what
// front-end widgets read; the migration from `p.PnL` to
// `domain.NewPositionFromBroker(p).PnL().Float64()` must leave
// this field byte-identical. Pins via a Net-positions roundtrip
// through GetPortfolioForWidgetUseCase.
func TestSlice6_WidgetPositionItem_PreservesWireValue(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "RELIANCE", Exchange: "NSE",
					Quantity: 2, AveragePrice: 2500, LastPrice: 2600,
					PnL: domain.NewINR(200.0), Product: "CNC"},
				{Tradingsymbol: "INFY", Exchange: "NSE",
					Quantity: -5, AveragePrice: 1500, LastPrice: 1520,
					PnL: domain.NewINR(-100.0), Product: "MIS"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())

	result, err := uc.Execute(context.Background(),
		cqrs.GetWidgetPortfolioQuery{Email: "trader@example.com"})
	require.NoError(t, err)
	require.Len(t, result.Positions, 2)

	assert.Equal(t, 200.0, result.Positions[0].PnL,
		"long-position PnL must round-trip exactly post-migration")
	assert.Equal(t, -100.0, result.Positions[1].PnL,
		"short-position PnL preserves negative sign post-migration")
}
