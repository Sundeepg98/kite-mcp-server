package usecases

// Slice 6b of the Money VO sweep — accessor migration on
// Holding.PnL consumers (commit lineage: 5ce3eb0 -> 0e516e7 ->
// 5b5a54e -> fb4ff33 -> aeb6f6a -> 555bdf4 -> [Slice 6b]).
//
// Slice 6b extends Slice 6's Position-accessor pattern to
// broker.Holding via the new domain.Holding wrapper. The keystone
// is in kc/domain/holding.go (Holding.PnL() Money). Consumer-side
// migration here covers JSON-emit boundaries — same boundary
// semantic Slice 6 used: read via the accessor (currency-tagged,
// Money-aware), drop to .Float64() at the wire seam so external
// consumers (claude.ai, Claude Desktop, Telegram briefings, web
// dashboards) see byte-identical output.
//
// In-loop aggregation reads (`totalPnL += h.PnL`) deliberately
// stay bare-float per Slice 3's "sum primitive then wrap once"
// hot-path discipline — they're documented in the migration
// commit, not migrated here.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// TestSlice6b_WidgetHoldingItem_PreservesWireValue is the
// regression-style guard for the widget JSON-emit migration. The
// production code now reads via domain.NewHoldingFromBroker(h).PnL()
// at the WidgetHoldingItem.PnL site; this test pins the round-trip
// identity for the wire format so external dashboard consumers
// see no drift across the migration.
func TestSlice6b_WidgetHoldingItem_PreservesWireValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		holding  broker.Holding
		wantPnL  float64
	}{
		{
			"positive PnL on long-held position",
			broker.Holding{
				Tradingsymbol: "INFY", Exchange: "NSE",
				Quantity: 10, AveragePrice: 1500, LastPrice: 1600,
				PnL: 1000, DayChangePct: 2.5,
			},
			1000.0,
		},
		{
			"negative PnL on losing holding (LTP < avg)",
			broker.Holding{
				Tradingsymbol: "TCS", Exchange: "NSE",
				Quantity: 5, AveragePrice: 3500, LastPrice: 3300,
				PnL: -1000, DayChangePct: -3.5,
			},
			-1000.0,
		},
		{
			"fractional PnL (rupees+paise)",
			broker.Holding{
				Tradingsymbol: "RELIANCE", Exchange: "NSE",
				Quantity: 3, AveragePrice: 2500.50, LastPrice: 2510.75,
				PnL: 30.75,
			},
			30.75,
		},
		{
			"zero PnL on freshly-bought holding",
			broker.Holding{
				Tradingsymbol: "HDFC", Exchange: "NSE",
				Quantity: 1, AveragePrice: 1500, LastPrice: 1500,
				PnL: 0,
			},
			0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &mockBrokerClient{
				holdings:  []broker.Holding{tc.holding},
				positions: broker.Positions{Net: []broker.Position{}},
			}
			resolver := &mockBrokerResolver{client: client}
			uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())

			result, err := uc.Execute(context.Background(),
				cqrs.GetWidgetPortfolioQuery{Email: "trader@example.com"})
			require.NoError(t, err)
			require.Len(t, result.Holdings, 1)

			assert.Equal(t, tc.wantPnL, result.Holdings[0].PnL,
				"WidgetHoldingItem.PnL must equal DTO PnL exactly post-migration")

			// Aggregate total_pnl (a float field on Summary) must
			// also round-trip — the aggregation accumulator
			// deliberately stays bare-float per Slice 3 pattern,
			// but the wire output must still match the DTO.
			gotTotal, ok := result.Summary["total_pnl"].(float64)
			require.True(t, ok, "total_pnl must be float64 in the JSON wire shape")
			assert.Equal(t, tc.wantPnL, gotTotal,
				"Summary total_pnl must match the single-holding DTO PnL")
		})
	}
}

// TestSlice6b_WidgetHoldingItem_MultipleHoldings_AggregateMatches
// verifies the per-row migration doesn't break the aggregation
// invariant: with three holdings (positive, negative, zero), the
// per-row PnL fields are byte-identical AND the aggregate
// total_pnl is the algebraic sum.
func TestSlice6b_WidgetHoldingItem_MultipleHoldings_AggregateMatches(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		holdings: []broker.Holding{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10,
				AveragePrice: 1500, LastPrice: 1600, PnL: 1000, DayChangePct: 2.5},
			{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 5,
				AveragePrice: 3500, LastPrice: 3300, PnL: -1000, DayChangePct: -3.5},
			{Tradingsymbol: "HDFC", Exchange: "NSE", Quantity: 1,
				AveragePrice: 1500, LastPrice: 1500, PnL: 0},
		},
		positions: broker.Positions{Net: []broker.Position{}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())

	result, err := uc.Execute(context.Background(),
		cqrs.GetWidgetPortfolioQuery{Email: "trader@example.com"})
	require.NoError(t, err)
	require.Len(t, result.Holdings, 3)

	// Per-row preserved
	assert.Equal(t, 1000.0, result.Holdings[0].PnL)
	assert.Equal(t, -1000.0, result.Holdings[1].PnL)
	assert.Equal(t, 0.0, result.Holdings[2].PnL)

	// Aggregate is algebraic sum (1000 + -1000 + 0 = 0)
	gotTotal, ok := result.Summary["total_pnl"].(float64)
	require.True(t, ok)
	assert.Equal(t, 0.0, gotTotal,
		"aggregated total_pnl across mixed-sign holdings sums correctly")
}
