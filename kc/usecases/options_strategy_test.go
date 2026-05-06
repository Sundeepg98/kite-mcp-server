package usecases

import (
	"context"
	"testing"

	"github.com/algo2go/kite-mcp-broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOptionInstrumentLookup is a test double for OptionInstrumentLookup.
// Returns whatever instruments the test seeds via Add. Filter lookups on
// (underlying, optionType, strike, expiry) — exact match.
type mockOptionInstrumentLookup struct {
	instruments []OptionInstrument
}

func (m *mockOptionInstrumentLookup) FindOption(underlying, optionType string, strike float64, expiry string) (OptionInstrument, bool) {
	for _, inst := range m.instruments {
		if inst.Underlying == underlying && inst.OptionType == optionType && inst.Strike == strike && inst.Expiry == expiry {
			return inst, true
		}
	}
	return OptionInstrument{}, false
}

func (m *mockOptionInstrumentLookup) DefaultLotSize(underlying string) (int, bool) {
	for _, inst := range m.instruments {
		if inst.Underlying == underlying && inst.LotSize > 0 {
			return inst.LotSize, true
		}
	}
	return 0, false
}

// TestBuildOptionsStrategy_BullCallSpread verifies the use case builds
// a 2-leg bull-call-spread with correct legs, fetches LTPs via the
// broker client, and computes max-profit / max-loss / breakeven from
// the canonical strategy formulas.
//
// Refactor invariant (Phase (a)): output JSON shape matches the
// existing options_payoff_builder MCP tool response, so dashboard +
// MCP-tool-handler share the same use case as backend.
func TestBuildOptionsStrategy_BullCallSpread(t *testing.T) {
	t.Parallel()
	// Seed instruments + LTPs.
	instr := &mockOptionInstrumentLookup{
		instruments: []OptionInstrument{
			{Underlying: "NIFTY", OptionType: "CE", Strike: 24000, Expiry: "2026-05-29", Tradingsymbol: "NIFTY26MAY24000CE", LotSize: 50},
			{Underlying: "NIFTY", OptionType: "CE", Strike: 24500, Expiry: "2026-05-29", Tradingsymbol: "NIFTY26MAY24500CE", LotSize: 50},
		},
	}
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{
			"NFO:NIFTY26MAY24000CE": {LastPrice: 100},
			"NFO:NIFTY26MAY24500CE": {LastPrice: 40},
		},
	}
	resolver := &mockBrokerResolver{client: client}

	uc := NewBuildOptionsStrategyUseCase(resolver, instr, testLogger())
	resp, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "bull_call_spread",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Strike1:    24000,
		Strike2:    24500,
		Lots:       1,
	})

	require.NoError(t, err)
	assert.Equal(t, "bull_call_spread", resp.Strategy)
	assert.Equal(t, "NIFTY", resp.Underlying)
	assert.Len(t, resp.Legs, 2)
	// Leg 0: BUY CE 24000 @ 100
	assert.Equal(t, "BUY", resp.Legs[0].Action)
	assert.Equal(t, 24000.0, resp.Legs[0].Strike)
	assert.Equal(t, 100.0, resp.Legs[0].Premium)
	// Leg 1: SELL CE 24500 @ 40
	assert.Equal(t, "SELL", resp.Legs[1].Action)
	assert.Equal(t, 24500.0, resp.Legs[1].Strike)
	assert.Equal(t, 40.0, resp.Legs[1].Premium)

	// Net debit = 100 - 40 = 60. Per-share quantity = 1 * 50 = 50.
	// Max profit = (24500 - 24000 - 60) * 50 = 22000
	// Max loss = 60 * 50 = 3000
	// Breakeven = 24000 + 60 = 24060
	assert.InDelta(t, 22000.0, resp.MaxProfitAmt, 0.01)
	assert.InDelta(t, 3000.0, resp.MaxLossAmt, 0.01)
	require.Len(t, resp.Breakevens, 1)
	assert.InDelta(t, 24060.0, resp.Breakevens[0], 0.01)
	assert.Equal(t, 50, resp.LotSize)
	assert.Equal(t, 1, resp.TotalLots)
}

// TestBuildOptionsStrategy_Straddle verifies the unlimited-profit case.
// Straddle = BUY CE + BUY PE at same strike. Max loss = total premium paid;
// max profit = "unlimited" (string sentinel; MaxProfitAmt = 0).
func TestBuildOptionsStrategy_Straddle(t *testing.T) {
	t.Parallel()
	instr := &mockOptionInstrumentLookup{
		instruments: []OptionInstrument{
			{Underlying: "NIFTY", OptionType: "CE", Strike: 24200, Expiry: "2026-05-29", Tradingsymbol: "NIFTY26MAY24200CE", LotSize: 50},
			{Underlying: "NIFTY", OptionType: "PE", Strike: 24200, Expiry: "2026-05-29", Tradingsymbol: "NIFTY26MAY24200PE", LotSize: 50},
		},
	}
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{
			"NFO:NIFTY26MAY24200CE": {LastPrice: 80},
			"NFO:NIFTY26MAY24200PE": {LastPrice: 70},
		},
	}
	resolver := &mockBrokerResolver{client: client}

	uc := NewBuildOptionsStrategyUseCase(resolver, instr, testLogger())
	resp, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "straddle",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Strike1:    24200,
		Lots:       1,
	})
	require.NoError(t, err)
	assert.Equal(t, "unlimited", resp.MaxProfit)
	assert.Equal(t, 0.0, resp.MaxProfitAmt) // sentinel for unlimited
	// Max loss = total debit (80+70=150) * 50 = 7500
	assert.InDelta(t, 7500.0, resp.MaxLossAmt, 0.01)
	// Breakevens: 24200 ± 150 = [24050, 24350]
	require.Len(t, resp.Breakevens, 2)
	assert.InDelta(t, 24050.0, resp.Breakevens[0], 0.01)
	assert.InDelta(t, 24350.0, resp.Breakevens[1], 0.01)
}

// TestBuildOptionsStrategy_UnknownStrategy verifies unknown names return
// a clear error rather than an empty/garbage response.
func TestBuildOptionsStrategy_UnknownStrategy(t *testing.T) {
	t.Parallel()
	uc := NewBuildOptionsStrategyUseCase(&mockBrokerResolver{}, &mockOptionInstrumentLookup{}, testLogger())
	_, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "no_such_strategy",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Strike1:    24000,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown strategy")
}

// TestBuildOptionsStrategy_BullCallSpread_StrikeOrder verifies invalid
// strike ordering for bull_call_spread (strike2 must be > strike1).
func TestBuildOptionsStrategy_BullCallSpread_StrikeOrder(t *testing.T) {
	t.Parallel()
	uc := NewBuildOptionsStrategyUseCase(&mockBrokerResolver{}, &mockOptionInstrumentLookup{}, testLogger())
	_, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "bull_call_spread",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Strike1:    24500,
		Strike2:    24000, // wrong order
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strike2 > strike1")
}

// TestBuildOptionsStrategy_InstrumentNotFound verifies a missing instrument
// (e.g. typo strike, wrong expiry) returns a clear error.
func TestBuildOptionsStrategy_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	instr := &mockOptionInstrumentLookup{instruments: []OptionInstrument{}}
	uc := NewBuildOptionsStrategyUseCase(&mockBrokerResolver{client: &mockBrokerClient{}}, instr, testLogger())
	_, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "bull_call_spread",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Strike1:    99999,
		Strike2:    100000,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "instrument")
}

// TestBuildOptionsStrategy_InvalidExpiry verifies the YYYY-MM-DD format check.
func TestBuildOptionsStrategy_InvalidExpiry(t *testing.T) {
	t.Parallel()
	uc := NewBuildOptionsStrategyUseCase(&mockBrokerResolver{}, &mockOptionInstrumentLookup{}, testLogger())
	_, err := uc.Execute(context.Background(), BuildOptionsStrategyCommand{
		Email:      "u@test.com",
		Strategy:   "straddle",
		Underlying: "NIFTY",
		Expiry:     "29-05-2026", // wrong format
		Strike1:    24200,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expiry")
}
