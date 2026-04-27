package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/money"
)

func TestComputeTaxHarvest(t *testing.T) {
	t.Parallel()
	t.Run("empty holdings", func(t *testing.T) {
		resp := computeTaxHarvest([]broker.Holding{}, 0)
		assert.Equal(t, 0, resp.Summary.HoldingsCount)
		assert.Empty(t, resp.HarvestCandidates)
		assert.Empty(t, resp.ApproachingLTCG)
		assert.Empty(t, resp.AllHoldings)
	})

	t.Run("single gaining STCG holding", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "RELIANCE",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  2000,
				LastPrice:     2500,
				PnL: money.NewINR(5000),
			},
		}
		resp := computeTaxHarvest(holdings, 0)

		assert.Equal(t, 1, resp.Summary.HoldingsCount)
		assert.InDelta(t, 20000.0, resp.Summary.TotalInvested, 0.01)
		assert.InDelta(t, 25000.0, resp.Summary.TotalCurrent, 0.01)
		assert.InDelta(t, 5000.0, resp.Summary.TotalUnrealizedPnL, 0.01)
		assert.InDelta(t, 5000.0, resp.Summary.STCGGains, 0.01)
		assert.InDelta(t, 1000.0, resp.Summary.STCGTaxEstimate, 0.01) // 5000 * 0.20
		assert.Equal(t, 0, resp.Summary.HarvestCandidatesCnt)
		assert.Empty(t, resp.HarvestCandidates)

		entry := resp.AllHoldings[0]
		assert.Equal(t, "STCG", entry.HoldingPeriod)
		assert.Equal(t, 0.20, entry.TaxRate)
		assert.InDelta(t, 1000.0, entry.EstimatedTax, 0.01)
		assert.False(t, entry.Harvestable)
	})

	t.Run("single losing STCG holding is harvestable", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "PAYTM",
				Exchange:      "NSE",
				Quantity:      100,
				AveragePrice:  500,
				LastPrice:     300,
				PnL: money.NewINR(-20000),
			},
		}
		resp := computeTaxHarvest(holdings, 0)

		assert.Equal(t, 1, resp.Summary.HarvestCandidatesCnt)
		assert.InDelta(t, -20000.0, resp.Summary.TotalHarvestable, 0.01)
		assert.InDelta(t, 4000.0, resp.Summary.TotalTaxSavings, 0.01) // 20000 * 0.20

		assert.Len(t, resp.HarvestCandidates, 1)
		assert.Equal(t, "PAYTM", resp.HarvestCandidates[0].Symbol)
		assert.True(t, resp.HarvestCandidates[0].Harvestable)
		assert.InDelta(t, 4000.0, resp.HarvestCandidates[0].TaxSavings, 0.01)
	})

	t.Run("LTCG classification via assume_ltcg_days", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "INFY",
				Exchange:      "NSE",
				Quantity:      50,
				AveragePrice:  1000,
				LastPrice:     1800,
				PnL: money.NewINR(40000),
			},
		}
		resp := computeTaxHarvest(holdings, 400) // assume 400 days (> 365 = LTCG)

		entry := resp.AllHoldings[0]
		assert.Equal(t, "LTCG", entry.HoldingPeriod)
		assert.Equal(t, 0.125, entry.TaxRate)
		assert.InDelta(t, 40000.0, entry.UnrealizedPnL, 0.01)
		assert.InDelta(t, 5000.0, entry.EstimatedTax, 0.01) // 40000 * 0.125

		// LTCG exemption applied at summary level: 40000 < 125000, so net tax = 0
		assert.InDelta(t, 0.0, resp.Summary.LTCGTaxEstimate, 0.01)
	})

	t.Run("LTCG exemption threshold", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "TCS",
				Exchange:      "NSE",
				Quantity:      100,
				AveragePrice:  3000,
				LastPrice:     5000,
				PnL: money.NewINR(200000),
			},
		}
		resp := computeTaxHarvest(holdings, 500) // assume 500 days (LTCG)

		// Gain: 200000, Exemption: 125000, Taxable: 75000, Tax: 75000 * 0.125 = 9375
		assert.InDelta(t, 200000.0, resp.Summary.LTCGGains, 0.01)
		assert.InDelta(t, 9375.0, resp.Summary.LTCGTaxEstimate, 0.01)
	})

	t.Run("assume_ltcg_days overrides unknown dates", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "HDFCBANK",
				Exchange:      "NSE",
				Quantity:      20,
				AveragePrice:  1500,
				LastPrice:     1700,
				PnL: money.NewINR(4000),
			},
		}
		resp := computeTaxHarvest(holdings, 400) // assume 400 days

		entry := resp.AllHoldings[0]
		assert.Equal(t, "LTCG", entry.HoldingPeriod)
		assert.Equal(t, 400, entry.HoldingDays)
		assert.Equal(t, 0.125, entry.TaxRate)
		assert.Equal(t, 400, resp.Summary.AssumedHoldingDays)
	})

	t.Run("approaching LTCG detection via assume_ltcg_days", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "SBIN",
				Exchange:      "NSE",
				Quantity:      30,
				AveragePrice:  600,
				LastPrice:     550,
				PnL: money.NewINR(-1500),
			},
		}
		resp := computeTaxHarvest(holdings, 345) // 20 days from LTCG threshold

		assert.Equal(t, 1, resp.Summary.ApproachingLTCGCnt)
		assert.Len(t, resp.ApproachingLTCG, 1)
		assert.Equal(t, "SBIN", resp.ApproachingLTCG[0].Symbol)
		assert.True(t, resp.ApproachingLTCG[0].ApproachingLTCG)
		assert.Equal(t, "STCG", resp.ApproachingLTCG[0].HoldingPeriod) // still STCG
	})

	t.Run("mixed portfolio with harvest candidates sorted by savings", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "LOSER_BIG",
				Exchange:      "NSE",
				Quantity:      100,
				AveragePrice:  1000,
				LastPrice:     500,
				PnL: money.NewINR(-50000),
			},
			{
				Tradingsymbol: "LOSER_SMALL",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  200,
				LastPrice:     150,
				PnL: money.NewINR(-500),
			},
			{
				Tradingsymbol: "GAINER",
				Exchange:      "NSE",
				Quantity:      50,
				AveragePrice:  100,
				LastPrice:     200,
				PnL: money.NewINR(5000),
			},
		}
		resp := computeTaxHarvest(holdings, 0)

		assert.Equal(t, 2, resp.Summary.HarvestCandidatesCnt)
		assert.Len(t, resp.HarvestCandidates, 2)
		// Sorted by tax savings descending
		assert.Equal(t, "LOSER_BIG", resp.HarvestCandidates[0].Symbol)
		assert.Equal(t, "LOSER_SMALL", resp.HarvestCandidates[1].Symbol)
		assert.InDelta(t, 10000.0, resp.HarvestCandidates[0].TaxSavings, 0.01) // 50000 * 0.20
		assert.InDelta(t, 100.0, resp.HarvestCandidates[1].TaxSavings, 0.01)   // 500 * 0.20
	})

	t.Run("STCG losses offset gains at summary level", func(t *testing.T) {
		holdings := []broker.Holding{
			{
				Tradingsymbol: "WINNER",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  100,
				LastPrice:     200,
				PnL: money.NewINR(1000),
			},
			{
				Tradingsymbol: "LOSER",
				Exchange:      "NSE",
				Quantity:      10,
				AveragePrice:  200,
				LastPrice:     100,
				PnL: money.NewINR(-1000),
			},
		}
		resp := computeTaxHarvest(holdings, 0)

		// Net STCG = 1000 - 1000 = 0, so no tax
		assert.InDelta(t, 0.0, resp.Summary.STCGTaxEstimate, 0.01)
		assert.InDelta(t, 1000.0, resp.Summary.STCGGains, 0.01)
		assert.InDelta(t, -1000.0, resp.Summary.STCGLosses, 0.01)
	})
}

func TestTaxHarvestToolDefinition(t *testing.T) {
	t.Parallel()
	tool := &TaxHarvestTool{}
	def := tool.Tool()

	assert.Equal(t, "tax_loss_analysis", def.Name)
	assert.Contains(t, def.Description, "12.5% LTCG")
	assert.Contains(t, def.Description, "20% STCG")
	assert.Contains(t, def.Description, "Not investment advice")
}
