package analytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-money"
)

// Anchor 1 PR 1.7: portfolio-internals tests
// (TestComputePortfolioSummary_*, TestComputePortfolioConcentration_*,
// TestComputePositionAnalysis_*) previously lived in
// mcp/tools_pure_portfolio_test.go but reference unexported analytics
// symbols (computePortfolioSummary, computePortfolioConcentration,
// computePositionAnalysis). Moved here so the tests can access internals
// without exporting them.

func TestComputePortfolioSummary_Empty(t *testing.T) {
	result := computePortfolioSummary([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, 0.0, result.TotalInvested)
	assert.Equal(t, 0.0, result.TotalCurrent)
}

func TestComputePortfolioSummary_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "INFY",
			Quantity:      10,
			AveragePrice:  1500,
			LastPrice:     1600,
			DayChangePct:  2.0,
		},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, 15000.0, result.TotalInvested)
	assert.Equal(t, 16000.0, result.TotalCurrent)
	assert.Equal(t, 1000.0, result.OverallPnL)
}

func TestComputePortfolioSummary_TopGainersAndLosers(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "GAINER1", Quantity: 10, AveragePrice: 100, LastPrice: 110, DayChangePct: 5.0},
		{Tradingsymbol: "GAINER2", Quantity: 10, AveragePrice: 100, LastPrice: 120, DayChangePct: 10.0},
		{Tradingsymbol: "LOSER1", Quantity: 10, AveragePrice: 100, LastPrice: 90, DayChangePct: -5.0},
		{Tradingsymbol: "FLAT", Quantity: 10, AveragePrice: 100, LastPrice: 100, DayChangePct: 0.0},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 4, result.HoldingsCount)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
	assert.LessOrEqual(t, len(result.BiggestHoldings), 5)
}

func TestComputePortfolioConcentration_Empty(t *testing.T) {
	result := computePortfolioConcentration([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, "empty", result.Concentration)
}

func TestComputePortfolioConcentration_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, "concentrated", result.Concentration)
	assert.Equal(t, 10000.0, result.HHIScore) // 100% squared
}

func TestComputePortfolioConcentration_Diversified(t *testing.T) {
	holdings := make([]broker.Holding, 20)
	for i := range holdings {
		holdings[i] = broker.Holding{
			Tradingsymbol: "STOCK" + string(rune('A'+i)),
			Quantity:      10,
			LastPrice:     100,
		}
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 20, result.HoldingsCount)
	assert.Equal(t, "diversified", result.Concentration)
	assert.Less(t, result.HHIScore, 1500.0)
}

func TestComputePortfolioConcentration_ZeroValue(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, "empty", result.Concentration)
}

func TestComputePositionAnalysis_Empty(t *testing.T) {
	result := computePositionAnalysis([]broker.Position{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NetPositionsCount)
	assert.Equal(t, 0.0, result.TotalPnL)
}

func TestComputePositionAnalysis_WithPositions(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Exchange: "NSE", Product: "MIS", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: money.NewINR(1000)},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Product: "CNC", Quantity: -5, AveragePrice: 2500, LastPrice: 2400, PnL: money.NewINR(-500)},
		{Tradingsymbol: "TCS", Exchange: "NSE", Product: "MIS", Quantity: 20, AveragePrice: 3500, LastPrice: 3600, PnL: money.NewINR(2000)},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 3, result.NetPositionsCount)
	assert.Equal(t, 2500.0, result.TotalPnL)
	assert.GreaterOrEqual(t, len(result.ByProduct), 1)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
}

func TestComputePositionAnalysis_ProductGrouping(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Product: "MIS", PnL: money.NewINR(100)},
		{Tradingsymbol: "TCS", Product: "MIS", PnL: money.NewINR(200)},
		{Tradingsymbol: "RELIANCE", Product: "CNC", PnL: money.NewINR(-50)},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 2, len(result.ByProduct))
}

func TestComputePortfolioConcentration_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: money.NewINR(10000)},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: money.NewINR(5000)},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_SingleHolding_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computePortfolioConcentration(nil)
	assert.NotNil(t, result)
}
