package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/money"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestComputeSectorExposure_Empty(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
}


func TestComputeSectorExposure_ZeroValue(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Empty(t, result.Sectors)
}


func TestComputeSectorExposure_MappedStocks(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500},
		{Tradingsymbol: "HDFCBANK", Quantity: 20, LastPrice: 1600},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 3, result.HoldingsCount)
	assert.Equal(t, 3, result.MappedCount)
	assert.Equal(t, 0, result.UnmappedCount)
	assert.GreaterOrEqual(t, len(result.Sectors), 2) // IT and Banking
}


func TestComputeSectorExposure_UnmappedStocks(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "UNKNOWNSTOCK", Quantity: 10, LastPrice: 100},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.UnmappedCount)
	assert.Len(t, result.UnmappedStocks, 1)
}


func TestComputeSectorExposure_OverExposed(t *testing.T) {
	t.Parallel()
	// Single stock = 100% in one sector = over-exposed
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computeSectorExposure(holdings)
	assert.GreaterOrEqual(t, len(result.Warnings), 1)
}


func TestComputeDividendCalendar_Empty(t *testing.T) {
	t.Parallel()
	result := computeDividendCalendar([]broker.Holding{}, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.Summary.HoldingsCount)
}


func TestComputeDividendCalendar_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500, AveragePrice: 1400},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500, AveragePrice: 3200},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.Equal(t, 2, result.Summary.HoldingsCount)
	assert.NotNil(t, result.HoldingsByYield)
}


func TestComputeDividendCalendar_ZeroDayLookAhead(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "RELIANCE", Quantity: 10, LastPrice: 2500},
	}
	result := computeDividendCalendar(holdings, 0)
	assert.NotNil(t, result)
}


func TestComputeSectorExposure_KnownStocks(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1500, LastPrice: 1600},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 50, AveragePrice: 1600, LastPrice: 1700},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.Sectors), 2, "Should have at least 2 sectors")
}


func TestComputeSectorExposure_UnknownStock(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "XYZUNKNOWN", Exchange: "NSE", Quantity: 100, AveragePrice: 100, LastPrice: 110},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.UnmappedStocks), 1, "Unknown stock should be unmapped")
}


func TestComputeSectorExposure_NoHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Empty(t, result.Sectors)
}


func TestComputeDividendCalendar_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeDividendCalendar(nil, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.HoldingsByYield))
}


func TestComputeDividendCalendar_WithHoldings_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: money.NewINR(10000)},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: money.NewINR(5000)},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, AveragePrice: 3400, LastPrice: 3500, PnL: money.NewINR(2000)},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 30, AveragePrice: 1600, LastPrice: 1700, PnL: money.NewINR(3000)},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.HoldingsByYield), 0)
	assert.NotEmpty(t, result.TaxNote)
}


func TestComputeDividendCalendar_SingleHolding(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1000, LastPrice: 0, PnL: money.NewINR(0)},
	}
	result := computeDividendCalendar(holdings, 365)
	assert.NotNil(t, result)
}


func TestComputeSectorExposure_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, LastPrice: 2500},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, LastPrice: 3500},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
}


func TestComputeSectorExposure_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure(nil)
	assert.NotNil(t, result)
}
