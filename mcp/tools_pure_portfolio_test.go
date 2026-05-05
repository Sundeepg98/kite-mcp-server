package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/mcp/portfolio"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// Anchor 1 PR 1.7: portfolio-internals tests (TestComputePortfolioSummary_*,
// TestComputePortfolioConcentration_*, TestComputePositionAnalysis_*) moved
// to mcp/analytics/tools_pure_portfolio_test.go because they reference
// unexported analytics-package symbols.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func TestStockSectors_NotEmpty(t *testing.T) {
	assert.Greater(t, len(portfolio.StockSectors), 50, "should have at least 50 stock-sector mappings")
}

func TestStockSectors_KnownStocks(t *testing.T) {
	knownStocks := map[string]string{
		"RELIANCE": "Energy",
		"INFY":     "IT",
		"HDFCBANK": "Banking",
		"TCS":      "IT",
	}
	for stock, expectedSector := range knownStocks {
		sector, ok := portfolio.StockSectors[stock]
		assert.True(t, ok, "stock %s should be in portfolio.StockSectors", stock)
		assert.Equal(t, expectedSector, sector, "stock %s sector mismatch", stock)
	}
}
