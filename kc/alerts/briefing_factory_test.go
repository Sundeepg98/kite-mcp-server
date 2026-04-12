package alerts

// Tests for BriefingService using the SetBrokerProvider injection point.
// Covers realistic multi-stock portfolios flowing through buildMorningBriefing,
// buildDailySummary, and SendMISWarnings with assertions on formatted output.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// realisticBrokerProvider returns a mockBrokerProvider populated with
// a multi-stock portfolio resembling a real Indian retail investor.
func realisticBrokerProvider() *mockBrokerProvider {
	return &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1200, DayChangePercentage: 2.1, Quantity: 15},
			{Tradingsymbol: "INFY", DayChange: -800, DayChangePercentage: -1.5, Quantity: 25},
			{Tradingsymbol: "HDFCBANK", DayChange: 500, DayChangePercentage: 0.9, Quantity: 20},
			{Tradingsymbol: "TCS", DayChange: -200, DayChangePercentage: -0.4, Quantity: 10},
			{Tradingsymbol: "TATAMOTORS", DayChange: 3000, DayChangePercentage: 4.5, Quantity: 50},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 1500, DayBuyQuantity: 100, Product: "MIS"},
				{Tradingsymbol: "BHARTIARTL", PnL: -300, DayBuyQuantity: 50, Product: "MIS"},
			},
			Net: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 1500, Quantity: 100, Product: "MIS"},
				{Tradingsymbol: "BHARTIARTL", PnL: -300, Quantity: -50, Product: "MIS"},
			},
		},
		margins: kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 125000},
		},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50":   {LastPrice: 22345.60},
			"NSE:NIFTY BANK": {LastPrice: 48120.75},
		},
	}
}

// TestBuildMorningBriefing_RealisticPortfolio exercises the full data flow
// from broker provider through buildMorningBriefing with 5 holdings + indices.
func TestBuildMorningBriefing_RealisticPortfolio(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 30, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Portfolio: sum of DayChange = 1200 - 800 + 500 - 200 + 3000 = 3700
	assert.Contains(t, result, "+₹3700")
	assert.Contains(t, result, "5 stocks")
	assert.Contains(t, result, "Margin available: ₹125000")
	assert.Contains(t, result, "NIFTY 50: ₹22345.60")
	assert.Contains(t, result, "BANK NIFTY: ₹48120.75")
	assert.Contains(t, result, "Market opens in 45 minutes")
}

// TestBuildMorningBriefing_WithTriggeredAlerts_RealisticData tests that
// overnight alerts appear alongside portfolio data in the morning briefing.
func TestBuildMorningBriefing_WithTriggeredAlerts_RealisticData(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	// Add a triggered alert
	id, err := store.Add("trader@test.com", "RELIANCE", "NSE", 738561, 2800.0, DirectionAbove)
	require.NoError(t, err)
	store.MarkTriggered(id, 2810.50)

	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc) // Monday morning
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	assert.Contains(t, result, "Alerts triggered overnight: 1")
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "2810.50")
	assert.Contains(t, result, "above")
	// Portfolio data should still be present
	assert.Contains(t, result, "Portfolio:")
	assert.Contains(t, result, "Token status: Valid")
}

// TestBuildDailySummary_RealisticPortfolio exercises buildDailySummary
// with a multi-stock portfolio, checking gainers/losers output.
func TestBuildDailySummary_RealisticPortfolio(t *testing.T) {
	t.Parallel()

	bp := realisticBrokerProvider()
	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	// Holdings P&L: 1200 - 800 + 500 - 200 + 3000 = 3700
	assert.Contains(t, result, "+₹3700")
	assert.Contains(t, result, "5 stocks")
	// Positions P&L: 1500 + (-300) = 1200
	assert.Contains(t, result, "+₹1200")
	assert.Contains(t, result, "2 positions")
	// Net = 3700 + 1200 = 4900
	assert.Contains(t, result, "Net Day P&amp;L: +₹4900")
	// Top Gainers should include TATAMOTORS (4.5%), RELIANCE (2.1%)
	assert.Contains(t, result, "Top Gainers:")
	assert.Contains(t, result, "TATAMOTORS +4.5%")
	assert.Contains(t, result, "RELIANCE +2.1%")
	// Top Losers should include INFY (-1.5%)
	assert.Contains(t, result, "Top Losers:")
	assert.Contains(t, result, "INFY -1.5%")
}

// TestBuildDailySummary_BrokerErrors_Graceful verifies that broker errors
// produce "unavailable" in the summary without panicking.
func TestBuildDailySummary_BrokerErrors_Graceful(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr:  fmt.Errorf("network error"),
		positionsErr: fmt.Errorf("timeout"),
	}
	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Positions P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Net Day P&amp;L: +₹0")
}

// TestSendMorningBriefings_RealisticMultiUser exercises SendMorningBriefings
// end-to-end with two users having different portfolio sizes.
func TestSendMorningBriefings_RealisticMultiUser(t *testing.T) {
	store := storeWithChat(map[string]int64{
		"alice@test.com": 100,
		"bob@test.com":   200,
	})
	tokens := validTokenChecker("alice@test.com", "bob@test.com")
	creds := credsFor(map[string]string{
		"alice@test.com": "key-alice",
		"bob@test.com":   "key-bob",
	})
	bp := realisticBrokerProvider()

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	// Should not panic and should send to both users.
	bs.SendMorningBriefings()
}

// TestSendDailySummaries_RealisticSingleUser exercises SendDailySummaries
// end-to-end with realistic data flowing through the mock broker provider.
func TestSendDailySummaries_RealisticSingleUser(t *testing.T) {
	store := storeWithChat(map[string]int64{"trader@test.com": 100})
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	bs.SendDailySummaries()
}

// TestSendMISWarnings_RealisticPositions exercises SendMISWarnings
// with open MIS positions flowing through the mock broker provider.
func TestSendMISWarnings_RealisticPositions(t *testing.T) {
	store := storeWithChat(map[string]int64{"trader@test.com": 100})
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider() // has MIS positions in Net

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	bs.SendMISWarnings()
}

// TestFormatMISWarning_RealisticPositions validates the content of MIS
// warning messages with both long and short positions.
func TestFormatMISWarning_RealisticPositions(t *testing.T) {
	t.Parallel()

	open := []misPosition{
		{Symbol: "SBIN", Quantity: 100, PnL: 1500},
		{Symbol: "BHARTIARTL", Quantity: -50, PnL: -300},
	}

	result := formatMISWarning(open)

	assert.Contains(t, result, "MIS Square-Off Warning")
	assert.Contains(t, result, "2 open MIS position(s)")
	assert.Contains(t, result, "SBIN: LONG 100")
	assert.Contains(t, result, "+₹1500")
	assert.Contains(t, result, "BHARTIARTL: SHORT 50")
	assert.Contains(t, result, "-₹300")
	// Net MIS P&L = 1500 + (-300) = 1200
	assert.Contains(t, result, "MIS P&amp;L: <b>+₹1200</b>")
	assert.Contains(t, result, "convert to CNC/NRML")
}

// TestBuildMorningBriefing_NegativePortfolio exercises the negative P&L
// formatting path with all holdings in the red.
func TestBuildMorningBriefing_NegativePortfolio(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: -2000, DayChangePercentage: -3.5, Quantity: 15},
			{Tradingsymbol: "INFY", DayChange: -1500, DayChangePercentage: -2.8, Quantity: 25},
		},
		margins: kiteconnect.AllMargins{Equity: kiteconnect.Margins{Net: 50000}},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50": {LastPrice: 21500},
		},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Total day P&L = -2000 + (-1500) = -3500
	assert.Contains(t, result, "-₹3500")
	assert.Contains(t, result, "2 stocks")
	assert.Contains(t, result, "Market is open.")
	// Only NIFTY 50, no BANK NIFTY
	assert.Contains(t, result, "NIFTY 50: ₹21500.00")
	assert.NotContains(t, result, "BANK NIFTY:")
}

// TestBuildMorningBriefing_LTPError_GracefulDegradation tests that
// LTP errors are handled gracefully — indices section simply omitted.
func TestBuildMorningBriefing_LTPError_GracefulDegradation(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 500, Quantity: 10},
		},
		margins: kiteconnect.AllMargins{Equity: kiteconnect.Margins{Net: 80000}},
		ltpErr:  fmt.Errorf("connection refused"),
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Holdings still show up
	assert.Contains(t, result, "+₹500")
	assert.Contains(t, result, "Margin available:")
	// No indices section
	assert.NotContains(t, result, "NIFTY 50:")
	assert.NotContains(t, result, "BANK NIFTY:")
}

// TestBuildDailySummary_OnlyHoldingsError tests partial failure
// where only holdings fetch fails but positions succeed.
func TestBuildDailySummary_OnlyHoldingsError(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("API rate limited"),
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 2500},
			},
		},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Positions P&amp;L: +₹2500")
	// Net = 0 (holdings err) + 2500 = 2500
	assert.Contains(t, result, "Net Day P&amp;L: +₹2500")
}

// TestFilterMISPositions_RealisticMix tests filtering with a mix of
// MIS and CNC positions, ensuring only open MIS positions are returned.
func TestFilterMISPositions_RealisticMix(t *testing.T) {
	t.Parallel()

	positions := kiteconnect.Positions{
		Net: []kiteconnect.Position{
			{Tradingsymbol: "SBIN", Quantity: 100, Product: "MIS", PnL: 1500},
			{Tradingsymbol: "RELIANCE", Quantity: 15, Product: "CNC", PnL: 800},
			{Tradingsymbol: "BHARTIARTL", Quantity: -50, Product: "MIS", PnL: -300},
			{Tradingsymbol: "INFY", Quantity: 0, Product: "MIS", PnL: 0}, // closed MIS — should be excluded
			{Tradingsymbol: "TCS", Quantity: 20, Product: "NRML", PnL: 200},
		},
	}

	open := filterMISPositions(positions)

	assert.Len(t, open, 2)

	var symbols []string
	for _, p := range open {
		symbols = append(symbols, p.Symbol)
	}
	assert.Contains(t, symbols, "SBIN")
	assert.Contains(t, symbols, "BHARTIARTL")
	// CNC, NRML, and closed MIS should be excluded
	assert.NotContains(t, symbols, "RELIANCE")
	assert.NotContains(t, symbols, "INFY")
	assert.NotContains(t, symbols, "TCS")
}

// TestBrokerProvider_DefaultFallback verifies that broker() returns
// defaultBrokerProvider when brokerProvider is nil.
func TestBrokerProvider_DefaultFallback(t *testing.T) {
	t.Parallel()

	bs := &BriefingService{
		alertStore: newTestStore(),
		logger:     defaultTestLogger(),
	}

	bp := bs.broker()
	assert.NotNil(t, bp)
	_, isDefault := bp.(*defaultBrokerProvider)
	assert.True(t, isDefault, "expected defaultBrokerProvider when brokerProvider is nil")
}

// TestBrokerProvider_OverrideUsed verifies that SetBrokerProvider
// correctly replaces the default broker.
func TestBrokerProvider_OverrideUsed(t *testing.T) {
	t.Parallel()

	bs := &BriefingService{
		alertStore: newTestStore(),
		logger:     defaultTestLogger(),
	}

	mock := &mockBrokerProvider{}
	bs.SetBrokerProvider(mock)

	bp := bs.broker()
	assert.Equal(t, mock, bp, "expected mock broker after SetBrokerProvider")
}

// TestBuildDailySummary_EmptyPortfolio tests the case where holdings
// and positions both return empty (new user with no trades).
func TestBuildDailySummary_EmptyPortfolio(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings:  []kiteconnect.Holding{},
		positions: kiteconnect.Positions{},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("newuser@test.com"),
		creds:          credsFor(map[string]string{"newuser@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("newuser@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: +₹0 (0 stocks)")
	assert.Contains(t, result, "Positions P&amp;L: +₹0 (0 positions)")
	assert.Contains(t, result, "Net Day P&amp;L: +₹0")
	assert.NotContains(t, result, "Top Gainers")
	assert.NotContains(t, result, "Top Losers")
}

// TestBuildMorningBriefing_AllBrokerErrors tests graceful degradation
// when all broker API calls fail — still produces valid briefing.
func TestBuildMorningBriefing_AllBrokerErrors(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("holdings error"),
		marginsErr:  fmt.Errorf("margins error"),
		ltpErr:      fmt.Errorf("ltp error"),
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Should still produce a valid briefing with token status
	assert.Contains(t, result, "Morning Briefing")
	assert.Contains(t, result, "Token status: Valid")
	// No portfolio/margin/indices data
	assert.NotContains(t, result, "Portfolio:")
	assert.NotContains(t, result, "Margin available:")
	assert.NotContains(t, result, "NIFTY 50:")
	// Market timing still works
	assert.True(t, strings.Contains(result, "Market opens in") || strings.Contains(result, "Market is open"))
}
