package alerts

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// ===========================================================================
// Mock BrokerDataProvider
// ===========================================================================

type mockBrokerProvider struct {
	holdings    []kiteconnect.Holding
	holdingsErr error
	positions   kiteconnect.Positions
	positionsErr error
	margins     kiteconnect.AllMargins
	marginsErr  error
	ltp         kiteconnect.QuoteLTP
	ltpErr      error
}

func (m *mockBrokerProvider) GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error) {
	return m.holdings, m.holdingsErr
}

func (m *mockBrokerProvider) GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error) {
	return m.positions, m.positionsErr
}

func (m *mockBrokerProvider) GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error) {
	return m.margins, m.marginsErr
}

func (m *mockBrokerProvider) GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error) {
	return m.ltp, m.ltpErr
}

// ===========================================================================
// Mock TokenChecker
// ===========================================================================

type mockTokenChecker struct {
	tokens map[string]struct {
		accessToken string
		storedAt    time.Time
	}
	expiredFunc func(time.Time) bool
}

func (m *mockTokenChecker) GetToken(email string) (string, time.Time, bool) {
	t, ok := m.tokens[email]
	if !ok {
		return "", time.Time{}, false
	}
	return t.accessToken, t.storedAt, true
}

func (m *mockTokenChecker) IsExpired(storedAt time.Time) bool {
	if m.expiredFunc != nil {
		return m.expiredFunc(storedAt)
	}
	return false // default: not expired
}

// ===========================================================================
// Mock CredentialGetter
// ===========================================================================

type mockCredentialGetter struct {
	keys map[string]string
}

func (m *mockCredentialGetter) GetAPIKey(email string) string {
	return m.keys[email]
}

// ===========================================================================
// formatMorningBriefing — pure function tests
// ===========================================================================

func TestFormatMorningBriefing_NoAlerts_ValidToken_BeforeMarket(t *testing.T) {
	t.Parallel()
	// 8 AM IST on a Tuesday — market not yet open
	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	data := morningBriefingData{
		DateStr:         "April 7, 2026",
		Triggered:       nil,
		TokenStatus:     "valid",
		Now:             now,
		HasHoldings:     true,
		HoldingsDayPnL:  1500,
		HoldingsCount:   5,
		HasMargin:       true,
		MarginAvailable: 50000,
		HasNifty:        true,
		NiftyLTP:        22500.50,
		HasBankNifty:    true,
		BankNiftyLTP:    48000.75,
	}

	result := formatMorningBriefing(data)

	assert.Contains(t, result, "Morning Briefing")
	assert.Contains(t, result, "April 7, 2026")
	assert.Contains(t, result, "No alerts triggered overnight.")
	assert.Contains(t, result, "Token status: Valid")
	assert.Contains(t, result, "Portfolio:")
	assert.Contains(t, result, "+\u20B91500")
	assert.Contains(t, result, "5 stocks")
	assert.Contains(t, result, "Margin available:")
	assert.Contains(t, result, "50000")
	assert.Contains(t, result, "NIFTY 50:")
	assert.Contains(t, result, "22500.50")
	assert.Contains(t, result, "BANK NIFTY:")
	assert.Contains(t, result, "48000.75")
	assert.Contains(t, result, "Market opens in")
	assert.Contains(t, result, "1h 15m")
}

func TestFormatMorningBriefing_WithAlerts_ExpiredToken_AfterMarket(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc) // 10 AM — market open
	triggeredTime := time.Date(2026, 4, 6, 20, 30, 0, 0, kolkataLoc)

	data := morningBriefingData{
		DateStr: "April 7, 2026",
		Triggered: []*Alert{
			{Tradingsymbol: "RELIANCE", TriggeredPrice: 2500.50, Direction: DirectionAbove, TriggeredAt: triggeredTime},
			{Tradingsymbol: "INFY", TriggeredPrice: 1400.00, Direction: DirectionBelow, TriggeredAt: triggeredTime},
		},
		TokenStatus: "expired",
		Now:         now,
	}

	result := formatMorningBriefing(data)

	assert.Contains(t, result, "Alerts triggered overnight: 2")
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "2500.50")
	assert.Contains(t, result, "INFY")
	assert.Contains(t, result, "Token status: <b>Expired</b>")
	assert.Contains(t, result, "Market is open.")
	// No portfolio data since token expired
	assert.NotContains(t, result, "Portfolio:")
}

func TestFormatMorningBriefing_TokenNotFound(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 7, 8, 30, 0, 0, kolkataLoc)
	data := morningBriefingData{
		DateStr:     "April 7, 2026",
		TokenStatus: "not_found",
		Now:         now,
	}

	result := formatMorningBriefing(data)
	assert.Contains(t, result, "Token status: <b>Not found</b>")
}

func TestFormatMorningBriefing_MarketOpensSoon(t *testing.T) {
	t.Parallel()
	// 8:45 AM — 30 minutes to market open
	now := time.Date(2026, 4, 7, 8, 45, 0, 0, kolkataLoc)
	data := morningBriefingData{
		DateStr:     "April 7, 2026",
		TokenStatus: "valid",
		Now:         now,
	}

	result := formatMorningBriefing(data)
	assert.Contains(t, result, "Market opens in 30 minutes")
}

func TestFormatMorningBriefing_OnlyNifty(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc)
	data := morningBriefingData{
		DateStr:     "April 7, 2026",
		TokenStatus: "valid",
		Now:         now,
		HasNifty:    true,
		NiftyLTP:    22000,
	}

	result := formatMorningBriefing(data)
	assert.Contains(t, result, "NIFTY 50:")
	assert.NotContains(t, result, "BANK NIFTY:")
}

func TestFormatMorningBriefing_NegativePnL(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc)
	data := morningBriefingData{
		DateStr:        "April 7, 2026",
		TokenStatus:    "valid",
		Now:            now,
		HasHoldings:    true,
		HoldingsDayPnL: -3500,
		HoldingsCount:  10,
	}

	result := formatMorningBriefing(data)
	assert.Contains(t, result, "-\u20B93500")
}

// ===========================================================================
// formatDailySummary — pure function tests
// ===========================================================================

func TestFormatDailySummary_FullData(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr:        "April 7, 2026",
		HoldingsDayPnL: 5000,
		HoldingsCount:  10,
		Changes: []stockChange{
			{Symbol: "RELIANCE", Percent: 3.5},
			{Symbol: "INFY", Percent: 2.0},
			{Symbol: "TCS", Percent: -1.5},
			{Symbol: "HDFC", Percent: -3.0},
		},
		PositionsPnL:   -2000,
		PositionsCount: 3,
	}

	result := formatDailySummary(data)

	assert.Contains(t, result, "Daily Summary")
	assert.Contains(t, result, "April 7, 2026")
	assert.Contains(t, result, "Holdings P&amp;L: +\u20B95000 (10 stocks)")
	assert.Contains(t, result, "Positions P&amp;L: -\u20B92000 (3 positions)")
	assert.Contains(t, result, "Net Day P&amp;L: +\u20B93000")
	assert.Contains(t, result, "Top Gainers:")
	assert.Contains(t, result, "RELIANCE +3.5%")
	assert.Contains(t, result, "Top Losers:")
	assert.Contains(t, result, "HDFC -3.0%")
}

func TestFormatDailySummary_HoldingsError(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr:        "April 7, 2026",
		HoldingsErr:    true,
		PositionsPnL:   1000,
		PositionsCount: 2,
	}

	result := formatDailySummary(data)

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Positions P&amp;L: +\u20B91000 (2 positions)")
}

func TestFormatDailySummary_PositionsError(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr:        "April 7, 2026",
		HoldingsDayPnL: 2000,
		HoldingsCount:  5,
		PositionsErr:   true,
	}

	result := formatDailySummary(data)

	assert.Contains(t, result, "Holdings P&amp;L: +\u20B92000 (5 stocks)")
	assert.Contains(t, result, "Positions P&amp;L: <i>unavailable</i>")
}

func TestFormatDailySummary_NoChanges(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr:        "April 7, 2026",
		HoldingsDayPnL: 0,
		HoldingsCount:  0,
	}

	result := formatDailySummary(data)

	assert.NotContains(t, result, "Top Gainers")
	assert.NotContains(t, result, "Top Losers")
}

func TestFormatDailySummary_OnlyGainers(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr: "April 7, 2026",
		Changes: []stockChange{
			{Symbol: "A", Percent: 5.0},
			{Symbol: "B", Percent: 3.0},
		},
	}

	result := formatDailySummary(data)

	assert.Contains(t, result, "Top Gainers:")
	assert.NotContains(t, result, "Top Losers:")
}

func TestFormatDailySummary_OnlyLosers(t *testing.T) {
	t.Parallel()
	data := dailySummaryData{
		DateStr: "April 7, 2026",
		Changes: []stockChange{
			{Symbol: "A", Percent: -2.0},
			{Symbol: "B", Percent: -4.0},
		},
	}

	result := formatDailySummary(data)

	assert.NotContains(t, result, "Top Gainers:")
	assert.Contains(t, result, "Top Losers:")
}

// ===========================================================================
// formatMISWarning — pure function tests
// ===========================================================================

func TestFormatMISWarning_SingleLong(t *testing.T) {
	t.Parallel()
	open := []misPosition{
		{Symbol: "RELIANCE", Quantity: 10, PnL: 500},
	}

	result := formatMISWarning(open)

	assert.Contains(t, result, "MIS Square-Off Warning")
	assert.Contains(t, result, "1 open MIS position(s)")
	assert.Contains(t, result, "RELIANCE: LONG 10")
	assert.Contains(t, result, "+\u20B9500")
	assert.Contains(t, result, "Action: Close manually")
}

func TestFormatMISWarning_MixedPositions(t *testing.T) {
	t.Parallel()
	open := []misPosition{
		{Symbol: "RELIANCE", Quantity: 10, PnL: 500},
		{Symbol: "INFY", Quantity: -5, PnL: -200},
	}

	result := formatMISWarning(open)

	assert.Contains(t, result, "2 open MIS position(s)")
	assert.Contains(t, result, "RELIANCE: LONG 10")
	assert.Contains(t, result, "INFY: SHORT 5")
	assert.Contains(t, result, "MIS P&amp;L: <b>+\u20B9300</b>")
}

func TestFormatMISWarning_NegativePnL(t *testing.T) {
	t.Parallel()
	open := []misPosition{
		{Symbol: "TCS", Quantity: 15, PnL: -3000},
	}

	result := formatMISWarning(open)
	assert.Contains(t, result, "MIS P&amp;L: <b>-\u20B93000</b>")
}

// ===========================================================================
// filterMISPositions
// ===========================================================================

func TestFilterMISPositions_Mixed(t *testing.T) {
	t.Parallel()
	positions := kiteconnect.Positions{
		Net: []kiteconnect.Position{
			{Tradingsymbol: "RELIANCE", Product: "MIS", Quantity: 10, PnL: 500},
			{Tradingsymbol: "INFY", Product: "CNC", Quantity: 20, PnL: 1000},    // not MIS
			{Tradingsymbol: "TCS", Product: "MIS", Quantity: 0, PnL: 0},          // zero qty
			{Tradingsymbol: "HDFC", Product: "mis", Quantity: -5, PnL: -200},      // lowercase MIS
		},
	}

	result := filterMISPositions(positions)

	assert.Len(t, result, 2)
	assert.Equal(t, "RELIANCE", result[0].Symbol)
	assert.Equal(t, 10, result[0].Quantity)
	assert.Equal(t, "HDFC", result[1].Symbol)
	assert.Equal(t, -5, result[1].Quantity)
}

func TestFilterMISPositions_Empty(t *testing.T) {
	t.Parallel()
	positions := kiteconnect.Positions{}
	result := filterMISPositions(positions)
	assert.Empty(t, result)
}

func TestFilterMISPositions_NoMIS(t *testing.T) {
	t.Parallel()
	positions := kiteconnect.Positions{
		Net: []kiteconnect.Position{
			{Tradingsymbol: "RELIANCE", Product: "CNC", Quantity: 10},
			{Tradingsymbol: "INFY", Product: "NRML", Quantity: 5},
		},
	}

	result := filterMISPositions(positions)
	assert.Empty(t, result)
}

// ===========================================================================
// buildPnLEntry — pure computation tests
// ===========================================================================

func TestBuildPnLEntry_AllSuccess(t *testing.T) {
	t.Parallel()
	holdings := []kiteconnect.Holding{
		{Tradingsymbol: "RELIANCE", DayChange: 500},
		{Tradingsymbol: "INFY", DayChange: -200},
	}
	positions := kiteconnect.Positions{
		Day: []kiteconnect.Position{
			{Tradingsymbol: "TCS", PnL: 300, Quantity: 10, DayBuyQuantity: 10},
			{Tradingsymbol: "HDFC", PnL: -100, Quantity: 0, DayBuyQuantity: 0, DaySellQuantity: 0},
		},
	}

	entry := buildPnLEntry("2026-04-07", "user@example.com", holdings, nil, positions, nil)

	assert.Equal(t, "2026-04-07", entry.Date)
	assert.Equal(t, "user@example.com", entry.Email)
	assert.Equal(t, 2, entry.HoldingsCount)
	assert.InDelta(t, 300.0, entry.HoldingsPnL, 0.01)
	assert.InDelta(t, 200.0, entry.PositionsPnL, 0.01) // 300 + (-100)
	assert.Equal(t, 1, entry.TradesCount)               // only TCS has non-zero activity
	assert.InDelta(t, 500.0, entry.NetPnL, 0.01)
}

func TestBuildPnLEntry_HoldingsError(t *testing.T) {
	t.Parallel()
	positions := kiteconnect.Positions{
		Day: []kiteconnect.Position{
			{Tradingsymbol: "TCS", PnL: 100, Quantity: 5},
		},
	}

	entry := buildPnLEntry("2026-04-07", "user@example.com", nil, fmt.Errorf("API error"), positions, nil)

	assert.Equal(t, 0, entry.HoldingsCount)
	assert.Equal(t, 0.0, entry.HoldingsPnL)
	assert.Equal(t, 1, entry.TradesCount)
	assert.InDelta(t, 100.0, entry.NetPnL, 0.01)
}

func TestBuildPnLEntry_PositionsError(t *testing.T) {
	t.Parallel()
	holdings := []kiteconnect.Holding{
		{Tradingsymbol: "RELIANCE", DayChange: 1000},
	}

	entry := buildPnLEntry("2026-04-07", "user@example.com", holdings, nil, kiteconnect.Positions{}, fmt.Errorf("API error"))

	assert.Equal(t, 1, entry.HoldingsCount)
	assert.InDelta(t, 1000.0, entry.HoldingsPnL, 0.01)
	assert.Equal(t, 0, entry.TradesCount)
	assert.InDelta(t, 1000.0, entry.NetPnL, 0.01)
}

func TestBuildPnLEntry_BothErrors(t *testing.T) {
	t.Parallel()
	entry := buildPnLEntry("2026-04-07", "user@example.com", nil, fmt.Errorf("err1"), kiteconnect.Positions{}, fmt.Errorf("err2"))

	assert.Equal(t, 0, entry.HoldingsCount)
	assert.Equal(t, 0, entry.TradesCount)
	assert.Equal(t, 0.0, entry.NetPnL)
}

func TestBuildPnLEntry_DayBuyQuantityCountsTrade(t *testing.T) {
	t.Parallel()
	positions := kiteconnect.Positions{
		Day: []kiteconnect.Position{
			{PnL: 50, Quantity: 0, DayBuyQuantity: 10, DaySellQuantity: 10}, // closed position, still a trade
		},
	}
	entry := buildPnLEntry("2026-04-07", "user@example.com", nil, nil, positions, nil)
	assert.Equal(t, 1, entry.TradesCount)
}

// ===========================================================================
// Integration: buildMorningBriefing with mock BrokerDataProvider
// ===========================================================================

func TestBuildMorningBriefing_WithMockBroker(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
	}
	creds := &mockCredentialGetter{
		keys: map[string]string{"user@example.com": "test-api-key"},
	}
	mockBP := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1000, DayChangePercentage: 2.5},
		},
		margins: kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 75000},
		},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50":   {LastPrice: 22000},
			"NSE:NIFTY BANK": {LastPrice: 48000},
		},
	}

	// Create a minimal notifier-less BriefingService (we only call buildMorningBriefing)
	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: mockBP,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("user@example.com", "April 7, 2026", now)

	assert.Contains(t, result, "Morning Briefing")
	assert.Contains(t, result, "Token status: Valid")
	assert.Contains(t, result, "+\u20B91000")
	assert.Contains(t, result, "Margin available:")
	assert.Contains(t, result, "75000")
	assert.Contains(t, result, "NIFTY 50:")
	assert.Contains(t, result, "22000.00")
	assert.Contains(t, result, "BANK NIFTY:")
}

func TestBuildMorningBriefing_NoAPIKey(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
	}
	creds := &mockCredentialGetter{keys: map[string]string{}} // no API key

	bs := &BriefingService{
		alertStore: store,
		tokens:     tokens,
		creds:      creds,
		logger:     defaultTestLogger(),
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("user@example.com", "April 7, 2026", now)

	assert.Contains(t, result, "Token status: Valid")
	// No portfolio data
	assert.NotContains(t, result, "Portfolio:")
}

func TestBuildMorningBriefing_ExpiredToken(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
		expiredFunc: func(time.Time) bool { return true }, // always expired
	}
	creds := &mockCredentialGetter{keys: map[string]string{"user@example.com": "key"}}

	bs := &BriefingService{
		alertStore: store,
		tokens:     tokens,
		creds:      creds,
		logger:     defaultTestLogger(),
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("user@example.com", "April 7, 2026", now)

	assert.Contains(t, result, "Token status: <b>Expired</b>")
	assert.NotContains(t, result, "Portfolio:")
}

func TestBuildMorningBriefing_WithTriggeredAlerts(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	// Add a triggered alert
	id, _ := store.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	triggeredAt := time.Date(2026, 4, 6, 20, 30, 0, 0, kolkataLoc) // last evening
	store.MarkTriggered(id, 2550.0)
	// Manually set TriggeredAt
	store.mu.Lock()
	for _, a := range store.alerts["user@example.com"] {
		if a.ID == id {
			a.TriggeredAt = triggeredAt
		}
	}
	store.mu.Unlock()

	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
	}
	creds := &mockCredentialGetter{keys: map[string]string{"user@example.com": "key"}}
	mockBP := &mockBrokerProvider{}

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: mockBP,
	}

	// Tuesday 8 AM
	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("user@example.com", "April 7, 2026", now)

	assert.Contains(t, result, "Alerts triggered overnight: 1")
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "2550.00")
}

// ===========================================================================
// Integration: buildDailySummary with mock BrokerDataProvider
// ===========================================================================

func TestBuildDailySummary_WithMockBroker(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
	}
	creds := &mockCredentialGetter{keys: map[string]string{"user@example.com": "key"}}
	mockBP := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1000, DayChangePercentage: 2.5},
			{Tradingsymbol: "INFY", DayChange: -500, DayChangePercentage: -1.5},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "TCS", PnL: 300},
			},
		},
	}

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: mockBP,
	}

	result := bs.buildDailySummary("user@example.com", "key", "token", "April 7, 2026")

	assert.Contains(t, result, "Daily Summary")
	assert.Contains(t, result, "+\u20B9500") // 1000 - 500 = 500 holdings
	assert.Contains(t, result, "+\u20B9300") // positions
	assert.Contains(t, result, "Top Gainers:")
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "Top Losers:")
	assert.Contains(t, result, "INFY")
}

func TestBuildDailySummary_HoldingsError(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	mockBP := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("API error"),
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "TCS", PnL: 100},
			},
		},
	}

	bs := &BriefingService{
		alertStore:     store,
		logger:         defaultTestLogger(),
		brokerProvider: mockBP,
	}

	result := bs.buildDailySummary("user@example.com", "key", "token", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "+\u20B9100")
}

// ===========================================================================
// Integration: TakeSnapshots with mock BrokerDataProvider
// ===========================================================================

func TestTakeSnapshots_WithMockBroker(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
	}
	creds := &mockCredentialGetter{keys: map[string]string{"user@example.com": "key"}}
	mockBP := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1000},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "TCS", PnL: 500, Quantity: 10},
			},
		},
	}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	require.NotNil(t, svc)
	svc.SetBrokerProvider(mockBP)

	// Store a telegram chat ID so the user is found
	err := db.SaveTelegramChatID("user@example.com", 123456)
	require.NoError(t, err)

	// Store a token in the DB so LoadTokens finds the user
	err = db.SaveToken("user@example.com", "test-token", "UID01", "TestUser", time.Now())
	require.NoError(t, err)

	svc.TakeSnapshots()

	// Verify snapshot was saved
	today := time.Now().In(kolkataLoc).Format("2006-01-02")
	entries, err := db.LoadDailyPnL("user@example.com", today, today)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.InDelta(t, 1000.0, entries[0].HoldingsPnL, 0.01)
	assert.InDelta(t, 500.0, entries[0].PositionsPnL, 0.01)
	assert.InDelta(t, 1500.0, entries[0].NetPnL, 0.01)
	assert.Equal(t, 1, entries[0].HoldingsCount)
	assert.Equal(t, 1, entries[0].TradesCount)
}

func TestTakeSnapshots_ExpiredToken_Skipped(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "test-token", storedAt: time.Now()},
		},
		expiredFunc: func(time.Time) bool { return true },
	}
	creds := &mockCredentialGetter{keys: map[string]string{"user@example.com": "key"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	require.NotNil(t, svc)

	err := db.SaveTelegramChatID("user@example.com", 123456)
	require.NoError(t, err)

	svc.TakeSnapshots()

	today := time.Now().In(kolkataLoc).Format("2006-01-02")
	entries, err := db.LoadDailyPnL("user@example.com", today, today)
	require.NoError(t, err)
	assert.Empty(t, entries, "no snapshot should be saved for expired token")
}

// ===========================================================================
// SetBrokerProvider
// ===========================================================================

func TestSetBrokerProvider_BriefingService(t *testing.T) {
	t.Parallel()
	// nil-safe
	var bs *BriefingService
	bs.SetBrokerProvider(&mockBrokerProvider{}) // should not panic
}

func TestSetBrokerProvider_PnLService(t *testing.T) {
	t.Parallel()
	// nil-safe
	var svc *PnLSnapshotService
	svc.SetBrokerProvider(&mockBrokerProvider{}) // should not panic
}

// ===========================================================================
// HTML escaping in formatMorningBriefing
// ===========================================================================

func TestFormatMorningBriefing_HTMLEscaping(t *testing.T) {
	t.Parallel()
	data := morningBriefingData{
		DateStr:     "<script>alert('xss')</script>",
		TokenStatus: "valid",
		Now:         time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc),
	}

	result := formatMorningBriefing(data)
	assert.NotContains(t, result, "<script>")
	assert.Contains(t, result, "&lt;script&gt;")
}

func TestFormatMorningBriefing_AlertHTMLEscaping(t *testing.T) {
	t.Parallel()
	data := morningBriefingData{
		DateStr: "April 7, 2026",
		Triggered: []*Alert{
			{Tradingsymbol: "<b>EVIL</b>", TriggeredPrice: 100, Direction: DirectionAbove, TriggeredAt: time.Now()},
		},
		TokenStatus: "valid",
		Now:         time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc),
	}

	result := formatMorningBriefing(data)
	assert.NotContains(t, result, "<b>EVIL</b>")
	assert.True(t, strings.Contains(result, "&lt;b&gt;EVIL&lt;/b&gt;"))
}
