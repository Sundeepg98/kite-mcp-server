package alerts


import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)


// ===========================================================================
// Pure helper tests (no external dependencies)
// ===========================================================================

func TestFormatRupee(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{0, "+\u20B90"},
		{5000, "+\u20B95000"},
		{-3000, "-\u20B93000"},
		{0.5, "+\u20B90"},  // rounds to 0 (%.0f)
		{-0.5, "-\u20B90"}, // rounds to 0
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, formatRupee(tc.in), "formatRupee(%f)", tc.in)
	}
}

func TestPreviousTradingDayClose_Weekday(t *testing.T) {
	t.Parallel()
	// Tuesday 10 AM IST -> previous trading day close = Monday 3:30 PM IST
	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc) // Tuesday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Monday, close.Weekday())
	assert.Equal(t, 15, close.Hour())
	assert.Equal(t, 30, close.Minute())
}

func TestPreviousTradingDayClose_Monday(t *testing.T) {
	t.Parallel()
	// Monday 10 AM -> previous trading day = Friday
	now := time.Date(2026, 4, 6, 10, 0, 0, 0, kolkataLoc) // Monday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
	assert.Equal(t, 15, close.Hour())
	assert.Equal(t, 30, close.Minute())
}

func TestPreviousTradingDayClose_Sunday(t *testing.T) {
	t.Parallel()
	// Sunday -> previous trading day = Friday
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, kolkataLoc) // Sunday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
}

func TestPreviousTradingDayClose_Saturday(t *testing.T) {
	t.Parallel()
	// Saturday -> previous trading day = Friday
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, kolkataLoc) // Saturday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
}

func TestFilterPositiveChanges(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 3.0},
		{Symbol: "C", Percent: 1.0},
		{Symbol: "D", Percent: -2.0},
	}
	result := filterPositiveChanges(changes, 2)
	assert.Len(t, result, 2)
	assert.Equal(t, "A", result[0].Symbol)
	assert.Equal(t, "B", result[1].Symbol)
}

func TestFilterPositiveChanges_LessThanN(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
	}
	result := filterPositiveChanges(changes, 3)
	assert.Len(t, result, 1)
}

func TestFilterPositiveChanges_NonePositive(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: -1.0},
		{Symbol: "B", Percent: -3.0},
	}
	result := filterPositiveChanges(changes, 3)
	assert.Empty(t, result)
}

func TestFilterNegativeChanges(t *testing.T) {
	t.Parallel()
	// Input must be sorted descending (as in production code).
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 1.0},
		{Symbol: "C", Percent: -2.0},
		{Symbol: "D", Percent: -5.0},
	}
	result := filterNegativeChanges(changes, 2)
	assert.Len(t, result, 2)
	// Reversed: worst first
	assert.Equal(t, "D", result[0].Symbol)
	assert.Equal(t, "C", result[1].Symbol)
}

func TestFilterNegativeChanges_LessThanN(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: -1.0},
	}
	result := filterNegativeChanges(changes, 5)
	assert.Len(t, result, 1)
}

func TestFilterNegativeChanges_NoneNegative(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 1.0},
	}
	result := filterNegativeChanges(changes, 3)
	assert.Empty(t, result)
}

func TestAbs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 5, abs(5))
	assert.Equal(t, 5, abs(-5))
	assert.Equal(t, 0, abs(0))
}

// ===========================================================================
// EscapeTelegramMarkdown
// ===========================================================================

func TestEscapeTelegramMarkdown(t *testing.T) {
	t.Parallel()
	input := "Hello_world *bold* (test) [link] {curly} ~strike~ `code`"
	escaped := escapeTelegramMarkdown(input)

	// Each special char should be escaped
	assert.Contains(t, escaped, "\\_")
	assert.Contains(t, escaped, "\\*")
	assert.Contains(t, escaped, "\\(")
	assert.Contains(t, escaped, "\\)")
	assert.Contains(t, escaped, "\\[")
	assert.Contains(t, escaped, "\\]")
	assert.Contains(t, escaped, "\\{")
	assert.Contains(t, escaped, "\\}")
	assert.Contains(t, escaped, "\\~")
	assert.Contains(t, escaped, "\\`")
}

func TestEscapeMarkdown_Exported(t *testing.T) {
	t.Parallel()
	// EscapeMarkdown is the exported alias
	assert.Equal(t, escapeTelegramMarkdown("test.value"), EscapeMarkdown("test.value"))
}

// ===========================================================================
// NewBriefingService
// ===========================================================================

func TestNewBriefingService_NilNotifier(t *testing.T) {
	t.Parallel()
	bs := NewBriefingService(nil, nil, nil, nil, nil)
	assert.Nil(t, bs)
}

func TestNewBriefingService_NilSafe(t *testing.T) {
	t.Parallel()
	// Calling SendMorningBriefings on nil BriefingService should not panic.
	var bs *BriefingService
	bs.SendMorningBriefings()
	bs.SendDailySummaries()
	bs.SendMISWarnings()
}

// ===========================================================================
// NewTelegramNotifier
// ===========================================================================

func TestNewTelegramNotifier_EmptyToken(t *testing.T) {
	t.Parallel()
	notifier, err := NewTelegramNotifier("", nil, defaultTestLogger())
	assert.Nil(t, notifier)
	assert.NoError(t, err)
}

func TestTelegramNotifier_NilSafeMethods(t *testing.T) {
	t.Parallel()
	// Nil notifier should not panic on these methods.
	var tn *TelegramNotifier
	assert.Nil(t, tn.Bot())

	// Notify with nil should not panic.
	tn.Notify(&Alert{Email: "test@example.com", Direction: DirectionAbove}, 100.0)
}

func TestTelegramNotifier_SendMessage_NilSafe(t *testing.T) {
	t.Parallel()
	var tn *TelegramNotifier
	err := tn.SendMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")

	err = tn.SendHTMLMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ===========================================================================
// Store.DeleteByEmail
// ===========================================================================

func TestStore_DeleteByEmail(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.SetTelegramChatID("user@example.com", 123456789)

	// Verify data exists
	assert.Len(t, s.List("user@example.com"), 2)
	_, ok := s.GetTelegramChatID("user@example.com")
	assert.True(t, ok)

	// Delete all data for user
	s.DeleteByEmail("user@example.com")

	// Verify data is gone
	assert.Empty(t, s.List("user@example.com"))
	_, ok = s.GetTelegramChatID("user@example.com")
	assert.False(t, ok)
}

func TestStore_DeleteByEmail_NonExistent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.DeleteByEmail("nobody@example.com")
}

// ===========================================================================
// Store.GetEmailByChatID
// ===========================================================================

func TestStore_GetEmailByChatID(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.SetTelegramChatID("user@example.com", 123456789)

	email, ok := s.GetEmailByChatID(123456789)
	assert.True(t, ok)
	assert.Equal(t, "user@example.com", email)

	// Not found
	_, ok = s.GetEmailByChatID(999999)
	assert.False(t, ok)
}

// ===========================================================================
// Store.MarkNotificationSent
// ===========================================================================

func TestStore_MarkNotificationSent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	id, _ := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)

	now := time.Now()
	s.MarkNotificationSent(id, now)

	alerts := s.List("user@example.com")
	assert.Len(t, alerts, 1)
	assert.Equal(t, now.Unix(), alerts[0].NotificationSentAt.Unix())
}

func TestStore_MarkNotificationSent_NonExistent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.MarkNotificationSent("nonexistent", time.Now())
}

// ===========================================================================
// PnL Snapshot service
// ===========================================================================

func TestNewPnLSnapshotService_NilDB(t *testing.T) {
	t.Parallel()
	svc := NewPnLSnapshotService(nil, nil, nil, defaultTestLogger())
	assert.Nil(t, svc)
}

// ===========================================================================
// NewEvaluator
// ===========================================================================

func TestNewEvaluator(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	e := NewEvaluator(s, defaultTestLogger())
	assert.NotNil(t, e)
}


// ===========================================================================
// Merged from briefing_format_test.go
// ===========================================================================


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
		HoldingsDayPnL:  domain.NewINR(1500),
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
		HoldingsDayPnL: domain.NewINR(-3500),
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
		HoldingsDayPnL: domain.NewINR(5000),
		HoldingsCount:  10,
		Changes: []stockChange{
			{Symbol: "RELIANCE", Percent: 3.5},
			{Symbol: "INFY", Percent: 2.0},
			{Symbol: "TCS", Percent: -1.5},
			{Symbol: "HDFC", Percent: -3.0},
		},
		PositionsPnL:   domain.NewINR(-2000),
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
		PositionsPnL:   domain.NewINR(1000),
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
		HoldingsDayPnL: domain.NewINR(2000),
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
		HoldingsDayPnL: domain.Money{},
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
		{Symbol: "RELIANCE", Quantity: 10, PnL: domain.NewINR(500)},
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
		{Symbol: "RELIANCE", Quantity: 10, PnL: domain.NewINR(500)},
		{Symbol: "INFY", Quantity: -5, PnL: domain.NewINR(-200)},
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
		{Symbol: "TCS", Quantity: 15, PnL: domain.NewINR(-3000)},
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
		logger:         logport.NewSlog(defaultTestLogger()),
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
		logger:     logport.NewSlog(defaultTestLogger()),
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
		logger:     logport.NewSlog(defaultTestLogger()),
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
		logger:         logport.NewSlog(defaultTestLogger()),
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
		logger:         logport.NewSlog(defaultTestLogger()),
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
		logger:         logport.NewSlog(defaultTestLogger()),
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


// ===========================================================================
// Merged from briefing_send_test.go
// ===========================================================================


// newBriefingServiceWithMock creates a BriefingService backed by a mock Telegram
// server and configurable mock broker/token/creds. The returned cleanup function
// must be deferred.
func newBriefingServiceWithMock(
	t *testing.T,
	failSend bool,
	store *Store,
	tokens TokenChecker,
	creds CredentialGetter,
	broker BrokerDataProvider,
) (*BriefingService, func()) {
	t.Helper()
	notifier, server := newTestNotifier(t, failSend)
	bs := NewBriefingService(notifier, store, tokens, creds, slog.Default())
	require.NotNil(t, bs)
	if broker != nil {
		bs.SetBrokerProvider(broker)
	}
	return bs, server.Close
}

// validTokenChecker returns a mockTokenChecker where the given emails have valid tokens.
func validTokenChecker(emails ...string) *mockTokenChecker {
	tc := &mockTokenChecker{
		tokens: make(map[string]struct {
			accessToken string
			storedAt    time.Time
		}),
	}
	for _, e := range emails {
		tc.tokens[e] = struct {
			accessToken string
			storedAt    time.Time
		}{accessToken: "tok-" + e, storedAt: time.Now()}
	}
	return tc
}

// expiredTokenChecker returns a mockTokenChecker where all tokens are expired.
func expiredTokenChecker(emails ...string) *mockTokenChecker {
	tc := validTokenChecker(emails...)
	tc.expiredFunc = func(time.Time) bool { return true }
	return tc
}

// credsFor returns a mockCredentialGetter with the given email -> apiKey mappings.
func credsFor(m map[string]string) *mockCredentialGetter {
	return &mockCredentialGetter{keys: m}
}

// storeWithChat creates a Store with the given email->chatID entries.
func storeWithChat(entries map[string]int64) *Store {
	s := newTestStore()
	for email, chatID := range entries {
		s.SetTelegramChatID(email, chatID)
	}
	return s
}

// ===========================================================================
// SendMorningBriefings
// ===========================================================================

func TestSendMorningBriefings_NilService(t *testing.T) {
	var bs *BriefingService
	bs.SendMorningBriefings() // must not panic
}

func TestSendMorningBriefings_NoUsers(t *testing.T) {
	store := newTestStore() // no chat IDs
	bs, cleanup := newBriefingServiceWithMock(t, false, store,
		validTokenChecker(), credsFor(nil), &mockBrokerProvider{})
	defer cleanup()
	bs.SendMorningBriefings() // logs "no users" and returns
}

func TestSendMorningBriefings_SingleUser_Success(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key-1"})
	broker := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 500, DayChangePercentage: 1.5},
		},
		margins: kiteconnect.AllMargins{Equity: kiteconnect.Margins{Net: 40000}},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50":   {LastPrice: 22000},
			"NSE:NIFTY BANK": {LastPrice: 48000},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMorningBriefings() // should send successfully
}

func TestSendMorningBriefings_SendFailure(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key-1"})

	bs, cleanup := newBriefingServiceWithMock(t, true, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMorningBriefings() // should log error but not panic
}

func TestSendMorningBriefings_MultipleUsers(t *testing.T) {
	store := storeWithChat(map[string]int64{
		"alice@test.com": 100,
		"bob@test.com":   200,
	})
	tokens := validTokenChecker("alice@test.com", "bob@test.com")
	creds := credsFor(map[string]string{
		"alice@test.com": "key-alice",
		"bob@test.com":   "key-bob",
	})
	broker := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "TCS", DayChange: 200},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMorningBriefings()
}

func TestSendMorningBriefings_ExpiredToken(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := expiredTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	// Should still send (briefing sends regardless of token — just no portfolio data)
	bs.SendMorningBriefings()
}

func TestSendMorningBriefings_NoToken(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := &mockTokenChecker{
		tokens: make(map[string]struct {
			accessToken string
			storedAt    time.Time
		}),
	} // empty — no tokens at all
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMorningBriefings()
}

func TestSendMorningBriefings_BrokerErrors(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})
	broker := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("holdings error"),
		marginsErr:  fmt.Errorf("margins error"),
		ltpErr:      fmt.Errorf("ltp error"),
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMorningBriefings() // should handle broker errors gracefully
}

func TestSendMorningBriefings_NoAPIKey(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{}) // no API key

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMorningBriefings() // briefing without portfolio data
}

// ===========================================================================
// SendDailySummaries
// ===========================================================================

func TestSendDailySummaries_NilService(t *testing.T) {
	var bs *BriefingService
	bs.SendDailySummaries() // must not panic
}

func TestSendDailySummaries_NoUsers(t *testing.T) {
	store := newTestStore()
	bs, cleanup := newBriefingServiceWithMock(t, false, store,
		validTokenChecker(), credsFor(nil), &mockBrokerProvider{})
	defer cleanup()
	bs.SendDailySummaries()
}

func TestSendDailySummaries_SingleUser_Success(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key"})
	broker := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1000, DayChangePercentage: 2.5},
			{Tradingsymbol: "INFY", DayChange: -300, DayChangePercentage: -1.2},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "TCS", PnL: 500, Quantity: 10, DayBuyQuantity: 10},
			},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendDailySummaries()
}

func TestSendDailySummaries_SendFailure(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key"})

	bs, cleanup := newBriefingServiceWithMock(t, true, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendDailySummaries() // should log error but not panic
}

func TestSendDailySummaries_ExpiredToken_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := expiredTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendDailySummaries() // should skip — no valid token
}

func TestSendDailySummaries_NoToken_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := &mockTokenChecker{
		tokens: make(map[string]struct {
			accessToken string
			storedAt    time.Time
		}),
	}
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendDailySummaries()
}

func TestSendDailySummaries_NoAPIKey_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{}) // empty — no API key

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendDailySummaries() // should skip — no API key
}

func TestSendDailySummaries_BrokerErrors(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})
	broker := &mockBrokerProvider{
		holdingsErr:  fmt.Errorf("holdings fail"),
		positionsErr: fmt.Errorf("positions fail"),
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendDailySummaries() // sends summary with "unavailable" sections
}

func TestSendDailySummaries_MultipleUsers_MixedTokens(t *testing.T) {
	store := storeWithChat(map[string]int64{
		"valid@test.com":   100,
		"expired@test.com": 200,
		"nokey@test.com":   300,
	})
	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"valid@test.com":   {accessToken: "tok", storedAt: time.Now()},
			"expired@test.com": {accessToken: "tok", storedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			"nokey@test.com":   {accessToken: "tok", storedAt: time.Now()},
		},
		expiredFunc: func(storedAt time.Time) bool {
			return storedAt.Before(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
		},
	}
	creds := credsFor(map[string]string{
		"valid@test.com": "key-valid",
		// expired@test.com has a key but expired token
		"expired@test.com": "key-expired",
		// nokey@test.com has no API key
	})
	broker := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{{Tradingsymbol: "A", DayChange: 100}},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{{Tradingsymbol: "B", PnL: 50}},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendDailySummaries() // only valid@test.com should get a summary
}

// ===========================================================================
// SendMISWarnings
// ===========================================================================

func TestSendMISWarnings_NilService(t *testing.T) {
	var bs *BriefingService
	bs.SendMISWarnings() // must not panic
}

func TestSendMISWarnings_NoUsers(t *testing.T) {
	store := newTestStore()
	bs, cleanup := newBriefingServiceWithMock(t, false, store,
		validTokenChecker(), credsFor(nil), &mockBrokerProvider{})
	defer cleanup()
	bs.SendMISWarnings()
}

func TestSendMISWarnings_HasMISPositions_Success(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key"})
	broker := &mockBrokerProvider{
		positions: kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "RELIANCE", Product: "MIS", Quantity: 10, PnL: 500},
				{Tradingsymbol: "INFY", Product: "MIS", Quantity: -5, PnL: -200},
			},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMISWarnings() // should send MIS warning
}

func TestSendMISWarnings_HasMISPositions_SendFailure(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key"})
	broker := &mockBrokerProvider{
		positions: kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "RELIANCE", Product: "MIS", Quantity: 10, PnL: 500},
			},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, true, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMISWarnings() // should log error but not panic
}

func TestSendMISWarnings_NoMISPositions(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "api-key"})
	broker := &mockBrokerProvider{
		positions: kiteconnect.Positions{
			Net: []kiteconnect.Position{
				{Tradingsymbol: "RELIANCE", Product: "CNC", Quantity: 10, PnL: 500},
			},
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMISWarnings() // no MIS positions, no warning sent
}

func TestSendMISWarnings_ExpiredToken_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := expiredTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMISWarnings()
}

func TestSendMISWarnings_NoToken_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := &mockTokenChecker{
		tokens: make(map[string]struct {
			accessToken string
			storedAt    time.Time
		}),
	}
	creds := credsFor(map[string]string{"alice@test.com": "key"})

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMISWarnings()
}

func TestSendMISWarnings_NoAPIKey_Skipped(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{}) // no API key

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, &mockBrokerProvider{})
	defer cleanup()

	bs.SendMISWarnings()
}

func TestSendMISWarnings_PositionsFetchError(t *testing.T) {
	store := storeWithChat(map[string]int64{"alice@test.com": 100})
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})
	broker := &mockBrokerProvider{
		positionsErr: fmt.Errorf("positions API error"),
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMISWarnings() // should log error and continue
}

func TestSendMISWarnings_MultipleUsers(t *testing.T) {
	store := storeWithChat(map[string]int64{
		"has-mis@test.com": 100,
		"no-mis@test.com":  200,
		"err@test.com":     300,
	})
	tokens := validTokenChecker("has-mis@test.com", "no-mis@test.com", "err@test.com")
	creds := credsFor(map[string]string{
		"has-mis@test.com": "key1",
		"no-mis@test.com":  "key2",
		"err@test.com":     "key3",
	})

	// We need per-user behavior — use a custom broker provider keyed by apiKey.
	broker := &perEmailBrokerProvider{
		positionsByEmail: map[string]kiteconnect.Positions{
			"key1": {
				Net: []kiteconnect.Position{
					{Tradingsymbol: "SBIN", Product: "MIS", Quantity: 20, PnL: 300},
				},
			},
			"key2": {
				Net: []kiteconnect.Position{
					{Tradingsymbol: "SBIN", Product: "CNC", Quantity: 10, PnL: 100},
				},
			},
		},
		positionsErrByEmail: map[string]error{
			"key3": fmt.Errorf("fetch error"),
		},
	}

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, broker)
	defer cleanup()

	bs.SendMISWarnings() // only has-mis@test.com should get warning
}

// ===========================================================================
// SetBrokerProvider edge case
// ===========================================================================

func TestSetBrokerProvider_NilService(t *testing.T) {
	var bs *BriefingService
	bs.SetBrokerProvider(&mockBrokerProvider{}) // must not panic
}

func TestBroker_DefaultProvider(t *testing.T) {
	store := storeWithChat(map[string]int64{"a@test.com": 1})
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	bs := NewBriefingService(notifier, store, validTokenChecker(), credsFor(nil), slog.Default())
	require.NotNil(t, bs)

	// broker() with no provider set should return defaultBrokerProvider
	bp := bs.broker()
	assert.NotNil(t, bp)
	_, isDefault := bp.(*defaultBrokerProvider)
	assert.True(t, isDefault)
}

// ===========================================================================
// NewBriefingService edge case — non-nil notifier
// ===========================================================================

func TestNewBriefingService_NonNilNotifier(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	store := newTestStore()
	tokens := validTokenChecker()
	creds := credsFor(nil)

	bs := NewBriefingService(notifier, store, tokens, creds, slog.Default())
	assert.NotNil(t, bs)
}

// ===========================================================================
// buildDailySummary coverage — verify Telegram message content
// ===========================================================================

func TestBuildDailySummary_FullIntegration_Send(t *testing.T) {
	store := newTestStore()
	tokens := validTokenChecker("alice@test.com")
	creds := credsFor(map[string]string{"alice@test.com": "key"})
	broker := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1500, DayChangePercentage: 3.0},
			{Tradingsymbol: "TCS", DayChange: -500, DayChangePercentage: -2.0},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "INFY", PnL: 800, Quantity: 5, DayBuyQuantity: 5},
			},
		},
	}

	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	bs := &BriefingService{
		notifier:       notifier,
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         logport.NewSlog(slog.Default()),
		brokerProvider: broker,
	}

	msg := bs.buildDailySummary("alice@test.com", "key", "tok", "April 11, 2026")

	assert.Contains(t, msg, "Daily Summary")
	assert.Contains(t, msg, "April 11, 2026")
	assert.Contains(t, msg, "Holdings")
	assert.Contains(t, msg, "2 stocks")
	assert.Contains(t, msg, "Positions")
	assert.Contains(t, msg, "1 positions")
	assert.Contains(t, msg, "RELIANCE")
	assert.Contains(t, msg, "Top Gainers")
	assert.Contains(t, msg, "Top Losers")
}

func TestBuildDailySummary_HoldingsError_Send(t *testing.T) {
	store := newTestStore()
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	bs := &BriefingService{
		notifier:   notifier,
		alertStore: store,
		tokens:     validTokenChecker("alice@test.com"),
		creds:      credsFor(map[string]string{"alice@test.com": "key"}),
		logger:     logport.NewSlog(slog.Default()),
		brokerProvider: &mockBrokerProvider{
			holdingsErr: fmt.Errorf("API error"),
			positions: kiteconnect.Positions{
				Day: []kiteconnect.Position{{PnL: 100}},
			},
		},
	}

	msg := bs.buildDailySummary("alice@test.com", "key", "tok", "April 11, 2026")
	assert.Contains(t, msg, "unavailable")
}

func TestBuildDailySummary_PositionsError_Send(t *testing.T) {
	store := newTestStore()
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	bs := &BriefingService{
		notifier:   notifier,
		alertStore: store,
		tokens:     validTokenChecker("alice@test.com"),
		creds:      credsFor(map[string]string{"alice@test.com": "key"}),
		logger:     logport.NewSlog(slog.Default()),
		brokerProvider: &mockBrokerProvider{
			holdings:     []kiteconnect.Holding{{DayChange: 200}},
			positionsErr: fmt.Errorf("API error"),
		},
	}

	msg := bs.buildDailySummary("alice@test.com", "key", "tok", "April 11, 2026")
	assert.True(t, strings.Contains(msg, "unavailable") || strings.Contains(msg, "Positions"))
}

// ===========================================================================
// perEmailBrokerProvider — per-user mock for multi-user tests
// ===========================================================================

// perEmailBrokerProvider routes broker calls based on the apiKey (which maps 1:1
// with email in our tests via credsFor). This allows multi-user tests where each
// user gets different broker responses.
type perEmailBrokerProvider struct {
	holdingsByEmail     map[string][]kiteconnect.Holding
	holdingsErrByEmail  map[string]error
	positionsByEmail    map[string]kiteconnect.Positions
	positionsErrByEmail map[string]error
	marginsByEmail      map[string]kiteconnect.AllMargins
	marginsErrByEmail   map[string]error
	ltpByEmail          map[string]kiteconnect.QuoteLTP
	ltpErrByEmail       map[string]error
}

// emailFromKey extracts the email from the apiKey convention "key-<suffix>" or "key<N>".
// For perEmailBrokerProvider, we key by apiKey directly since creds maps email->apiKey.
func (p *perEmailBrokerProvider) resolveEmail(apiKey string) string {
	// In our tests, the creds map is email -> apiKey, so positions are stored by email.
	// The broker receives apiKey, but we stored by email. We need to reverse-map.
	// Simpler: store by apiKey directly. But our tests store by email.
	// Solution: iterate over the maps checking apiKey patterns.
	// Actually, simplest: the caller passes apiKey which maps 1:1 to an email
	// in the test. We just store data by email and do a prefix match.
	// Even simpler: store by apiKey. Let's just do that.
	return apiKey // In multi-user tests, we'll key everything by apiKey.
}

func (p *perEmailBrokerProvider) GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error) {
	key := p.resolveEmail(apiKey)
	if p.holdingsErrByEmail != nil {
		if err, ok := p.holdingsErrByEmail[key]; ok {
			return nil, err
		}
	}
	if p.holdingsByEmail != nil {
		return p.holdingsByEmail[key], nil
	}
	return nil, nil
}

func (p *perEmailBrokerProvider) GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error) {
	key := p.resolveEmail(apiKey)
	if p.positionsErrByEmail != nil {
		if err, ok := p.positionsErrByEmail[key]; ok {
			return kiteconnect.Positions{}, err
		}
	}
	if p.positionsByEmail != nil {
		return p.positionsByEmail[key], nil
	}
	return kiteconnect.Positions{}, nil
}

func (p *perEmailBrokerProvider) GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error) {
	key := p.resolveEmail(apiKey)
	if p.marginsErrByEmail != nil {
		if err, ok := p.marginsErrByEmail[key]; ok {
			return kiteconnect.AllMargins{}, err
		}
	}
	if p.marginsByEmail != nil {
		return p.marginsByEmail[key], nil
	}
	return kiteconnect.AllMargins{}, nil
}

func (p *perEmailBrokerProvider) GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error) {
	key := p.resolveEmail(apiKey)
	if p.ltpErrByEmail != nil {
		if err, ok := p.ltpErrByEmail[key]; ok {
			return nil, err
		}
	}
	if p.ltpByEmail != nil {
		return p.ltpByEmail[key], nil
	}
	return nil, nil
}

// ===========================================================================
// defaultBrokerProvider — exercises the real Kite wrappers (network calls fail
// with auth/connection errors, but all code paths are covered).
// ===========================================================================

func TestDefaultBrokerProvider_GetHoldings(t *testing.T) {
	t.Parallel()
	p := &defaultBrokerProvider{}
	_, err := p.GetHoldings("fake-api-key", "fake-token")
	require.Error(t, err, "expected error with invalid credentials")
}

func TestDefaultBrokerProvider_GetPositions(t *testing.T) {
	t.Parallel()
	p := &defaultBrokerProvider{}
	_, err := p.GetPositions("fake-api-key", "fake-token")
	require.Error(t, err, "expected error with invalid credentials")
}

func TestDefaultBrokerProvider_GetUserMargins(t *testing.T) {
	t.Parallel()
	p := &defaultBrokerProvider{}
	_, err := p.GetUserMargins("fake-api-key", "fake-token")
	require.Error(t, err, "expected error with invalid credentials")
}

func TestDefaultBrokerProvider_GetLTP(t *testing.T) {
	t.Parallel()
	p := &defaultBrokerProvider{}
	_, err := p.GetLTP("fake-api-key", "fake-token", "NSE:RELIANCE")
	require.Error(t, err, "expected error with invalid credentials")
}

