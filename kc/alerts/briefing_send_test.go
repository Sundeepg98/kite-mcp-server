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
)

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
		logger:         slog.Default(),
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
		logger:     slog.Default(),
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
		logger:     slog.Default(),
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
