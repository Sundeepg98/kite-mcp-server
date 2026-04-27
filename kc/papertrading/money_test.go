package papertrading

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// TestAccountCashFields_AreMoney is the type-level assertion for Slice 5
// of the Money VO sweep: paper Account.CashBalance and Account.InitialCash
// MUST be domain.Money values (not bare float64) so the engine fails fast
// on cross-currency comparisons rather than silently coercing. JSON wire
// stays float via Money.Float64() at the marshal boundary.
//
// If this test fails after a refactor reverted the field types to float64,
// reapply the Slice 5 conversion (kc/papertrading/store.go Account struct).
func TestAccountCashFields_AreMoney(t *testing.T) {
	t.Parallel()

	moneyType := reflect.TypeOf(domain.Money{})

	a := Account{}
	cashType := reflect.TypeOf(a.CashBalance)
	if cashType != moneyType {
		t.Fatalf("Account.CashBalance must be domain.Money, got %s", cashType)
	}
	initialType := reflect.TypeOf(a.InitialCash)
	if initialType != moneyType {
		t.Fatalf("Account.InitialCash must be domain.Money, got %s", initialType)
	}
}

// TestAccountZeroMoneySemantic verifies the zero-Money sentinel pattern
// holds for paper accounts: a freshly constructed Account has IsZero()
// cash on both fields, matching the "empty account, no funding yet" meaning.
// When EnableAccount runs, IsPositive() flips true.
func TestAccountZeroMoneySemantic(t *testing.T) {
	t.Parallel()

	// Bare struct: zero value is the "empty account" semantic.
	a := Account{}
	if !a.CashBalance.IsZero() {
		t.Errorf("zero Account should have zero CashBalance, got %v", a.CashBalance)
	}
	if !a.InitialCash.IsZero() {
		t.Errorf("zero Account should have zero InitialCash, got %v", a.InitialCash)
	}

	// After construction with NewINR — IsPositive flips true.
	a.InitialCash = domain.NewINR(1_000_000)
	a.CashBalance = domain.NewINR(1_000_000)
	if !a.InitialCash.IsPositive() {
		t.Errorf("funded account should have positive InitialCash")
	}
	if !a.CashBalance.IsPositive() {
		t.Errorf("funded account should have positive CashBalance")
	}
}

// TestCashBalanceCrossCurrencyRejection verifies that an attempt to
// compare or subtract from a cash balance using a non-INR Money value
// returns an error rather than silently coercing — the canonical Slice 1
// "no silent coercion" invariant.
func TestCashBalanceCrossCurrencyRejection(t *testing.T) {
	t.Parallel()

	cash := domain.NewINR(1_000_000)
	usdCost := domain.Money{Amount: 12000, Currency: "USD"} // hypothetical USD cost

	// GreaterThan must return an error for currency mismatch.
	if _, err := usdCost.GreaterThan(cash); err == nil {
		t.Errorf("expected cross-currency GreaterThan to return error, got nil")
	}

	// Sub must return an error for currency mismatch.
	if _, err := cash.Sub(usdCost); err == nil {
		t.Errorf("expected cross-currency Sub to return error, got nil")
	}

	// Same-currency Sub succeeds.
	cost := domain.NewINR(25_000)
	got, err := cash.Sub(cost)
	require.NoError(t, err)
	assert.Equal(t, "INR", got.Currency)
	assert.InDelta(t, 975_000.0, got.Float64(), 0.01)
}

// TestPaperPnLSignPreservation verifies that paper-trading P&L can be
// negative without crashing the Money pipeline. Position P&L is intrinsic
// to virtual portfolios — losing trades are normal and the Money type
// must round-trip negative amounts cleanly through arithmetic and the
// Float64 boundary.
//
// Position.PnL stays float64 (out of Slice 5 scope per Slice 3 territory),
// but cash subtraction at fill time can produce negative deltas that flow
// through Money.Sub. Verify the math.
func TestPaperPnLSignPreservation(t *testing.T) {
	t.Parallel()

	// Cash starts at 1M, BUY 100 @ 800 = 80k, SELL 100 @ 750 = 75k. Net loss 5k.
	cash := domain.NewINR(1_000_000)

	buyCost := domain.NewINR(80_000)
	afterBuy, err := cash.Sub(buyCost)
	require.NoError(t, err)
	assert.InDelta(t, 920_000.0, afterBuy.Float64(), 0.01)

	sellProceeds := domain.NewINR(75_000)
	afterSell, err := afterBuy.Add(sellProceeds)
	require.NoError(t, err)
	assert.InDelta(t, 995_000.0, afterSell.Float64(), 0.01)

	// Net delta on the round-trip (loss).
	netDelta, err := afterSell.Sub(cash)
	require.NoError(t, err)
	assert.True(t, netDelta.IsNegative(), "net loss should be negative")
	assert.InDelta(t, -5_000.0, netDelta.Float64(), 0.01)
}

// TestStoreEnableAccount_RoundtripsAsMoney verifies the SQLite REAL
// storage / domain.Money reconstruction pattern: Enable persists a
// float64, and GetAccount rehydrates via domain.NewINR(scanned) so the
// returned Account presents Money values to engine code.
func TestStoreEnableAccount_RoundtripsAsMoney(t *testing.T) {
	t.Parallel()

	// Reuse the testEngine helper which sets up an in-memory store +
	// initialised tables.
	engine := testEngine(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	require.NotNil(t, acct)

	// Both Money fields rehydrated as INR.
	assert.Equal(t, "INR", acct.InitialCash.Currency)
	assert.Equal(t, "INR", acct.CashBalance.Currency)
	assert.InDelta(t, 1_000_000.0, acct.InitialCash.Float64(), 0.01)
	assert.InDelta(t, 1_000_000.0, acct.CashBalance.Float64(), 0.01)
}

// TestStatusJSONBoundaryStaysFloat verifies the Status() map keeps
// float64 values for initial_cash / cash_balance — the dashboard SSR
// and JSON marshal path read these as float64 (kc/ops/dashboard_paper.go
// line 108: status["initial_cash"].(float64)). Breaking this seam
// silently breaks the dashboard.
func TestStatusJSONBoundaryStaysFloat(t *testing.T) {
	t.Parallel()

	engine := testEngine(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	statusMap, err := engine.Status(testEmail)
	require.NoError(t, err)

	// Both fields must marshal as float64 for JSON compatibility.
	initialCash, ok := statusMap["initial_cash"].(float64)
	if !ok {
		t.Fatalf("status[initial_cash] must be float64 at the JSON boundary, got %T", statusMap["initial_cash"])
	}
	cashBalance, ok := statusMap["cash_balance"].(float64)
	if !ok {
		t.Fatalf("status[cash_balance] must be float64 at the JSON boundary, got %T", statusMap["cash_balance"])
	}
	assert.InDelta(t, 1_000_000.0, initialCash, 0.01)
	assert.InDelta(t, 1_000_000.0, cashBalance, 0.01)
}

// TestPositionLastPrice_IsMoney is the type-level assertion for Slice 6a
// (papertrading P&L sweep, commit 1 of 3): Position.LastPrice MUST be
// domain.Money. LastPrice is a leaf "what the LTP refresh wrote" field
// — read-only at the engine layer (set during refresh, consumed by the
// JSON map output). Slice 1 pattern: zero Money is the "no LTP yet"
// sentinel (set on the bare struct before refresh runs).
func TestPositionLastPrice_IsMoney(t *testing.T) {
	t.Parallel()

	moneyType := reflect.TypeOf(domain.Money{})
	p := Position{}
	got := reflect.TypeOf(p.LastPrice)
	if got != moneyType {
		t.Fatalf("Position.LastPrice must be domain.Money, got %s", got)
	}
}

// TestHoldingLastPrice_IsMoney mirrors TestPositionLastPrice_IsMoney for
// the Holding aggregate. Same semantic: leaf field set during LTP refresh.
func TestHoldingLastPrice_IsMoney(t *testing.T) {
	t.Parallel()

	moneyType := reflect.TypeOf(domain.Money{})
	h := Holding{}
	got := reflect.TypeOf(h.LastPrice)
	if got != moneyType {
		t.Fatalf("Holding.LastPrice must be domain.Money, got %s", got)
	}
}

// TestPositionLastPriceZeroSentinel verifies the "no LTP yet" semantic:
// a Position fresh from UpsertPosition (before any LTP refresh) has
// IsZero LastPrice, distinguishable from "LTP=0" (which would be an
// invalid LTP for any tradable instrument anyway, but the sentinel
// makes the intent explicit).
func TestPositionLastPriceZeroSentinel(t *testing.T) {
	t.Parallel()

	p := Position{}
	if !p.LastPrice.IsZero() {
		t.Errorf("zero Position should have zero LastPrice, got %v", p.LastPrice)
	}
	// After LTP refresh — IsPositive flips true.
	p.LastPrice = domain.NewINR(2500)
	if !p.LastPrice.IsPositive() {
		t.Errorf("after LTP refresh, LastPrice should be positive")
	}
}

// TestPositionsJSONLastPriceStaysFloat verifies the Kite-API-shaped
// GetPositions output keeps last_price as float64 at the JSON boundary
// — same Slice 5 pattern (Status / GetMargins). External clients that
// JSON-decode the response read last_price as a number, not as a
// {"amount", "currency"} object.
func TestPositionsJSONLastPriceStaysFloat(t *testing.T) {
	t.Parallel()

	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 2600.0})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a MARKET BUY so a position exists with a known LastPrice
	// after the LTP refresh inside GetPositions.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	raw, err := engine.GetPositions(testEmail)
	require.NoError(t, err)

	resp, ok := raw.(map[string]any)
	require.True(t, ok)
	day, ok := resp["day"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, day, 1)

	lp, ok := day[0]["last_price"].(float64)
	if !ok {
		t.Fatalf("day[0][last_price] must be float64 at JSON boundary, got %T", day[0]["last_price"])
	}
	assert.InDelta(t, 2600.0, lp, 0.01)
}

// TestHoldingsJSONLastPriceStaysFloat mirrors TestPositionsJSONLastPriceStaysFloat
// for the Holdings JSON output (CNC product places a row in paper_holdings).
func TestHoldingsJSONLastPriceStaysFloat(t *testing.T) {
	t.Parallel()

	engine := testEngine(t, map[string]float64{"NSE:INFY": 1700.0})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         5,
	})
	require.NoError(t, err)

	raw, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)

	holdings, ok := raw.([]map[string]any)
	require.True(t, ok)
	require.Len(t, holdings, 1)

	lp, ok := holdings[0]["last_price"].(float64)
	if !ok {
		t.Fatalf("holdings[0][last_price] must be float64 at JSON boundary, got %T", holdings[0]["last_price"])
	}
	assert.InDelta(t, 1700.0, lp, 0.01)
}

// TestGetMargins_BoundaryStaysFloat verifies GetMargins (consumed by the
// Kite-API-shaped paper response) preserves float64 at the JSON wire so
// existing dashboards / chat clients that read margin data as numbers
// continue working.
func TestGetMargins_BoundaryStaysFloat(t *testing.T) {
	t.Parallel()

	engine := testEngine(t, nil)
	require.NoError(t, engine.Enable(testEmail, 500_000))

	raw, err := engine.GetMargins(testEmail)
	require.NoError(t, err)

	margins, ok := raw.(map[string]any)
	require.True(t, ok, "GetMargins must return map[string]any")

	equity, ok := margins["equity"].(map[string]any)
	require.True(t, ok)

	available, ok := equity["available"].(map[string]any)
	require.True(t, ok)

	cash, ok := available["cash"].(float64)
	if !ok {
		t.Fatalf("equity.available.cash must be float64, got %T", available["cash"])
	}
	assert.InDelta(t, 500_000.0, cash, 0.01)
}
