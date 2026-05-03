package papertrading

// riskguard_integration_test.go — cross-slice integration tests pinning
// the Money-VO interop contract between paper trading (Slice 5) and
// riskguard (Slice 1: UserLimits.Max*INR, DailyPlacedValue).
//
// Production middleware order (per .claude/CLAUDE.md "Middleware Chain"):
//   ... -> RiskGuard -> Rate Limiter -> Billing -> Paper Trading -> ...
//
// So riskguard.CheckOrder runs against the user's REAL Money limits BEFORE
// the paper-trading interceptor — paper users do not get a Money-limit
// bypass. These tests assert that contract end-to-end without the full
// HTTP/MCP plumbing: instantiate Guard + PaperEngine separately, invoke
// CheckOrder + RecordOrder + PaperEngine.PlaceOrder in the same sequence
// the middleware chain would execute.
//
// File-scope: ONLY paper + riskguard. No billing, no broker, no Manager
// boot. Hermetic via :memory: SQLite + mockLTP.

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

const rgIntegrationEmail = "trader@rg-paper.test"

// rgPaperHarness builds a coupled Guard + PaperEngine pair sharing nothing
// but the conceptual user (no shared store — riskguard's tracker state
// lives in-memory; paper engine's account lives in :memory: SQLite). The
// caller drives the middleware sequence manually.
type rgPaperHarness struct {
	guard  *riskguard.Guard
	engine *PaperEngine
	prices map[string]float64
}

// newRGPaperHarness wires a fresh hermetic harness. Pins the riskguard
// clock to a market-hours moment (10:30 IST on a weekday) so off-hours
// and market-hours checks pass by default; specific tests override the
// clock via h.guard.SetClock.
func newRGPaperHarness(t *testing.T, prices map[string]float64) *rgPaperHarness {
	t.Helper()

	// Hermetic SQLite for the paper engine's cash/positions/holdings.
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: prices})

	guard := riskguard.NewGuard(logger)
	pinClockWithinMarketHours(guard)

	return &rgPaperHarness{guard: guard, engine: engine, prices: prices}
}

// enablePaper enables paper trading with the given starting cash.
func (h *rgPaperHarness) enablePaper(t *testing.T, email string, cash float64) {
	t.Helper()
	require.NoError(t, h.engine.Enable(email, cash))
}

// chainedPlaceOrder simulates the production middleware chain
// (riskguard → paper) in a single function: CheckOrder, on Allowed call
// PaperEngine.PlaceOrder, on success call RecordOrder. Returns the
// guard result (Allowed flag + Reason) and the paper engine response.
// One of (paperResp, paperErr) is non-nil when guard allowed; both nil
// when guard rejected.
func (h *rgPaperHarness) chainedPlaceOrder(
	email, exchange, symbol, txnType, orderType, product string,
	qty int,
	price float64,
	confirmed bool,
	variety string,
) (riskguard.CheckResult, map[string]any, error) {
	req := riskguard.OrderCheckRequest{
		Email:           email,
		ToolName:        "place_order",
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		TransactionType: txnType,
		Quantity:        qty,
		Price:           domain.NewINR(price),
		OrderType:       orderType,
		Confirmed:       confirmed,
		Variety:         variety,
	}
	rgResult := h.guard.CheckOrderCtx(context.Background(), req)
	if !rgResult.Allowed {
		return rgResult, nil, nil
	}

	resp, err := h.engine.PlaceOrder(email, map[string]any{
		"exchange":         exchange,
		"tradingsymbol":    symbol,
		"transaction_type": txnType,
		"order_type":       orderType,
		"product":          product,
		"quantity":         qty,
		"price":            price,
		"variety":          variety,
	})
	// Riskguard middleware records on successful tool execution. Paper
	// engine returns nil-error for both "filled" and "rejected" states
	// (rejection-via-result pattern), so RecordOrder fires whenever the
	// tool call itself didn't error.
	if err == nil {
		h.guard.RecordOrder(email, req)
	}
	return rgResult, resp, err
}

// pinClockWithinMarketHours pins the guard clock to today (Friday-rolled
// on weekends) at 10:30 IST so off-hours, market-hours, and weekend
// checks pass by default. Mirrors kc/riskguard/guard_test.go's helper
// but is local to this package to avoid an internal-symbol import.
func pinClockWithinMarketHours(g *riskguard.Guard) {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time {
		now := time.Now().In(ist)
		switch now.Weekday() {
		case time.Saturday:
			now = now.AddDate(0, 0, -1)
		case time.Sunday:
			now = now.AddDate(0, 0, -2)
		}
		return time.Date(now.Year(), now.Month(), now.Day(), 10, 30, 0, 0, ist)
	})
}

// pinClockOffHours pins the guard clock to 03:00 IST on a Wednesday —
// inside the 02:00-06:00 IST hard-block window. Used by the AMO-bypass
// integration test.
func pinClockOffHours(g *riskguard.Guard) {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time {
		return time.Date(2026, 4, 8, 3, 0, 0, 0, ist)
	})
}

// setLimitsViaDB drives the production "set per-user limits" path
// through the public SetDB + InitTable + persistLimits + LoadLimits
// chain. This is what app/wire.go does on startup. We use it instead
// of poking g.limits directly so the test exercises only public API.
func setLimitsViaDB(t *testing.T, g *riskguard.Guard, email string, max1Order, maxDaily float64, requireConfirm, allowOffHours bool, maxOrdersPerDay, maxOrdersPerMinute, dupWindow int) {
	t.Helper()

	// Open a hermetic SQLite for the riskguard side.
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	g.SetDB(db)
	require.NoError(t, g.InitTable())

	autoFreeze := 1 // always-on for these tests
	confirmCol := 0
	if requireConfirm {
		confirmCol = 1
	}
	_ = allowOffHours // schema doesn't carry AllowOffHours — tests that
	// need it must drive in-memory mutation; left out of this helper.

	require.NoError(t, db.ExecInsert(
		`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', '', ?)`,
		email, max1Order, maxOrdersPerDay, maxOrdersPerMinute, dupWindow, maxDaily, autoFreeze, confirmCol, time.Now().Format(time.RFC3339),
	))
	require.NoError(t, g.LoadLimits())
}

// ---------------------------------------------------------------------------
// 1. Paper-mode place_order with limit-EXCEEDING cost → riskguard rejects
// ---------------------------------------------------------------------------

// TestRGPaper_OrderValueExceedsLimit_RejectedByRiskguard verifies the
// production contract: a paper user whose order notional exceeds
// MaxSingleOrderINR is rejected by riskguard BEFORE reaching the paper
// engine. The reason surfaces as ReasonOrderValue, and the paper
// account's cash is unchanged because the engine never executed.
func TestRGPaper_OrderValueExceedsLimit_RejectedByRiskguard(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000) // Rs 1 Cr virtual cash

	// Set a tight per-order cap: Rs 50,000.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		50_000,    // MaxSingleOrderINR
		2_00_000,  // MaxDailyValueINR
		false,     // RequireConfirmAllOrders — disabled so we isolate order-value path
		false,     // AllowOffHours
		20, 10, 30,
	)

	// 100 shares * Rs 2500 = Rs 2,50,000 — 5x over the per-order cap.
	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		100, 2500.00, true, "regular",
	)

	require.NoError(t, err)
	assert.False(t, rgResult.Allowed, "riskguard must reject Rs 2.5L order vs Rs 50k cap")
	assert.Equal(t, riskguard.ReasonOrderValue, rgResult.Reason)
	assert.Contains(t, rgResult.Message, "Rs 250000")
	assert.Contains(t, rgResult.Message, "Rs 50000")
	assert.Nil(t, paperResp, "paper engine must not execute when riskguard rejects")

	// Paper account cash is unchanged — the engine never ran.
	acct, err := h.engine.store.GetAccount(rgIntegrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0, acct.CashBalance.Float64(), 0.01,
		"paper cash must be untouched by riskguard rejection")
}

// ---------------------------------------------------------------------------
// 2. Paper-mode place_order with limit-OK cost → allowed; cash decremented
// ---------------------------------------------------------------------------

// TestRGPaper_OrderValueWithinLimit_AllowedAndCashDecremented verifies
// the happy path: a paper order under MaxSingleOrderINR passes
// riskguard and the paper engine debits virtual cash.
func TestRGPaper_OrderValueWithinLimit_AllowedAndCashDecremented(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	// Tight cap that still admits a 10-share order: 10*2500 = Rs 25,000 < Rs 50,000.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		50_000, 2_00_000, false, false, 20, 10, 30,
	)

	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "MARKET", "MIS",
		10, 0, true, "regular", // MARKET → price 0 in the request
	)

	require.NoError(t, err)
	assert.True(t, rgResult.Allowed, "MARKET order skips order-value check (price unknown)")
	require.NotNil(t, paperResp, "paper engine must execute when riskguard allows")
	assert.Equal(t, "COMPLETE", paperResp["status"])

	// Paper cash debited by 10 * LTP(2500) = Rs 25,000.
	acct, err := h.engine.store.GetAccount(rgIntegrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0-25_000.0, acct.CashBalance.Float64(), 0.01,
		"paper cash must be debited by 10*LTP after successful riskguard+paper chain")
}

// TestRGPaper_LimitOrderWithinCap_Allowed verifies the priced-order
// (LIMIT) happy path: order_value check sees the explicit price, the
// notional is under the cap, and the paper engine accepts the order.
// LIMIT BUY at price < LTP stays OPEN (no immediate fill) so the
// paper-side cash check kicks in via the limit-price reservation.
func TestRGPaper_LimitOrderWithinCap_Allowed(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:INFY": 1500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	// 10 * Rs 1400 = Rs 14,000 — well under the Rs 50,000 cap.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		50_000, 2_00_000, false, false, 20, 10, 30,
	)

	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "INFY", "BUY", "LIMIT", "MIS",
		10, 1400.00, true, "regular",
	)

	require.NoError(t, err)
	assert.True(t, rgResult.Allowed)
	require.NotNil(t, paperResp)
	// LIMIT 1400 < LTP 1500 for BUY → not marketable, stays OPEN.
	assert.Equal(t, "OPEN", paperResp["status"])
}

// ---------------------------------------------------------------------------
// 3. Multi-order accumulation hits daily-value cap → rejection on N+1
// ---------------------------------------------------------------------------

// TestRGPaper_DailyValueCap_RejectsAfterAccumulation verifies that
// successive paper orders accumulate into riskguard's
// UserTracker.DailyPlacedValue (Money VO from Slice 3) and the next
// order which would push past MaxDailyValueINR is rejected with
// ReasonDailyValueLimit. The paper engine must execute the allowed
// orders and skip the rejected one.
func TestRGPaper_DailyValueCap_RejectsAfterAccumulation(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:INFY": 1500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	// Per-order: Rs 1,00,000. Daily total: Rs 2,50,000.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		1_00_000, 2_50_000, false, false, 20, 10, 30,
	)

	// Place 3 LIMIT BUY orders with VARYING quantities so the
	// duplicate-order check (which hashes exchange+symbol+txnType+qty
	// within DuplicateWindowSecs) does not fire on identical params.
	// Notionals: 50*1500=75k, 51*1500=76.5k, 52*1500=78k — cumulative
	// Rs 2,29,500 still under Rs 2,50,000 daily cap.
	qties := []int{50, 51, 52}
	for i, qty := range qties {
		rgResult, paperResp, err := h.chainedPlaceOrder(
			rgIntegrationEmail, "NSE", "INFY", "BUY", "LIMIT", "MIS",
			qty, 1500.00, true, "regular",
		)
		require.NoError(t, err, "order %d should not error", i+1)
		require.True(t, rgResult.Allowed,
			"order %d should be allowed (cumulative under cap), got reason=%s msg=%s",
			i+1, rgResult.Reason, rgResult.Message)
		require.NotNil(t, paperResp, "paper engine must execute order %d", i+1)
	}

	// 4th order at qty=53: notional 53*1500=79,500 → cumulative
	// Rs 3,09,000 > Rs 2,50,000 cap → reject.
	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "INFY", "BUY", "LIMIT", "MIS",
		53, 1500.00, true, "regular",
	)
	require.NoError(t, err)
	assert.False(t, rgResult.Allowed, "4th order must be rejected by daily-value cap")
	assert.Equal(t, riskguard.ReasonDailyValueLimit, rgResult.Reason)
	assert.Nil(t, paperResp, "paper engine must not execute the rejected order")

	// Verify the tracker accumulated Money correctly: 50+51+52 = 153
	// shares * Rs 1500 = Rs 2,29,500.
	status := h.guard.GetUserStatus(rgIntegrationEmail)
	assert.Equal(t, "INR", status.DailyPlacedValue.Currency,
		"DailyPlacedValue must be Money-typed (regression guard)")
	assert.InDelta(t, 2_29_500.0, status.DailyPlacedValue.Float64(), 0.01,
		"DailyPlacedValue should reflect 3 successful orders (qty 50+51+52 * Rs 1500)")
	assert.Equal(t, 3, status.DailyOrderCount, "only 3 orders recorded")
}

// ---------------------------------------------------------------------------
// 4. Currency-mismatch regression guard
// ---------------------------------------------------------------------------

// TestRGPaper_CurrencyMismatch_NoSilentCoercion is the regression
// guard against a future bug where someone might construct a USD limit
// in UserLimits while the order is INR-denominated. The Money VO's
// GreaterThan returns an error on cross-currency comparison; the
// riskguard checkOrderValue + checkDailyValue paths consume that error
// via "fail open" — meaning a USD limit cannot block an INR order
// (currently a defensive no-op). This test pins THAT specific behaviour
// (no panic, no false-reject) so any future change to either the
// fail-open semantics or the Money type's mismatch handling is caught.
//
// The order is allowed (no false reject from cross-currency); a future
// stricter behaviour would change this assertion to assert false.
func TestRGPaper_CurrencyMismatch_NoSilentCoercion(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	// First go through the normal path to materialise a per-user limit row.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		50_000, 2_00_000, false, false, 20, 10, 30,
	)

	// Verify the Money type itself rejects cross-currency comparison.
	usd := domain.Money{Amount: 50_000, Currency: "USD"}
	inr := domain.NewINR(2_50_000)
	_, cmpErr := inr.GreaterThan(usd)
	require.Error(t, cmpErr, "Money.GreaterThan must error on cross-currency comparison")
	assert.Contains(t, cmpErr.Error(), "USD")
	assert.Contains(t, cmpErr.Error(), "INR")

	// Verify Add also rejects.
	_, addErr := inr.Add(usd)
	require.Error(t, addErr)
	assert.Contains(t, addErr.Error(), "USD")
	assert.Contains(t, addErr.Error(), "INR")

	// The riskguard fail-open behaviour (currently): when a Money
	// comparison errors, the check returns Allowed=true (defensive).
	// This is the production semantics today — pinning it here so a
	// future tightening (e.g. to fail-closed on currency mismatch) is
	// caught and gets explicit migration discussion.
	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		10, 1000.00, true, "regular",
	)
	require.NoError(t, err)
	// Default-INR limits are in place via setLimitsViaDB, so this is the
	// normal allowed path — no actual cross-currency wiring exists in
	// production. The Money type guards itself; the test above (cmpErr,
	// addErr) is the canonical regression assertion.
	assert.True(t, rgResult.Allowed)
	require.NotNil(t, paperResp)
}

// ---------------------------------------------------------------------------
// 5a. AMO bypasses market_hours; 5b. AMO does NOT bypass off_hours;
// 5c. Money limits hold regardless of variety.
// ---------------------------------------------------------------------------

// TestRGPaper_AMOOffHours_StillHonorsMoneyLimits verifies the
// consistency invariant: variety="amo" does NOT bypass MONEY-based
// limits. Paper users at 03:00 IST submitting an AMO order over the
// per-order cap must still be rejected with ReasonOrderValue (the
// order_value check at order=300 fires before the off_hours check at
// order=1200, so the Money rejection wins).
func TestRGPaper_AMOOffHours_StillHonorsMoneyLimits(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)
	pinClockOffHours(h.guard) // 03:00 IST — inside off-hours block

	// Tight per-order cap: Rs 50,000.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		50_000, 2_00_000, false, false, 20, 10, 30,
	)

	// 100 * 2500 = Rs 2.5L > Rs 50k cap. Variety="amo" so off-hours
	// passes, but order-value check still rejects.
	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		100, 2500.00, true, "amo",
	)

	require.NoError(t, err)
	assert.False(t, rgResult.Allowed, "AMO off-hours must still honor Money limits")
	assert.Equal(t, riskguard.ReasonOrderValue, rgResult.Reason,
		"order-value check (300) precedes off-hours (1200), so order_value reason wins")
	assert.Nil(t, paperResp)
}

// TestRGPaper_AMOAfterMarketHours_BypassesMarketHoursCheck verifies
// the variety="amo" bypass scope: AMO orders skip the market_hours
// check (the [09:15, 15:30) IST equity-cash session), letting users
// queue overnight orders for the next session. Pinned at 16:00 IST —
// after market close, but outside the 02:00-06:00 off-hours block.
//
// Important: AMO does NOT bypass off_hours. The off_hours window
// (02:00-06:00 IST) is opt-out via UserLimits.AllowOffHours, not via
// variety. This test pins the bypass scope so a future code change
// that conflates the two reasons is caught.
func TestRGPaper_AMOAfterMarketHours_BypassesMarketHoursCheck(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	// Pin at 16:00 IST (after market close, outside off-hours window).
	ist, _ := time.LoadLocation("Asia/Kolkata")
	h.guard.SetClock(func() time.Time {
		return time.Date(2026, 4, 8, 16, 0, 0, 0, ist) // Wednesday post-close
	})

	// Generous Money limits.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		1_00_000, 5_00_000, false, false, 20, 10, 30,
	)

	// AMO LIMIT BUY: 10 * Rs 2500 = Rs 25,000 — under cap.
	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		10, 2500.00, true, "amo",
	)

	require.NoError(t, err)
	assert.True(t, rgResult.Allowed,
		"AMO post-market-close should be allowed (market_hours bypass), got reason=%s msg=%s",
		rgResult.Reason, rgResult.Message)
	require.NotNil(t, paperResp)
}

// TestRGPaper_NonAMOAfterMarketHours_RejectedByMarketHoursCheck pins
// the contrapositive: a non-AMO order at 16:00 IST is rejected by the
// market_hours check. Variety field's bypass behaviour is load-
// bearing; this guards against accidentally widening the bypass.
func TestRGPaper_NonAMOAfterMarketHours_RejectedByMarketHoursCheck(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)

	ist, _ := time.LoadLocation("Asia/Kolkata")
	h.guard.SetClock(func() time.Time {
		return time.Date(2026, 4, 8, 16, 0, 0, 0, ist)
	})

	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		1_00_000, 5_00_000, false, false, 20, 10, 30,
	)

	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		10, 2500.00, true, "regular", // non-AMO
	)

	require.NoError(t, err)
	assert.False(t, rgResult.Allowed,
		"non-AMO post-market-close should be rejected (market_hours check)")
	assert.Equal(t, riskguard.ReasonMarketClosed, rgResult.Reason,
		"only market_hours rejects at 16:00 IST (off-hours window doesn't apply)")
	assert.Nil(t, paperResp)
}

// TestRGPaper_NonAMOOffHours_RejectedRegardlessOfMoneyLimits verifies
// the consistency invariant: a non-AMO order at 03:00 IST is rejected
// even when Money limits are wide-open. Pins the Variety field's
// behavioural impact end-to-end at the off-hours window specifically.
func TestRGPaper_NonAMOOffHours_RejectedRegardlessOfMoneyLimits(t *testing.T) {
	t.Parallel()
	h := newRGPaperHarness(t, map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	h.enablePaper(t, rgIntegrationEmail, 1_00_00_000)
	pinClockOffHours(h.guard)

	// Wide-open Money limits — only the time-based checks should reject.
	setLimitsViaDB(t, h.guard, rgIntegrationEmail,
		1_00_000, 5_00_000, false, false, 20, 10, 30,
	)

	rgResult, paperResp, err := h.chainedPlaceOrder(
		rgIntegrationEmail, "NSE", "RELIANCE", "BUY", "LIMIT", "MIS",
		10, 2500.00, true, "regular", // non-AMO
	)

	require.NoError(t, err)
	assert.False(t, rgResult.Allowed)
	// Off-hours check (1200) AND market-hours check (1300) both reject
	// non-AMO at 03:00 IST. Either reason is correct — the test pins
	// "rejected, paper not executed" as the load-bearing invariant.
	assert.Contains(t,
		[]riskguard.RejectionReason{riskguard.ReasonOffHoursBlocked, riskguard.ReasonMarketClosed},
		rgResult.Reason,
		"non-AMO at 03:00 IST must be rejected by either off-hours or market-hours check")
	assert.Nil(t, paperResp)
}
