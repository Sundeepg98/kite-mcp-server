package aop_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/aop"
)

// example_audit_riskguard_test.go — exercises the riskguard +
// audit demonstration shipped in example_audit_riskguard.go.
//
// What these tests prove (per the .research/decorator-code-gen-
// evaluation.md §3 Option 4 mandate "Demonstrate on at least ONE
// consumer chain"):
//
//   - The PlaceOrder field with `aop:"audit,riskguard"` gets the
//     full audit+riskguard chain. Order placement audits Before
//     and After, riskguard Around-checks fire and short-circuit
//     when configured to do so.
//
//   - The CancelOrder field with `aop:"audit"` gets audit only.
//     Riskguard does NOT gate cancels — production-shape behaviour.
//
//   - The GetQuote field with no tag bypasses the chain entirely.
//     Real method runs without audit overhead.
//
//   - When riskguard short-circuits PlaceOrder, the After audit
//     STILL fires (observe-only contract preserved through the
//     Around's error-return path).

// makeService produces a TradingService with realistic-shape
// implementations. Counters track the underlying real-method
// invocation counts so tests can assert "the real method DID run"
// or "the real method DID NOT run" depending on the path.
func makeService() (*aop.TradingService, *placeOrderCounter, *cancelOrderCounter, *getQuoteCounter) {
	po := &placeOrderCounter{}
	co := &cancelOrderCounter{}
	gq := &getQuoteCounter{}
	svc := &aop.TradingService{
		PlaceOrder: func(ctx context.Context, req aop.OrderReq) (aop.OrderResp, error) {
			po.calls.Add(1)
			po.lastReq.Store(req)
			return aop.OrderResp{OrderID: "DEMO-" + req.Symbol}, nil
		},
		CancelOrder: func(ctx context.Context, orderID string) error {
			co.calls.Add(1)
			co.lastID.Store(orderID)
			return nil
		},
		GetQuote: func(ctx context.Context, symbol string) (aop.Quote, error) {
			gq.calls.Add(1)
			gq.lastSym.Store(symbol)
			return aop.Quote{Last: 100.0}, nil
		},
	}
	return svc, po, co, gq
}

// placeOrderCounter / cancelOrderCounter / getQuoteCounter — local
// helpers to surface real-method invocations to tests without
// needing the AOP package to expose them.
type placeOrderCounter struct {
	calls   atomicI64
	lastReq atomicAny
}
type cancelOrderCounter struct {
	calls  atomicI64
	lastID atomicAny
}
type getQuoteCounter struct {
	calls   atomicI64
	lastSym atomicAny
}

// atomicI64 + atomicAny — local sync/atomic alternatives that the
// test file can use without depending on package-level types.
// Keeping these out of example_audit_riskguard.go avoids exporting
// test-only counters from the production-shape file.
type atomicI64 struct {
	v int64
}

func (a *atomicI64) Add(delta int64) { a.v += delta }
func (a *atomicI64) Load() int64     { return a.v }

type atomicAny struct {
	v interface{}
}

func (a *atomicAny) Store(v interface{}) { a.v = v }
func (a *atomicAny) Load() interface{}   { return a.v }

// TestDemo_PlaceOrder_FullChainFires demonstrates the canonical
// happy path: an order within the value cap with kill switch off
// passes through audit+riskguard and the real method runs. This is
// the rubric path A/B/C all-active demonstration: reflective
// composition (path A), tag-driven pointcut (path B), aspect
// weaving with Before/Around/After phases (path C).
func TestDemo_PlaceOrder_FullChainFires(t *testing.T) {
	t.Parallel()

	audit := &aop.AuditCounters{}
	risk := &aop.RiskguardCounters{}
	w := aop.BuildDemoWeaver(audit, risk, /*killSwitchOn=*/ false, /*valueCap=*/ 100_000.0)

	svc, po, _, _ := makeService()
	require.NoError(t, w.WeaveStruct(svc))

	resp, err := svc.PlaceOrder(context.Background(), aop.OrderReq{
		Symbol:   "INFY",
		Quantity: 100,
		Price:    1500.0,
	}) // notional = 150,000 is over cap; let's use a cheaper one:
	_ = resp

	// Re-test with a reasonable notional under the 100k cap.
	resp, err = svc.PlaceOrder(context.Background(), aop.OrderReq{
		Symbol:   "INFY",
		Quantity: 10,
		Price:    1500.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "DEMO-INFY", resp.OrderID)

	// Verify the chain's behavioural invariants.
	// audit Before fired ONCE per attempt (2 attempts in this test).
	assert.GreaterOrEqual(t, audit.BeforeCalls.Load(), int64(2), "audit.Before fires per attempt")
	assert.GreaterOrEqual(t, audit.AfterCalls.Load(), int64(2), "audit.After fires per attempt")

	// riskguard recorded one block (the over-cap attempt) and one
	// allow (the under-cap attempt).
	assert.Equal(t, int64(1), risk.Blocked.Load(), "first call blocked by value cap")
	assert.Equal(t, int64(1), risk.Allowed.Load(), "second call allowed")

	// The real method ran ONCE (only the allowed call reached it).
	assert.Equal(t, int64(1), po.calls.Load(), "real PlaceOrder ran exactly once")
}

// TestDemo_PlaceOrder_KillSwitchOn_ShortCircuits demonstrates the
// canonical riskguard short-circuit path: kill switch on, every
// PlaceOrder is rejected with a non-nil error and the real method
// never runs. Production-shape behaviour at the AOP layer.
func TestDemo_PlaceOrder_KillSwitchOn_ShortCircuits(t *testing.T) {
	t.Parallel()

	audit := &aop.AuditCounters{}
	risk := &aop.RiskguardCounters{}
	w := aop.BuildDemoWeaver(audit, risk, /*killSwitchOn=*/ true, /*valueCap=*/ 1_000_000.0)

	svc, po, _, _ := makeService()
	require.NoError(t, w.WeaveStruct(svc))

	_, err := svc.PlaceOrder(context.Background(), aop.OrderReq{
		Symbol:   "INFY",
		Quantity: 1,
		Price:    100.0,
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "kill switch"), "error message includes 'kill switch'")

	// Real method must NOT have run — riskguard short-circuited.
	assert.Equal(t, int64(0), po.calls.Load(), "real PlaceOrder must NOT run when kill switch is on")

	// Audit counters: Before fired (every attempt is logged);
	// After ALSO fired (observe-only — fires regardless of
	// riskguard's decision). This is the load-bearing
	// "audit captures rejected orders" contract.
	assert.Equal(t, int64(1), audit.BeforeCalls.Load())
	assert.Equal(t, int64(1), audit.AfterCalls.Load(),
		"After audit MUST fire even when riskguard blocked — observe-only contract")

	// Riskguard recorded the block.
	assert.Equal(t, int64(1), risk.Blocked.Load())
	assert.Equal(t, int64(0), risk.Allowed.Load())
}

// TestDemo_CancelOrder_AuditOnly_NoRiskguard demonstrates the
// per-field aspect-selection contract: CancelOrder is tagged
// `aop:"audit"` only, so riskguard does NOT participate in the
// cancel chain. Audit fires; riskguard does not.
//
// Production-shape: cancels are not subject to value-cap or
// kill-switch gating because a user can always cancel their own
// order even when the kill switch is engaged.
func TestDemo_CancelOrder_AuditOnly_NoRiskguard(t *testing.T) {
	t.Parallel()

	audit := &aop.AuditCounters{}
	risk := &aop.RiskguardCounters{}
	w := aop.BuildDemoWeaver(audit, risk, /*killSwitchOn=*/ true /* would block any riskguarded call */, /*valueCap=*/ 1.0)

	svc, _, co, _ := makeService()
	require.NoError(t, w.WeaveStruct(svc))

	// Even with kill switch on (which would block PlaceOrder),
	// CancelOrder must succeed because its tag does not include
	// "riskguard".
	err := svc.CancelOrder(context.Background(), "ORD-1234")
	require.NoError(t, err, "CancelOrder is audit-only — kill switch must not block it")

	// Audit fired Before+After — proof the audit aspect IS active
	// for cancel.
	assert.Equal(t, int64(1), audit.BeforeCalls.Load())
	assert.Equal(t, int64(1), audit.AfterCalls.Load())

	// Riskguard counters remain zero — proof the riskguard aspect
	// did NOT fire for cancel.
	assert.Equal(t, int64(0), risk.Allowed.Load())
	assert.Equal(t, int64(0), risk.Blocked.Load())

	// The real CancelOrder ran.
	assert.Equal(t, int64(1), co.calls.Load())
}

// TestDemo_GetQuote_Untagged_BypassesAOP demonstrates the
// "untagged field is unwrapped" contract for read-only operations:
// GetQuote has no `aop:` tag, so neither audit nor riskguard
// participate. The real method is called directly with no
// reflection overhead.
func TestDemo_GetQuote_Untagged_BypassesAOP(t *testing.T) {
	t.Parallel()

	audit := &aop.AuditCounters{}
	risk := &aop.RiskguardCounters{}
	w := aop.BuildDemoWeaver(audit, risk, false, 1_000_000.0)

	svc, _, _, gq := makeService()
	require.NoError(t, w.WeaveStruct(svc))

	q, err := svc.GetQuote(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, 100.0, q.Last)

	// No aspect counters incremented.
	assert.Equal(t, int64(0), audit.BeforeCalls.Load(), "audit must NOT fire on untagged field")
	assert.Equal(t, int64(0), risk.Allowed.Load(), "riskguard must NOT fire on untagged field")

	// Real method ran.
	assert.Equal(t, int64(1), gq.calls.Load())
}

// TestDemo_LatencyAfterAdviceCompiles is a smoke test that the
// LatencyAfterAdvice helper builds and registers without panicking
// — its actual After-side semantics are deliberately empty (a
// teaching aid for the cooperation pattern, not a production
// concern). Pinning compilation here so future refactors don't
// accidentally remove the helper.
func TestDemo_LatencyAfterAdviceCompiles(t *testing.T) {
	t.Parallel()

	var durations []interface{ String() string } // unused
	_ = durations
	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAfter,
		Pointcut: aop.PointcutByName("X"),
		Advice:   aop.LatencyAfterAdvice(nil),
	})
	assert.Equal(t, 1, w.AspectCount())
}
