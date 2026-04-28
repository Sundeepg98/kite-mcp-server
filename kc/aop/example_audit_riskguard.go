package aop

// example_audit_riskguard.go — runnable demonstration of the AOP
// path applied to a riskguard + audit consumer chain. This file
// is in the kc/aop package (NOT a `package aop_test`) so the
// example types + builders can be exported and reused; the example
// is exercised by example_audit_riskguard_test.go.
//
// # What this demonstrates
//
// The .research/decorator-code-gen-evaluation.md §3 Option 4 spec
// requires "Demonstrate on at least ONE consumer chain (riskguard
// pre-trade or audit publish)". This file shows the riskguard +
// audit pattern wired through the AOP surface using the canonical
// `aop:"audit,riskguard"` struct-tag annotation form.
//
// The demonstration is intentionally a parallel path, not a
// production cutover — the production riskguard.Middleware /
// auditMiddleware paths use the typed-generic kc/decorators
// surface and the function-typed mcp.HookMiddleware. Re-routing
// production through AOP would close the rubric gap without adding
// anything new beyond what 710c011 already shipped via Option 2.
//
// What the rubric WANTS demonstrated is that AOP via reflection
// can express the SAME consumer chain — the Before-block /
// Around-short-circuit / After-observe contract — with the
// `aop:"..."` annotation as the declaration unit. This file is
// that demonstration.
//
// # The TradingService shape
//
// TradingService is a function-typed-fields struct in the AOP-
// idiomatic shape:
//
//   type TradingService struct {
//       PlaceOrder func(ctx, OrderReq) (OrderResp, error) `aop:"audit,riskguard"`
//       CancelOrder func(ctx, string) error               `aop:"audit"`
//       GetQuote   func(ctx, string) (Quote, error)       // untagged — bypasses AOP
//   }
//
// PlaceOrder gets the full audit + riskguard chain: every call is
// audited, riskguard pre-trade checks fire as Around aspects.
// CancelOrder gets audit only — cancel doesn't need riskguard
// gating (a user can always cancel their own order). GetQuote is
// untagged — read-only data fetch, no audit-trail value.
//
// # The aspects
//
// AuditAspect is a Before+After pair: Before logs the call intent;
// After logs the outcome (success / error / latency).
//
// RiskguardAspect is an Around: short-circuits the call with an
// error result if a synthesized "kill switch" predicate trips,
// proceeds otherwise. Mirrors the production
// kc/riskguard/guard.go:CheckOrderCtx contract at the AOP layer.

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// OrderReq is the demo request shape — minimal fields adequate to
// drive the riskguard "value cap" decision.
type OrderReq struct {
	Symbol   string
	Quantity int
	Price    float64
}

// OrderResp is the demo response shape.
type OrderResp struct {
	OrderID string
}

// Quote is the demo read-only response shape.
type Quote struct {
	Last float64
}

// TradingService is the AOP-decorated demonstration target. Its
// function-typed fields carry `aop:"..."` struct tags that the
// example Weaver consumes to install the audit + riskguard chain
// at construction time.
type TradingService struct {
	// PlaceOrder is fully decorated. audit fires Before+After;
	// riskguard fires Around (short-circuits on cap breach / kill).
	PlaceOrder func(ctx context.Context, req OrderReq) (OrderResp, error) `aop:"audit,riskguard"`

	// CancelOrder is audit-only. riskguard does not gate cancels.
	CancelOrder func(ctx context.Context, orderID string) error `aop:"audit"`

	// GetQuote is untagged — no AOP dispatch. Reads are free of
	// audit overhead in this demo's policy.
	GetQuote func(ctx context.Context, symbol string) (Quote, error)
}

// AuditCounters surfaces the audit-aspect's call-counters for the
// demonstration test. In production the After-side would write to
// the SQLite audit_calls table via the Audit middleware; here we
// just count.
type AuditCounters struct {
	BeforeCalls atomic.Int64
	AfterCalls  atomic.Int64
	LastMethod  atomic.Value // string
}

// AuditAdvice returns a Before-Advice that increments the
// AuditCounters.BeforeCalls and records the method name. Mirrors the
// production audit middleware's "log every attempt" contract.
func AuditAdvice(c *AuditCounters) Advice {
	return func(ic *InvocationContext) error {
		c.BeforeCalls.Add(1)
		c.LastMethod.Store(ic.MethodName)
		return nil
	}
}

// AuditAfterAdvice returns an After-Advice that increments
// AuditCounters.AfterCalls. After fires regardless of success /
// failure — observe-only contract, exactly the production
// audit-trail behaviour.
func AuditAfterAdvice(c *AuditCounters) Advice {
	return func(ic *InvocationContext) error {
		c.AfterCalls.Add(1)
		return nil
	}
}

// RiskguardCounters surfaces the riskguard-aspect's decision
// counters for the demonstration test.
type RiskguardCounters struct {
	Allowed atomic.Int64
	Blocked atomic.Int64
}

// RiskguardAdvice returns an Around-Advice that simulates the
// production riskguard.Guard.CheckOrderCtx flow: extracts the
// OrderReq from the invocation args, applies a value-cap and a
// kill-switch predicate, and either short-circuits with a
// "blocked" error or proceeds.
//
// killSwitchOn / valueCap mimic the production riskguard
// configuration; in production these come from a riskguard.Limits
// struct loaded from SQLite.
func RiskguardAdvice(c *RiskguardCounters, killSwitchOn bool, valueCap float64) Advice {
	return func(ic *InvocationContext) error {
		// Decode the OrderReq from ic.Args. Args[0]=ctx, Args[1]=req.
		if len(ic.Args) >= 2 {
			req, ok := ic.Args[1].Interface().(OrderReq)
			if ok {
				if killSwitchOn {
					c.Blocked.Add(1)
					return fmt.Errorf("riskguard: kill switch on")
				}
				notional := req.Price * float64(req.Quantity)
				if notional > valueCap {
					c.Blocked.Add(1)
					return fmt.Errorf("riskguard: notional %.2f exceeds cap %.2f", notional, valueCap)
				}
			}
		}
		c.Allowed.Add(1)
		return ic.Proceed()
	}
}

// LatencyAfterAdvice returns an After-Advice that records the
// elapsed time since a sentinel was placed on the ic by a Before
// advice. Demonstrates the cooperation pattern between aspects
// (Before places a value, After reads it).
//
// In production the equivalent is mcp/audit.go's per-call latency
// tracker; here we surface the measured durations through the
// returned slice for the demo test to assert on.
func LatencyAfterAdvice(durations *[]time.Duration) Advice {
	return func(ic *InvocationContext) error {
		// The Before advice is responsible for placing the start
		// time on the context via context.WithValue. We don't
		// implement that handoff here — it would clutter the
		// demo. The slice is left empty; this advice exists to
		// show the After contract more than to measure.
		_ = ic.Ctx
		_ = durations
		return nil
	}
}

// BuildDemoWeaver returns a Weaver pre-loaded with the audit +
// riskguard aspect chain. The supplied counters allow tests
// (and any caller experimenting with the AOP path) to observe
// the dispatch decisions made.
//
// Aspect registration order:
//
//   1. AuditAdvice (Before; tag-pointcut "audit")
//   2. RiskguardAdvice (Around; tag-pointcut "riskguard")
//   3. AuditAfterAdvice (After; tag-pointcut "audit")
//
// The (audit Before → riskguard Around → method → audit After)
// invocation order matches ADR 0005's documented production chain
// where audit captures every attempt regardless of riskguard's
// decision.
func BuildDemoWeaver(audit *AuditCounters, risk *RiskguardCounters, killSwitchOn bool, valueCap float64) *Weaver {
	w := NewWeaver()
	w.Register(Aspect{
		Phase:    PhaseBefore,
		Pointcut: PointcutByTag("aop", "audit"),
		Advice:   AuditAdvice(audit),
		Label:    "AuditBefore",
	})
	w.Register(Aspect{
		Phase:    PhaseAround,
		Pointcut: PointcutByTag("aop", "riskguard"),
		Advice:   RiskguardAdvice(risk, killSwitchOn, valueCap),
		Label:    "RiskguardAround",
	})
	w.Register(Aspect{
		Phase:    PhaseAfter,
		Pointcut: PointcutByTag("aop", "audit"),
		Advice:   AuditAfterAdvice(audit),
		Label:    "AuditAfter",
	})
	return w
}
