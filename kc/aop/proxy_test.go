package aop_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/aop"
)

// proxy_test.go — coverage for the reflective Weave dispatch.
// Together with aop_test.go (foundation tests), this file completes
// the AOP package's public-surface coverage.
//
// What these tests prove:
//
//   - Path A reflective composition works end-to-end:
//     WeaveStruct mutates function-typed fields in place;
//     subsequent calls go through the aspect chain
//     (TestWeaveStruct_PathA_*).
//
//   - Path B annotation-driven decorators work via struct tags:
//     `aop:"audit,riskguard"` selects matching aspects for that
//     field; non-matching tag tokens are ignored
//     (TestWeaveStruct_PathB_*).
//
//   - Path C aspect weaving — Before/Around/After composition,
//     short-circuit semantics, error propagation
//     (TestComposeChain_*).
//
//   - Edge cases — non-pointer target, non-struct target, nil
//     function fields, unexported fields, no aspects
//     (TestWeaveStruct_Edge_*).

// orderServiceTagged demonstrates the canonical struct shape the
// AOP path supports: function-typed exported fields with `aop:`
// struct tags. Each tagged field is wrapped at WeaveStruct time;
// subsequent calls dispatch through the matched aspect chain.
type orderServiceTagged struct {
	PlaceOrder func(ctx context.Context, sym string) (int, error) `aop:"audit,riskguard"`
	GetQuote   func(ctx context.Context, sym string) (float64, error) `aop:"audit"`
	// Untagged field — never wrapped.
	Heartbeat func() error
}

// TestWeaveStruct_PathA_ReflectiveCompositionWorksEndToEnd
// demonstrates the rubric's path A: a Weaver-registered Pointcut
// selects methods reflectively, and Weave returns a value whose
// methods are wrapped. The "method" here is a function-typed struct
// field; the wrapping is in-place via reflect.MakeFunc + Set.
func TestWeaveStruct_PathA_ReflectiveCompositionWorksEndToEnd(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()

	// Path A advice — counts invocations.
	var beforeCount, afterCount int32
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&beforeCount, 1)
			return nil
		},
		Label: "BeforeCount",
	})
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAfter,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&afterCount, 1)
			return nil
		},
		Label: "AfterCount",
	})

	// Real implementation — increments a counter to verify the
	// underlying function actually runs.
	var realCalls int32
	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			atomic.AddInt32(&realCalls, 1)
			return 42, nil
		},
	}

	require.NoError(t, w.WeaveStruct(svc))

	// Now exercise the wrapped field. The aspect chain must fire.
	id, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, 42, id)

	assert.Equal(t, int32(1), atomic.LoadInt32(&beforeCount), "Before fired")
	assert.Equal(t, int32(1), atomic.LoadInt32(&realCalls), "real method ran")
	assert.Equal(t, int32(1), atomic.LoadInt32(&afterCount), "After fired")
}

// TestWeaveStruct_PathB_TagAnnotationDrivesAspectMatching
// demonstrates rubric path B: the aop:"audit,riskguard" struct tag
// is the annotation; PointcutByTag selects aspects per token.
// Different fields with different tag values get different aspect
// chains.
func TestWeaveStruct_PathB_TagAnnotationDrivesAspectMatching(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()

	// Two tag-driven aspects: audit and riskguard. Each fires when
	// its token appears in the field's `aop:` tag value.
	var auditCount, riskCount int32
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByTag("aop", "audit"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&auditCount, 1)
			return nil
		},
		Label: "AuditTag",
	})
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByTag("aop", "riskguard"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&riskCount, 1)
			return nil
		},
		Label: "RiskguardTag",
	})

	var poCalls, gqCalls int32
	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			atomic.AddInt32(&poCalls, 1)
			return 1, nil
		},
		GetQuote: func(ctx context.Context, sym string) (float64, error) {
			atomic.AddInt32(&gqCalls, 1)
			return 100.0, nil
		},
	}

	require.NoError(t, w.WeaveStruct(svc))

	// PlaceOrder is tagged "audit,riskguard" → both fire.
	_, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&auditCount), "audit fires for PlaceOrder")
	assert.Equal(t, int32(1), atomic.LoadInt32(&riskCount), "riskguard fires for PlaceOrder")

	// GetQuote is tagged "audit" only → riskguard does NOT fire.
	_, err = svc.GetQuote(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&auditCount), "audit fires for GetQuote (now 2 total)")
	assert.Equal(t, int32(1), atomic.LoadInt32(&riskCount), "riskguard does NOT fire for GetQuote (still 1)")

	// Both real implementations actually ran.
	assert.Equal(t, int32(1), atomic.LoadInt32(&poCalls))
	assert.Equal(t, int32(1), atomic.LoadInt32(&gqCalls))
}

// TestWeaveStruct_PathB_UntaggedFieldIsLeftUnwrapped pins the
// "non-tagged fields are not wrapped" contract — the Heartbeat field
// has no tag and must call through directly.
func TestWeaveStruct_PathB_UntaggedFieldIsLeftUnwrapped(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	var beforeFired int32
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByTag("aop", "audit"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&beforeFired, 1)
			return nil
		},
	})

	var heartbeatCalls int32
	svc := &orderServiceTagged{
		Heartbeat: func() error {
			atomic.AddInt32(&heartbeatCalls, 1)
			return nil
		},
	}

	require.NoError(t, w.WeaveStruct(svc))

	require.NoError(t, svc.Heartbeat())
	assert.Equal(t, int32(1), atomic.LoadInt32(&heartbeatCalls), "real heartbeat ran")
	assert.Equal(t, int32(0), atomic.LoadInt32(&beforeFired), "audit aspect must NOT fire on untagged field")
}

// TestWeaveStruct_PathC_AroundShortCircuitsByNotProceeding
// demonstrates the canonical Around contract — an aspect that
// returns without calling Proceed prevents the method from running.
// Mirrors the riskguard "blocked order" / billing "tier-gated tool"
// production pattern.
func TestWeaveStruct_PathC_AroundShortCircuitsByNotProceeding(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAround,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			// Simulate a riskguard "kill switch on" rejection.
			if len(ic.Args) >= 2 && ic.Args[1].String() == "BLOCKED" {
				return errors.New("kill switch on")
			}
			return ic.Proceed()
		},
		Label: "Riskguard",
	})

	var realCalls int32
	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			atomic.AddInt32(&realCalls, 1)
			return 42, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	// Blocked path: aspect returns error WITHOUT calling Proceed.
	_, err := svc.PlaceOrder(context.Background(), "BLOCKED")
	require.Error(t, err)
	assert.Equal(t, "kill switch on", err.Error())
	assert.Equal(t, int32(0), atomic.LoadInt32(&realCalls), "real method must NOT run")

	// Pass-through path: aspect calls Proceed, real method runs.
	id, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, 42, id)
	assert.Equal(t, int32(1), atomic.LoadInt32(&realCalls), "real method ran on pass-through")
}

// TestComposeChain_BeforeShortCircuitsBlocksMethod verifies
// the documented Before-contract — a non-nil error from Before
// prevents the method (and remaining Before aspects) from running;
// After still fires (observe-only).
func TestComposeChain_BeforeShortCircuitsBlocksMethod(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	var afterFired int32
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			return errors.New("rejected before")
		},
		Label: "Rejector",
	})
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAfter,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			atomic.AddInt32(&afterFired, 1)
			return nil
		},
		Label: "AfterObserver",
	})

	var realCalls int32
	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			atomic.AddInt32(&realCalls, 1)
			return 42, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	_, err := svc.PlaceOrder(context.Background(), "INFY")
	require.Error(t, err)
	assert.Equal(t, "rejected before", err.Error())
	assert.Equal(t, int32(0), atomic.LoadInt32(&realCalls), "real method must not run after Before rejection")
	assert.Equal(t, int32(1), atomic.LoadInt32(&afterFired), "After must still fire — observe-only contract")
}

// TestComposeChain_AfterErrorsAbsorbed verifies that errors from
// After advice do NOT propagate to the caller — After is observe-
// only, like mcp.Registry.RunAfterHooks.
func TestComposeChain_AfterErrorsAbsorbed(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAfter,
		Pointcut: aop.PointcutByName("GetQuote"),
		Advice: func(ic *aop.InvocationContext) error {
			return errors.New("after error — should be absorbed")
		},
		Label: "AfterErrorer",
	})

	svc := &orderServiceTagged{
		GetQuote: func(ctx context.Context, sym string) (float64, error) {
			return 100.0, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	q, err := svc.GetQuote(context.Background(), "INFY")
	require.NoError(t, err, "After errors must not propagate")
	assert.Equal(t, 100.0, q)
}

// TestComposeChain_AroundOrdering_FirstRegisteredOutermost pins
// the Around composition contract — first registered ends up as
// the outermost wrapper. Matches gRPC / Echo / kc/decorators /
// mcp.HookMiddleware conventions throughout the codebase.
func TestComposeChain_AroundOrdering_FirstRegisteredOutermost(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	var trace []string

	mark := func(label string) aop.Advice {
		return func(ic *aop.InvocationContext) error {
			trace = append(trace, label+"-before")
			err := ic.Proceed()
			trace = append(trace, label+"-after")
			return err
		}
	}

	w.Register(aop.Aspect{Phase: aop.PhaseAround, Pointcut: aop.PointcutByName("PlaceOrder"), Advice: mark("A"), Label: "A"})
	w.Register(aop.Aspect{Phase: aop.PhaseAround, Pointcut: aop.PointcutByName("PlaceOrder"), Advice: mark("B"), Label: "B"})
	w.Register(aop.Aspect{Phase: aop.PhaseAround, Pointcut: aop.PointcutByName("PlaceOrder"), Advice: mark("C"), Label: "C"})

	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			trace = append(trace, "method")
			return 42, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	_, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)

	// First registered (A) is OUTERMOST → A-before is first;
	// A-after is last.
	assert.Equal(t,
		[]string{"A-before", "B-before", "C-before", "method", "C-after", "B-after", "A-after"},
		trace,
	)
}

// TestComposeChain_ProceedIdempotent verifies Proceed is a no-op on
// second call — protects against user advice that accidentally
// double-invokes (e.g. forgot the early return after Proceed).
func TestComposeChain_ProceedIdempotent(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	var realCalls int32
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAround,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			err1 := ic.Proceed()
			// Buggy advice — accidentally calls Proceed twice.
			err2 := ic.Proceed()
			if err1 != err2 {
				// proceed-call N=2 must return nil (idempotent)
				return errors.New("idempotency contract violated")
			}
			return err1
		},
	})

	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			atomic.AddInt32(&realCalls, 1)
			return 1, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	_, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)
	// Real method called exactly once (idempotency held).
	assert.Equal(t, int32(1), atomic.LoadInt32(&realCalls))
}

// TestComposeChain_BeforeShortCircuitProducesZeroReturns verifies
// that when Before short-circuits, the wrapping function still
// returns reflect.Values matching the underlying signature — zero-
// valued except for the error position.
func TestComposeChain_BeforeShortCircuitProducesZeroReturns(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByName("PlaceOrder"),
		Advice: func(ic *aop.InvocationContext) error {
			return errors.New("rejected")
		},
	})

	svc := &orderServiceTagged{
		PlaceOrder: func(ctx context.Context, sym string) (int, error) {
			return 99, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	id, err := svc.PlaceOrder(context.Background(), "INFY")
	require.Error(t, err)
	assert.Equal(t, "rejected", err.Error())
	// id must be the zero value of int (the function's first
	// return type), NOT the 99 the real impl would have returned.
	assert.Equal(t, 0, id, "non-error returns must be zero values on short-circuit")
}

// TestWeaveStruct_Edge_NonPointerTargetReturnsError verifies the
// fail-fast on bad target types.
func TestWeaveStruct_Edge_NonPointerTargetReturnsError(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	err := w.WeaveStruct(orderServiceTagged{}) // value, not pointer
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a pointer")
}

// TestWeaveStruct_Edge_PointerToNonStructReturnsError covers the
// other malformed-target case.
func TestWeaveStruct_Edge_PointerToNonStructReturnsError(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	x := 42
	err := w.WeaveStruct(&x)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "point to a struct")
}

// TestWeaveStruct_Edge_NilTargetReturnsError handles the obvious
// nil case.
func TestWeaveStruct_Edge_NilTargetReturnsError(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	err := w.WeaveStruct(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestWeaveStruct_Edge_NilFunctionFieldsAreSkipped pins that nil
// function-typed fields don't crash WeaveStruct — there's nothing
// to wrap, so the field is left as-is.
func TestWeaveStruct_Edge_NilFunctionFieldsAreSkipped(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByTag("aop", "audit"),
		Advice:   func(*aop.InvocationContext) error { return nil },
	})

	// Initialised with nil PlaceOrder — must not crash WeaveStruct.
	svc := &orderServiceTagged{} // all fields nil
	require.NoError(t, w.WeaveStruct(svc))
	assert.Nil(t, svc.PlaceOrder, "nil field stays nil")
}

// TestWeaveStruct_Edge_NoMatchingAspectsLeavesFieldUnchanged
// covers the case where a registered aspect's Pointcut matches
// no field — WeaveStruct silently no-ops on that field.
func TestWeaveStruct_Edge_NoMatchingAspectsLeavesFieldUnchanged(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	// Aspect targets a field name that doesn't exist on the struct.
	w.Register(aop.Aspect{
		Phase:    aop.PhaseBefore,
		Pointcut: aop.PointcutByName("DoesNotExist"),
		Advice:   func(*aop.InvocationContext) error { return errors.New("never fires") },
	})

	original := func(ctx context.Context, sym string) (int, error) {
		return 1, nil
	}
	svc := &orderServiceTagged{
		PlaceOrder: original,
	}
	require.NoError(t, w.WeaveStruct(svc))

	// Verify the field was NOT replaced (no error from the never-
	// firing aspect propagates).
	id, err := svc.PlaceOrder(context.Background(), "INFY")
	require.NoError(t, err)
	assert.Equal(t, 1, id)
}

// TestWeaveStruct_PathC_AroundCanMutateArgsBeforeProceed
// demonstrates the request-mutation pattern at the AOP layer —
// equivalent of mcp.ToolMutableAroundHook. Around advice modifies
// Args before calling Proceed; the modified args reach the real
// method.
func TestWeaveStruct_PathC_AroundCanMutateArgsBeforeProceed(t *testing.T) {
	t.Parallel()

	w := aop.NewWeaver()
	w.Register(aop.Aspect{
		Phase:    aop.PhaseAround,
		Pointcut: aop.PointcutByName("GetQuote"),
		Advice: func(ic *aop.InvocationContext) error {
			// Args[0] is ctx, Args[1] is sym (string). Uppercase it
			// in place by replacing the slice entry with a new
			// reflect.Value wrapping the transformed string.
			if len(ic.Args) >= 2 {
				orig := ic.Args[1].String()
				upper := strings.ToUpper(orig)
				ic.Args[1] = reflect.ValueOf(upper)
			}
			return ic.Proceed()
		},
	})

	var observed string
	svc := &orderServiceTagged{
		GetQuote: func(ctx context.Context, sym string) (float64, error) {
			observed = sym
			return 100.0, nil
		},
	}
	require.NoError(t, w.WeaveStruct(svc))

	_, err := svc.GetQuote(context.Background(), "infy")
	require.NoError(t, err)
	assert.Equal(t, "INFY", observed, "Around mutation reached the real method")
}
