package decorators_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/decorators"
)

// Sample request/response types used in tests. Kept package-internal so tests
// document the typed-decorator usage without leaking on the export surface.
type fooReq struct {
	Symbol string
}

type fooResp struct {
	Price float64
}

// fooHandler is the "real" handler — returns a deterministic price for the
// happy-path tests; returns an error when Symbol == "EXPLODE".
func fooHandler(_ context.Context, req fooReq) (fooResp, error) {
	if req.Symbol == "EXPLODE" {
		return fooResp{}, errors.New("explode")
	}
	return fooResp{Price: 42.0}, nil
}

// auditDecorator increments a per-test counter every time it sees a request
// pass through. Tests assert the counter to verify execution order.
func auditDecorator(seen *int32) decorators.Decorator[fooReq, fooResp] {
	return func(next decorators.Handler[fooReq, fooResp]) decorators.Handler[fooReq, fooResp] {
		return func(ctx context.Context, req fooReq) (fooResp, error) {
			atomic.AddInt32(seen, 1)
			return next(ctx, req)
		}
	}
}

// blockDecorator short-circuits the chain — never calls next. Returns a
// canned response. Mirrors the riskguard / billing / paper-trading
// "interception" pattern in mcp/middleware_chain.go.
func blockDecorator(blockedSymbol string) decorators.Decorator[fooReq, fooResp] {
	return func(next decorators.Handler[fooReq, fooResp]) decorators.Handler[fooReq, fooResp] {
		return func(ctx context.Context, req fooReq) (fooResp, error) {
			if req.Symbol == blockedSymbol {
				return fooResp{Price: -1}, nil // synthetic "blocked" response
			}
			return next(ctx, req)
		}
	}
}

// transformDecorator mutates the request's Symbol before passing it on.
// Tests this is genuinely possible at compile time (the existing
// ToolMutableAroundHook in mcp/registry.go is for the MCP request shape;
// this proves the same pattern at arbitrary type).
func transformDecorator(suffix string) decorators.Decorator[fooReq, fooResp] {
	return func(next decorators.Handler[fooReq, fooResp]) decorators.Handler[fooReq, fooResp] {
		return func(ctx context.Context, req fooReq) (fooResp, error) {
			req.Symbol = req.Symbol + suffix
			return next(ctx, req)
		}
	}
}

// TestCompose_NoDecorators verifies the identity case — Compose with zero
// decorators returns the original handler unchanged.
func TestCompose_NoDecorators(t *testing.T) {
	t.Parallel()

	composed := decorators.Compose[fooReq, fooResp]()(fooHandler)

	resp, err := composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
}

// TestCompose_SingleDecorator verifies the single-decorator wrap path.
// The decorator must observe the request before the handler runs, and the
// response must flow back through unchanged.
func TestCompose_SingleDecorator(t *testing.T) {
	t.Parallel()

	var seen int32
	composed := decorators.Compose(auditDecorator(&seen))(fooHandler)

	resp, err := composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
	assert.Equal(t, int32(1), atomic.LoadInt32(&seen))
}

// TestCompose_OrderingFirstRegisteredOutermost verifies the documented
// composition contract — the FIRST decorator passed to Compose ends up as
// the OUTERMOST wrapper, matching the gRPC / Echo / mcp.HookMiddleware
// convention. Callers expect "audit then riskguard then handler", so the
// order order they list decorators in Compose() must match invocation
// order outside-in.
func TestCompose_OrderingFirstRegisteredOutermost(t *testing.T) {
	t.Parallel()

	// Use a slice + index so we can verify EXACT execution order rather
	// than just count.
	var trace []string
	mark := func(label string) decorators.Decorator[fooReq, fooResp] {
		return func(next decorators.Handler[fooReq, fooResp]) decorators.Handler[fooReq, fooResp] {
			return func(ctx context.Context, req fooReq) (fooResp, error) {
				trace = append(trace, label+"-before")
				resp, err := next(ctx, req)
				trace = append(trace, label+"-after")
				return resp, err
			}
		}
	}

	composed := decorators.Compose(mark("A"), mark("B"), mark("C"))(fooHandler)

	_, err := composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)

	// Outermost first wraps innermost last: A wraps B wraps C wraps handler.
	// Execution order: A-before, B-before, C-before, handler, C-after, B-after, A-after.
	assert.Equal(t,
		[]string{"A-before", "B-before", "C-before", "C-after", "B-after", "A-after"},
		trace,
	)
}

// TestCompose_ShortCircuit verifies a decorator can choose to NOT call next
// and return a synthetic response. The handler itself must never run, and
// inner decorators after the short-circuit must also not run.
func TestCompose_ShortCircuit(t *testing.T) {
	t.Parallel()

	var innerSeen int32

	composed := decorators.Compose(
		blockDecorator("BLOCKED"),
		auditDecorator(&innerSeen),
	)(fooHandler)

	// Blocked path: blockDecorator returns synthetic response, audit never fires.
	resp, err := composed(context.Background(), fooReq{Symbol: "BLOCKED"})
	require.NoError(t, err)
	assert.Equal(t, -1.0, resp.Price)
	assert.Equal(t, int32(0), atomic.LoadInt32(&innerSeen))

	// Pass-through path: blockDecorator calls next, audit fires, handler runs.
	resp, err = composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
	assert.Equal(t, int32(1), atomic.LoadInt32(&innerSeen))
}

// TestCompose_ErrorPropagation verifies handler errors flow back through the
// chain unmodified — decorators see them in their inner-side branches and
// can either surface or swallow.
func TestCompose_ErrorPropagation(t *testing.T) {
	t.Parallel()

	var innerSeen int32
	composed := decorators.Compose(auditDecorator(&innerSeen))(fooHandler)

	_, err := composed(context.Background(), fooReq{Symbol: "EXPLODE"})
	require.Error(t, err)
	assert.Equal(t, "explode", err.Error())
	assert.Equal(t, int32(1), atomic.LoadInt32(&innerSeen))
}

// TestCompose_RequestMutation verifies a decorator can mutate the request
// before passing to next — the gRPC / mcp.ToolMutableAroundHook pattern at
// arbitrary types.
func TestCompose_RequestMutation(t *testing.T) {
	t.Parallel()

	// transformDecorator appends "-MUTATED"; handler returns Price=42 for
	// any non-EXPLODE symbol, so we verify the chain runs end-to-end with
	// the mutated request.
	composed := decorators.Compose(transformDecorator("-MUTATED"))(fooHandler)

	// Inject a recorder via a follow-up decorator that captures the symbol
	// the handler ultimately sees.
	var observed string
	recorder := func(next decorators.Handler[fooReq, fooResp]) decorators.Handler[fooReq, fooResp] {
		return func(ctx context.Context, req fooReq) (fooResp, error) {
			observed = req.Symbol
			return next(ctx, req)
		}
	}
	composed = decorators.Compose(transformDecorator("-MUTATED"), recorder)(fooHandler)

	_, err := composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, "INFY-MUTATED", observed)
}

// TestCompose_NilSafety verifies that a nil Decorator in the chain panics
// at composition time rather than at request time. This is the
// fail-fast contract — wrong wiring should crash at startup, not on the
// first user request.
func TestCompose_NilSafety(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on nil decorator, got none")
		}
	}()

	_ = decorators.Compose[fooReq, fooResp](nil)(fooHandler)
}

// TestApply_AlternateFormSugar verifies the Apply convenience wrapper —
// some callers prefer "Apply(handler, decorators...)" reading order over
// "Compose(decorators...)(handler)". Same semantics, different sugar.
func TestApply_AlternateFormSugar(t *testing.T) {
	t.Parallel()

	var seen int32
	composed := decorators.Apply(fooHandler, auditDecorator(&seen))

	resp, err := composed(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
	assert.Equal(t, int32(1), atomic.LoadInt32(&seen))
}

// TestHandler_TypeIsCallable verifies that a Handler[Req, Resp] value can
// be invoked directly without going through Compose — Handler is a regular
// function type, NOT a wrapper struct. This is the Go-idiomatic guarantee.
func TestHandler_TypeIsCallable(t *testing.T) {
	t.Parallel()

	var h decorators.Handler[fooReq, fooResp] = fooHandler

	resp, err := h(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
}

// TestDecorator_TypeIsCallable verifies that a Decorator[Req, Resp] value
// can be invoked directly to produce a wrapped handler — Decorator is a
// regular function type, NOT a wrapper struct.
func TestDecorator_TypeIsCallable(t *testing.T) {
	t.Parallel()

	var seen int32
	d := auditDecorator(&seen)

	wrapped := d(fooHandler)
	resp, err := wrapped(context.Background(), fooReq{Symbol: "INFY"})
	require.NoError(t, err)
	assert.Equal(t, 42.0, resp.Price)
	assert.Equal(t, int32(1), atomic.LoadInt32(&seen))
}
