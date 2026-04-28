package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/decorators"
)

// Phase 3a Decorator Option 2 consumer-pattern tests.
//
// These tests exercise the typed decorator surface directly (without
// going through the Registry / hooks machinery) to demonstrate that
// the around-hook chain in HookMiddlewareFor is a genuine instance of
// kc/decorators.Decorator[mcp.CallToolRequest, *mcp.CallToolResult].
//
// Existing around_hook_test.go tests cover the integrated path
// (Registry.OnToolExecution + HookMiddleware end-to-end). These tests
// complement that surface by proving the typed pattern works against
// the same type instantiation an external plugin author would use.

// TestComposeAroundChain_EmptyChainReturnsBase verifies that a
// composeAroundChain call with no entries returns the original
// handler — same fast-path the pre-migration loop took when no hooks
// were registered.
func TestComposeAroundChain_EmptyChainReturnsBase(t *testing.T) {
	t.Parallel()

	called := 0
	base := server.ToolHandlerFunc(func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called++
		return mcp.NewToolResultText("from-base"), nil
	})

	composed := composeAroundChain(nil, base)

	res, err := composed(context.Background(), mcp.CallToolRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, called)
	// Identity contract: the returned function pointer is the SAME
	// as base when len(merged)==0 — no allocation, no wrapping.
	// We compare via behaviour (called==1 after exactly one invoke)
	// rather than function-pointer equality because Go does not
	// guarantee function-value identity comparison semantics across
	// type conversions.
}

// TestDecoratorTypedChain_PreservesShortCircuit demonstrates the
// canonical "decorator can short-circuit" contract using the typed
// decorators.Decorator surface that mcp/registry.go's around-chain
// also depends on. Mirrors TestCompose_ShortCircuit in
// kc/decorators/decorators_test.go but at the mcp.CallToolRequest /
// *mcp.CallToolResult instantiation that production callers use.
func TestDecoratorTypedChain_PreservesShortCircuit(t *testing.T) {
	t.Parallel()

	type req = mcp.CallToolRequest
	type resp = *mcp.CallToolResult

	innerCalled := false

	// Outer decorator: short-circuits if Tool name is "blocked", else
	// forwards. Models the riskguard / billing / paper-trading
	// "intercept and synthesize" pattern that the around-hook chain
	// is a vehicle for.
	gateDecorator := func(next decorators.Handler[req, resp]) decorators.Handler[req, resp] {
		return func(ctx context.Context, r req) (resp, error) {
			if r.Params.Name == "blocked" {
				return mcp.NewToolResultError("gate: blocked"), nil
			}
			return next(ctx, r)
		}
	}

	// Inner decorator: counts invocations to verify the short-circuit
	// path doesn't reach it.
	innerDecorator := func(next decorators.Handler[req, resp]) decorators.Handler[req, resp] {
		return func(ctx context.Context, r req) (resp, error) {
			innerCalled = true
			return next(ctx, r)
		}
	}

	base := decorators.Handler[req, resp](func(_ context.Context, r req) (resp, error) {
		return mcp.NewToolResultText("ok:" + r.Params.Name), nil
	})

	composed := decorators.Compose(gateDecorator, innerDecorator)(base)

	// Blocked path: gate short-circuits, inner+base must not run.
	r1, err := composed(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "blocked"},
	})
	require.NoError(t, err)
	require.NotNil(t, r1)
	assert.True(t, r1.IsError, "blocked tool should produce error result")
	assert.False(t, innerCalled, "inner decorator must not run on short-circuit")

	// Pass-through path: gate forwards, inner+base run.
	r2, err := composed(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "allowed"},
	})
	require.NoError(t, err)
	require.NotNil(t, r2)
	assert.False(t, r2.IsError, "allowed tool should produce success result")
	assert.True(t, innerCalled, "inner decorator must run on pass-through")
}

// TestAroundEntryToDecorator_ImmutableHookRoutesThroughSafeWrapper
// verifies the per-entry adapter wraps the immutable branch via
// safeInvokeAroundHook (panic recovery). Constructs a panicking hook,
// composes via the typed decorator surface, and asserts the panic is
// surfaced as an IsError CallToolResult — the same contract
// safeInvokeAroundHook owns.
func TestAroundEntryToDecorator_ImmutableHookRoutesThroughSafeWrapper(t *testing.T) {
	t.Parallel()

	panickingHook := ToolAroundHook(func(_ context.Context, _ mcp.CallToolRequest, _ ToolHandlerNext) (*mcp.CallToolResult, error) {
		panic("simulated plugin bug")
	})

	entry := mergedAroundEntry{seq: 1, immutable: panickingHook}
	d := aroundEntryToDecorator(entry)

	base := decorators.Handler[mcp.CallToolRequest, *mcp.CallToolResult](
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Errorf("base handler must not be called when outer hook panics")
			return nil, errors.New("unreachable")
		},
	)

	wrapped := d(base)
	res, err := wrapped(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "tool_with_buggy_plugin"},
	})

	// safeInvokeAroundHook surfaces panics as IsError results, not as
	// returned errors. Same contract validated by
	// TestOnToolExecution_PanicRecovered in around_hook_test.go.
	require.NoError(t, err, "panic should be converted to error result, not bubble as Go error")
	require.NotNil(t, res)
	assert.True(t, res.IsError, "panicked hook should produce IsError=true result")
}
