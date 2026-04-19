package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnToolExecution_SubstituteResult exercises the new around-style hook:
// a hook can return a synthetic *mcp.CallToolResult WITHOUT invoking next,
// and the downstream tool handler MUST be skipped.
func TestOnToolExecution_SubstituteResult(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	handlerCalled := false
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("real result"), nil
	}

	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		// Substitute — deliberately do NOT call next.
		return mcp.NewToolResultText("substituted"), nil
	})

	mw := HookMiddleware()
	wrapped := mw(next)

	req := mcp.CallToolRequest{}
	req.Params.Name = "any_tool"
	result, err := wrapped(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	tc, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])
	assert.Equal(t, "substituted", tc.Text)
	assert.False(t, handlerCalled, "downstream handler MUST NOT run when around-hook substitutes")
}

// TestOnToolExecution_CallsNext confirms the canonical pass-through path:
// an around-hook that delegates to next(ctx, req) receives the real
// handler's result and can return it (or a transformation of it).
func TestOnToolExecution_CallsNext(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	handlerCalled := false
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("real result"), nil
	}

	hookSawResult := ""
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		result, err := next(ctx, req)
		if result != nil && len(result.Content) > 0 {
			if tc, ok := result.Content[0].(mcp.TextContent); ok {
				hookSawResult = tc.Text
			}
		}
		return result, err
	})

	mw := HookMiddleware()
	wrapped := mw(next)

	req := mcp.CallToolRequest{}
	req.Params.Name = "any_tool"
	result, err := wrapped(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, handlerCalled, "handler should have been called via next")
	assert.Equal(t, "real result", hookSawResult, "hook should have seen the real result")
}

// TestOnToolExecution_PanicRecovered confirms the safety promise: a panic
// inside an around-hook does NOT propagate. The middleware recovers,
// logs (best-effort), and returns an error-shaped CallToolResult so the
// client gets a well-formed response instead of a disconnect.
func TestOnToolExecution_PanicRecovered(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	handlerCalled := false
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("real"), nil
	}

	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		panic("boom from around hook")
	})

	mw := HookMiddleware()
	wrapped := mw(next)

	req := mcp.CallToolRequest{}
	req.Params.Name = "any_tool"
	result, err := wrapped(context.Background(), req)

	// Panic recovered: err is nil, result surfaces an error to the client.
	assert.NoError(t, err, "panic must not propagate as error")
	require.NotNil(t, result, "middleware must return a well-formed result even on panic")
	assert.True(t, result.IsError, "recovered panic should surface as IsError=true")
	assert.False(t, handlerCalled, "handler should not be called after a panicking around-hook")
}

// TestOnToolExecution_ChainedHooks verifies that multiple around-hooks
// compose correctly: each wraps the next, and the innermost-registered
// hook is closest to the real handler. (Convention: first registered =
// outermost wrapper, matches how HTTP middleware chains read.)
func TestOnToolExecution_ChainedHooks(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	order := []string{}
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		order = append(order, "handler")
		return mcp.NewToolResultText("ok"), nil
	}

	// First registered = outer.
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		order = append(order, "outer-pre")
		r, e := next(ctx, req)
		order = append(order, "outer-post")
		return r, e
	})
	// Second registered = inner.
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		order = append(order, "inner-pre")
		r, e := next(ctx, req)
		order = append(order, "inner-post")
		return r, e
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	req := mcp.CallToolRequest{}
	req.Params.Name = "any_tool"
	_, _ = wrapped(context.Background(), req)

	assert.Equal(t, []string{
		"outer-pre", "inner-pre", "handler", "inner-post", "outer-post",
	}, order, "around-hooks should compose in registration order with handler innermost")
}

// TestOnToolExecution_ShortCircuitSkipsLaterHooks confirms that when an
// earlier around-hook returns a synthetic result without calling next,
// subsequent around-hooks AND the handler are both skipped.
func TestOnToolExecution_ShortCircuitSkipsLaterHooks(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	secondCalled := false
	handlerCalled := false

	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("real"), nil
	}

	// Outer: short-circuit.
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("short-circuited"), nil
	})
	// Inner: should never run.
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error) {
		secondCalled = true
		return next(ctx, req)
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	req := mcp.CallToolRequest{}
	req.Params.Name = "any_tool"
	result, _ := wrapped(context.Background(), req)

	require.NotNil(t, result)
	tc, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "short-circuited", tc.Text)
	assert.False(t, secondCalled, "inner around-hook must NOT run when outer short-circuits")
	assert.False(t, handlerCalled, "handler must NOT run when any around-hook short-circuits")
}

// TestOnBeforeAfterSemanticsPreserved confirms that adding the around
// layer does NOT break the pre-existing OnBeforeToolExecution /
// OnAfterToolExecution contract.
func TestOnBeforeAfterSemanticsPreserved(t *testing.T) {
	t.Run("before hook still blocks via error return", func(t *testing.T) {
		ClearHooks()
		defer ClearHooks()

		errBlocked := errors.New("blocked by before-hook")
		OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
			return errBlocked
		})

		handlerCalled := false
		next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			handlerCalled = true
			return mcp.NewToolResultText("ok"), nil
		}

		mw := HookMiddleware()
		wrapped := mw(next)
		req := mcp.CallToolRequest{}
		req.Params.Name = "blocked_tool"
		result, err := wrapped(context.Background(), req)

		require.NoError(t, err, "before-hook block is surfaced via result, not err")
		require.NotNil(t, result)
		assert.True(t, result.IsError, "block should yield an error-shaped result")
		assert.False(t, handlerCalled, "before-hook block must skip handler")
	})

	t.Run("after hook still observes", func(t *testing.T) {
		ClearHooks()
		defer ClearHooks()

		var sawTool string
		OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
			sawTool = toolName
			return nil
		})

		next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		}

		mw := HookMiddleware()
		wrapped := mw(next)
		req := mcp.CallToolRequest{}
		req.Params.Name = "observed_tool"
		_, err := wrapped(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "observed_tool", sawTool)
	})
}

// TestOnBeforePanicRecovered ensures the safety fix applies to the
// existing before/after hook paths as well — a panicking before-hook
// cannot crash the middleware.
func TestOnBeforePanicRecovered(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		panic("before-hook panic")
	})

	err := RunBeforeHooks(context.Background(), "test_tool", nil)
	// Panic recovered → returned as error.
	assert.Error(t, err, "panic in before-hook should be recovered and returned as error")
}

// TestOnAfterPanicRecovered ensures a panicking after-hook does NOT
// crash RunAfterHooks (after-hooks are fire-and-forget; a panic must
// simply be swallowed).
func TestOnAfterPanicRecovered(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	secondCalled := false
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		panic("after-hook panic")
	})
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		secondCalled = true
		return nil
	})

	// Must not panic; must continue to second hook.
	RunAfterHooks(context.Background(), "test_tool", nil)
	assert.True(t, secondCalled, "second after-hook should still run after first panics")
}

// Compile-time interface assertion — the ToolHandlerNext alias must
// match server.ToolHandlerFunc so callers can pass the chain through
// transparently.
var _ ToolHandlerNext = server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return nil, nil
})
