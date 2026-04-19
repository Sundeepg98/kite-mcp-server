package mcp

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterMiddleware_WrapsInOrder confirms that plugin-registered
// middleware compose around a handler in Order() ascending — low order
// wraps outermost, high order sits closest to the handler.
func TestRegisterMiddleware_WrapsInOrder(t *testing.T) {
	ClearPluginMiddleware()
	defer ClearPluginMiddleware()

	var seen []string
	mk := func(label string) server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				seen = append(seen, label+"-pre")
				r, e := next(ctx, req)
				seen = append(seen, label+"-post")
				return r, e
			}
		}
	}

	require.NoError(t, RegisterMiddleware("outer", mk("outer"), 100))
	require.NoError(t, RegisterMiddleware("inner", mk("inner"), 500))

	base := server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		seen = append(seen, "handler")
		return mcp.NewToolResultText("ok"), nil
	})
	wrapped := PluginMiddlewareChain()(base)
	_, _ = wrapped(context.Background(), mcp.CallToolRequest{})

	assert.Equal(t, []string{
		"outer-pre", "inner-pre", "handler", "inner-post", "outer-post",
	}, seen)
}

// TestRegisterMiddleware_RejectsNil — nil mw and empty name both fail
// at registration so the problem surfaces at wire-up not on first call.
func TestRegisterMiddleware_RejectsNil(t *testing.T) {
	ClearPluginMiddleware()
	defer ClearPluginMiddleware()
	assert.Error(t, RegisterMiddleware("", nil, 0))
	assert.Error(t, RegisterMiddleware("has_name_nil_mw", nil, 0))
	assert.Error(t, RegisterMiddleware("", func(n server.ToolHandlerFunc) server.ToolHandlerFunc { return n }, 0))
}

// TestRegisterMiddleware_DuplicateNameReplaces — last-wins semantics
// matching the pattern used by RegisterWidget and plugin_commands.
func TestRegisterMiddleware_DuplicateNameReplaces(t *testing.T) {
	ClearPluginMiddleware()
	defer ClearPluginMiddleware()

	var firstCalled, secondCalled bool
	require.NoError(t, RegisterMiddleware("dup",
		func(n server.ToolHandlerFunc) server.ToolHandlerFunc {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				firstCalled = true
				return n(ctx, req)
			}
		}, 100))
	require.NoError(t, RegisterMiddleware("dup",
		func(n server.ToolHandlerFunc) server.ToolHandlerFunc {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				secondCalled = true
				return n(ctx, req)
			}
		}, 100))

	base := server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	})
	_, _ = PluginMiddlewareChain()(base)(context.Background(), mcp.CallToolRequest{})
	assert.False(t, firstCalled, "first handler should have been replaced")
	assert.True(t, secondCalled, "second handler must run")
	assert.Equal(t, 1, PluginMiddlewareCount())
}

// TestListPluginMiddleware confirms the listing API returns registered
// entries in Order ascending — the order they will execute.
func TestListPluginMiddleware(t *testing.T) {
	ClearPluginMiddleware()
	defer ClearPluginMiddleware()

	noop := func(n server.ToolHandlerFunc) server.ToolHandlerFunc { return n }
	require.NoError(t, RegisterMiddleware("b", noop, 500))
	require.NoError(t, RegisterMiddleware("a", noop, 100))
	require.NoError(t, RegisterMiddleware("c", noop, 900))

	entries := ListPluginMiddleware()
	require.Len(t, entries, 3)
	assert.Equal(t, "a", entries[0].Name)
	assert.Equal(t, "b", entries[1].Name)
	assert.Equal(t, "c", entries[2].Name)
	assert.Equal(t, 100, entries[0].Order)
}

// TestRegisterMiddleware_EmptyChainPassthrough — when no plugin
// middleware is registered, PluginMiddlewareChain() is a
// transparent passthrough around next.
func TestRegisterMiddleware_EmptyChainPassthrough(t *testing.T) {
	ClearPluginMiddleware()
	defer ClearPluginMiddleware()

	called := false
	base := server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("ok"), nil
	})
	wrapped := PluginMiddlewareChain()(base)
	_, _ = wrapped(context.Background(), mcp.CallToolRequest{})
	assert.True(t, called, "empty chain must call handler unchanged")
}

// TestRegisterMiddleware_PanicRecoveredPerLayer — a plugin middleware
// that panics surfaces as an IsError=true CallToolResult and is marked
// Failed in PluginHealth. Sibling middleware and the handler above it
// are unaffected.
func TestRegisterMiddleware_PanicRecoveredPerLayer(t *testing.T) {
	ClearPluginMiddleware()
	ClearPluginHealth()
	defer ClearPluginMiddleware()
	defer ClearPluginHealth()

	require.NoError(t, RegisterMiddleware("panicker",
		func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				panic("mw boom")
			}
		}, 100))

	handlerCalled := false
	base := server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("ok"), nil
	})
	result, err := PluginMiddlewareChain()(base)(context.Background(), mcp.CallToolRequest{})

	require.NoError(t, err, "panic must not propagate as err")
	require.NotNil(t, result)
	assert.True(t, result.IsError, "panic surfaces as IsError result")
	assert.False(t, handlerCalled, "handler under a panicking mw must not be called")

	// PluginHealth records the failure.
	health := PluginHealth()
	require.Contains(t, health, "panicker")
	assert.Equal(t, HealthStateFailed, health["panicker"].State)
}
