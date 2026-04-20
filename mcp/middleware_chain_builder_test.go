package mcp

// middleware_chain_builder_test.go — unit tests for the Config-driven
// middleware chain builder (BuildMiddlewareChain + MiddlewareBuilder).
// Lets operators reorder the tool-handler middleware stack (audit /
// riskguard / elicitation / papertrading, etc.) without recompiling
// by feeding BuildMiddlewareChain a named ordering list.

import (
	"context"
	"fmt"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
)

// recordingMiddlewareForBuilder is a test helper: every middleware it
// builds appends its name to the shared calls slice when invoked, then
// calls through. Running a chain against a terminal handler therefore
// records the outer-to-inner invocation order in calls.
func recordingMiddlewareForBuilder(name string, calls *[]string) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			*calls = append(*calls, name)
			return next(ctx, req)
		}
	}
}

// applyChainForBuilder composes the given middlewares around a terminal
// handler and invokes them once. The caller passes the calls slice
// pointer that recording middleware appended to; this helper just wires
// the handler chain and fires one request.
func applyChainForBuilder(t *testing.T, mws []server.ToolHandlerMiddleware) {
	t.Helper()
	var handler server.ToolHandlerFunc = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	}
	// BuildMiddlewareChain returns middleware in outer-to-inner order.
	// To invoke them as a true chain, wrap right-to-left so the first
	// entry in the list is the outermost caller (first to record itself).
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	_, err := handler(context.Background(), mcp.CallToolRequest{})
	assert.NoError(t, err)
}

func TestBuildMiddlewareChain_DefaultOrder(t *testing.T) {
	t.Parallel()

	calls := []string{}
	entries := map[string]MiddlewareBuilder{
		"audit":        func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("audit", &calls) },
		"riskguard":    func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("riskguard", &calls) },
		"papertrading": func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("papertrading", &calls) },
	}

	chain, err := BuildMiddlewareChain(entries, []string{"audit", "riskguard", "papertrading"})
	assert.NoError(t, err)
	assert.Len(t, chain, 3)

	applyChainForBuilder(t, chain)
	assert.Equal(t, []string{"audit", "riskguard", "papertrading"}, calls,
		"default order should preserve the list order outer-to-inner")
}

func TestBuildMiddlewareChain_ReversedOrder(t *testing.T) {
	t.Parallel()

	calls := []string{}
	entries := map[string]MiddlewareBuilder{
		"audit":     func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("audit", &calls) },
		"riskguard": func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("riskguard", &calls) },
	}

	chain, err := BuildMiddlewareChain(entries, []string{"riskguard", "audit"})
	assert.NoError(t, err)

	applyChainForBuilder(t, chain)
	assert.Equal(t, []string{"riskguard", "audit"}, calls,
		"reversed config order should reverse invocation order")
}

func TestBuildMiddlewareChain_CustomSubset(t *testing.T) {
	t.Parallel()

	calls := []string{}
	entries := map[string]MiddlewareBuilder{
		"audit":        func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("audit", &calls) },
		"riskguard":    func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("riskguard", &calls) },
		"papertrading": func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("papertrading", &calls) },
	}

	chain, err := BuildMiddlewareChain(entries, []string{"papertrading", "audit"})
	assert.NoError(t, err)
	assert.Len(t, chain, 2, "should only include requested names")

	applyChainForBuilder(t, chain)
	assert.Equal(t, []string{"papertrading", "audit"}, calls)
}

func TestBuildMiddlewareChain_UnknownName(t *testing.T) {
	t.Parallel()

	entries := map[string]MiddlewareBuilder{
		"audit": func() server.ToolHandlerMiddleware {
			return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
		},
	}

	_, err := BuildMiddlewareChain(entries, []string{"audit", "nonexistent"})
	assert.Error(t, err, "unknown middleware name should fail fast")
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestBuildMiddlewareChain_EmptyOrder(t *testing.T) {
	t.Parallel()

	entries := map[string]MiddlewareBuilder{
		"audit": func() server.ToolHandlerMiddleware {
			return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
		},
	}

	chain, err := BuildMiddlewareChain(entries, []string{})
	assert.NoError(t, err, "empty order is valid (no middleware)")
	assert.Empty(t, chain)
}

func TestBuildMiddlewareChain_NilBuilderSkipped(t *testing.T) {
	t.Parallel()

	// Nil builders model "optional middleware" — e.g. billing is only
	// registered when STRIPE_SECRET_KEY is set. BuildChain should skip
	// them silently rather than panic or error.
	calls := []string{}
	entries := map[string]MiddlewareBuilder{
		"audit":   func() server.ToolHandlerMiddleware { return recordingMiddlewareForBuilder("audit", &calls) },
		"billing": nil,
	}

	chain, err := BuildMiddlewareChain(entries, []string{"audit", "billing"})
	assert.NoError(t, err)
	assert.Len(t, chain, 1, "nil builder entry must be skipped, not errored")

	applyChainForBuilder(t, chain)
	assert.Equal(t, []string{"audit"}, calls)
}

func TestDefaultBuiltInOrder_IsDeterministic(t *testing.T) {
	t.Parallel()

	// Guard against accidental reordering of the default built-in
	// chain. A re-order here is a semantic change — audit before
	// riskguard means blocked orders are still logged, etc. Any
	// intentional change updates this test explicitly.
	assert.Equal(t, []string{
		"correlation",
		"timeout",
		"audit",
		"hooks",
		"circuitbreaker",
		"riskguard",
		"ratelimit",
		"billing",
		"papertrading",
		"dashboardurl",
	}, DefaultBuiltInOrder)
}

func TestBuildMiddlewareChain_ProducesServerOptions(t *testing.T) {
	t.Parallel()

	entries := map[string]MiddlewareBuilder{
		"audit": func() server.ToolHandlerMiddleware {
			return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
		},
	}

	chain, err := BuildMiddlewareChain(entries, []string{"audit"})
	assert.NoError(t, err)

	for i, mw := range chain {
		opt := server.WithToolHandlerMiddleware(mw)
		assert.NotNil(t, opt, fmt.Sprintf("entry %d produced nil ServerOption", i))
	}
}
