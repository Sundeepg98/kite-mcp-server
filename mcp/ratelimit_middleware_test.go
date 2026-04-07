package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/oauth"
)

func TestToolRateLimiter(t *testing.T) {
	rl := NewToolRateLimiter(map[string]int{"test_tool": 2})
	mw := rl.Middleware()
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	})
	ctx := oauth.ContextWithEmail(context.Background(), "user@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"

	// First 2 calls pass
	r1, _ := handler(ctx, req)
	assert.False(t, r1.IsError)
	r2, _ := handler(ctx, req)
	assert.False(t, r2.IsError)

	// Third call blocked
	r3, _ := handler(ctx, req)
	assert.True(t, r3.IsError)
}

func TestToolRateLimiter_UnlimitedTool(t *testing.T) {
	rl := NewToolRateLimiter(map[string]int{"limited_tool": 1})
	mw := rl.Middleware()
	called := 0
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		called++
		return gomcp.NewToolResultText("OK"), nil
	})
	ctx := oauth.ContextWithEmail(context.Background(), "user@test.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "unlimited_tool" // not in limits map

	// Should pass unlimited times (no limit configured)
	for i := 0; i < 10; i++ {
		r, err := handler(ctx, req)
		assert.NoError(t, err)
		assert.False(t, r.IsError)
	}
	assert.Equal(t, 10, called)
}

func TestToolRateLimiter_PerUserIsolation(t *testing.T) {
	rl := NewToolRateLimiter(map[string]int{"test_tool": 1})
	mw := rl.Middleware()
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	})
	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"

	// User A uses their 1 allowed call
	ctxA := oauth.ContextWithEmail(context.Background(), "a@test.com")
	r1, _ := handler(ctxA, req)
	assert.False(t, r1.IsError)

	// User A is now blocked
	r2, _ := handler(ctxA, req)
	assert.True(t, r2.IsError)

	// User B still has their own quota
	ctxB := oauth.ContextWithEmail(context.Background(), "b@test.com")
	r3, _ := handler(ctxB, req)
	assert.False(t, r3.IsError)
}
