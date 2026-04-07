package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestTimeoutMiddleware_PassesOnTime(t *testing.T) {
	mw := TimeoutMiddleware(1 * time.Second)
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	})
	result, err := handler(context.Background(), gomcp.CallToolRequest{})
	assert.NoError(t, err)
	assert.False(t, result.IsError)
}

func TestTimeoutMiddleware_TimesOut(t *testing.T) {
	mw := TimeoutMiddleware(50 * time.Millisecond)
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		time.Sleep(200 * time.Millisecond)
		return gomcp.NewToolResultText("OK"), nil
	})
	result, err := handler(context.Background(), gomcp.CallToolRequest{})
	assert.NoError(t, err)
	assert.True(t, result.IsError)
}
