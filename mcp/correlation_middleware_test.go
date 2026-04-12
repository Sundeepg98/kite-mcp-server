package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorrelationMiddleware_InjectsID(t *testing.T) {
	var capturedCtx context.Context
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		capturedCtx = ctx
		return gomcp.NewToolResultText("ok"), nil
	}

	mw := CorrelationMiddleware()
	wrapped := mw(handler)

	result, err := wrapped(context.Background(), gomcp.CallToolRequest{})
	require.NoError(t, err)
	assert.NotNil(t, result)

	id := CorrelationIDFromContext(capturedCtx)
	assert.NotEmpty(t, id, "correlation ID should be set in context")
	assert.Len(t, id, 36, "correlation ID should be a UUID (36 chars)")
}

func TestCorrelationMiddleware_UniquePerCall(t *testing.T) {
	var ids []string
	handler := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		ids = append(ids, CorrelationIDFromContext(ctx))
		return gomcp.NewToolResultText("ok"), nil
	}

	mw := CorrelationMiddleware()
	wrapped := mw(handler)

	for i := 0; i < 5; i++ {
		_, _ = wrapped(context.Background(), gomcp.CallToolRequest{})
	}

	assert.Len(t, ids, 5)
	// All IDs should be unique
	seen := make(map[string]bool)
	for _, id := range ids {
		assert.False(t, seen[id], "duplicate correlation ID: %s", id)
		seen[id] = true
	}
}

func TestCorrelationIDFromContext_NoID(t *testing.T) {
	id := CorrelationIDFromContext(context.Background())
	assert.Empty(t, id)
}
