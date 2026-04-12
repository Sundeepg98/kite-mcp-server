package mcp

import (
	"context"

	"github.com/google/uuid"
	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// correlationKey is the context key for correlation IDs.
type correlationKey struct{}

// CorrelationIDFromContext extracts the correlation ID from the context.
// Returns an empty string if no correlation ID is set.
func CorrelationIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(correlationKey{}).(string); ok {
		return id
	}
	return ""
}

// CorrelationMiddleware generates a unique correlation ID for each tool call
// and injects it into the context. Downstream middleware and handlers can
// retrieve it via CorrelationIDFromContext for logging and audit trails.
func CorrelationMiddleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			id := uuid.New().String()
			ctx = context.WithValue(ctx, correlationKey{}, id)
			return next(ctx, request)
		}
	}
}
