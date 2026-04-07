package mcp

import (
	"context"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// TimeoutMiddleware adds a per-tool execution timeout.
// If the tool handler doesn't return within the timeout, returns an error.
func TimeoutMiddleware(timeout time.Duration) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			type result struct {
				res *gomcp.CallToolResult
				err error
			}
			ch := make(chan result, 1)
			go func() {
				r, e := next(ctx, request)
				ch <- result{r, e}
			}()

			select {
			case <-ctx.Done():
				return gomcp.NewToolResultError("Tool execution timed out. Please try again."), nil
			case r := <-ch:
				return r.res, r.err
			}
		}
	}
}
