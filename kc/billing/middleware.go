package billing

import (
	"context"
	"fmt"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Middleware returns an MCP tool handler middleware that enforces billing tier
// requirements. Tools that require a higher tier than the user's current
// subscription are rejected with an upgrade prompt.
func Middleware(store *Store, adminEmailFn func(string) string) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				// No authenticated user — let the request through
				// (auth middleware will handle rejection if needed).
				return next(ctx, request)
			}

			required := RequiredTier(request.Params.Name)
			current := store.GetTierForUser(email, adminEmailFn).EffectiveTier()

			if current < required {
				return gomcp.NewToolResultError(fmt.Sprintf(
					"This tool requires a %s subscription (you have: %s). Upgrade at /dashboard/billing",
					required, current)), nil
			}

			return next(ctx, request)
		}
	}
}
