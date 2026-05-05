package common

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// AdminCheck validates that the caller is an authenticated admin.
// Returns email on success, or an error result on failure.
//
// Phase 3a Batch 3: takes the narrow kc.UserStoreProvider port rather
// than the full *kc.Manager. *kc.Manager satisfies this provider so
// existing callers passing manager keep compiling unchanged.
//
// Anchor 1 PR 1.4: relocated from mcp/admin_tools.go to mcp/common
// because mcp/observability_tool.go (which stays in mcp/ root)
// also needs AdminCheck. Putting the helper in mcp/common (a leaf
// sub-package) avoids a cycle through mcp/admin.
func AdminCheck(ctx context.Context, users kc.UserStoreProvider) (string, *mcp.CallToolResult) {
	email := oauth.EmailFromContext(ctx)
	if email == "" {
		return "", mcp.NewToolResultError(ErrAuthRequired)
	}
	if users != nil {
		if uStore := users.UserStore(); uStore != nil {
			if !uStore.IsAdmin(email) {
				return "", mcp.NewToolResultError(ErrAdminRequired)
			}
		}
	}
	return email, nil
}

// WithAdminCheck wraps a tool handler that needs admin access. It calls
// AdminCheck and, on success, passes the admin email to the inner handler.
// Use for new admin tools to avoid repeating the AdminCheck boilerplate.
//
// Phase 3a Batch 3: takes kc.UserStoreProvider (narrow port). *kc.Manager
// satisfies this provider, so existing call sites that pass manager
// continue to compile unchanged.
//
// Anchor 1 PR 1.4: relocated from mcp/admin_tools.go to mcp/common
// alongside AdminCheck.
func WithAdminCheck(users kc.UserStoreProvider, handler func(ctx context.Context, adminEmail string, request mcp.CallToolRequest) (*mcp.CallToolResult, error)) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		adminEmail, errResult := AdminCheck(ctx, users)
		if errResult != nil {
			return errResult, nil
		}
		return handler(ctx, adminEmail, request)
	}
}
