package mcp

import (
	"context"
	"fmt"
	"regexp"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// kiteAPIKeyPattern validates basic Kite API key format (lowercase alphanumeric, 8-32 chars).
var kiteAPIKeyPattern = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

type SetupKiteTool struct{}

func (*SetupKiteTool) Tool() mcp.Tool {
	return mcp.NewTool("setup_kite",
		mcp.WithDescription(
			"Register your Kite developer app credentials for multi-user support. "+
				"Create a free Kite app at https://developers.kite.trade/apps, "+
				"set the Redirect URL to https://kite-mcp-server.fly.dev/callback, "+
				"then provide your API key and API secret here. "+
				"After setup, call the login tool to authenticate with your Zerodha account.",
		),
		mcp.WithString("api_key",
			mcp.Description("Your Kite developer app API key (from https://developers.kite.trade/apps)"),
			mcp.Required(),
		),
		mcp.WithString("api_secret",
			mcp.Description("Your Kite developer app API secret"),
			mcp.Required(),
		),
	)
}

func (*SetupKiteTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler := NewToolHandler(manager)
		handler.trackToolCall(ctx, "setup_kite")

		// Extract email from OAuth context — required for per-user credential storage
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			handler.trackToolError(ctx, "setup_kite", "no_email")
			return mcp.NewToolResultError(
				"setup_kite requires OAuth authentication. Your email is used to store credentials per-user.",
			), nil
		}

		// Extract and validate parameters
		args := request.GetArguments()
		if err := ValidateRequired(args, "api_key", "api_secret"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		apiKey := SafeAssertString(args["api_key"], "")
		apiSecret := SafeAssertString(args["api_secret"], "")

		// Basic format validation for API key
		if !kiteAPIKeyPattern.MatchString(apiKey) {
			return mcp.NewToolResultError(
				"Invalid API key format. Kite API keys are lowercase alphanumeric, typically 16 characters. " +
					"Get yours at https://developers.kite.trade/apps",
			), nil
		}

		// Store credentials under this user's email
		manager.CredentialStore().Set(email, &kc.KiteCredentialEntry{
			APIKey:    apiKey,
			APISecret: apiSecret,
		})
		manager.Logger.Info("Stored Kite credentials for user", "email", email)

		// Clear any cached token (old token was generated with possibly different credentials)
		if manager.HasCachedToken(email) {
			manager.TokenStore().Delete(email)
			manager.Logger.Info("Cleared cached token for user (credentials changed)", "email", email)
		}

		// Clear current session data so next operation creates a fresh KiteConnect client with new API key
		mcpClientSession := server.ClientSessionFromContext(ctx)
		sessionID := mcpClientSession.SessionID()
		if err := manager.ClearSessionData(sessionID); err != nil {
			manager.Logger.Warn("Failed to clear session data after credential setup", "error", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"Kite credentials saved for %s. "+
							"You can now use the login tool to authenticate with your Zerodha account.\n\n"+
							"Note: Credentials are stored in memory and will need to be re-entered if the server restarts.",
						email,
					),
				},
			},
		}, nil
	}
}
