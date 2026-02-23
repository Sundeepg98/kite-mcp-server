package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// dashboardLink returns a markdown dashboard link suffix, or empty string if not configured.
func dashboardLink(manager *kc.Manager) string {
	var base string
	if manager.IsLocalMode() {
		base = "http://127.0.0.1:8080"
	} else {
		base = manager.ExternalURL()
	}
	if base == "" {
		return ""
	}
	return fmt.Sprintf("\n\nOps dashboard: [Open Dashboard](%s/admin/ops)", base)
}

type LoginTool struct{}

func (*LoginTool) Tool() mcp.Tool {
	return mcp.NewTool("login",
		mcp.WithDescription("Login to Kite API. This tool helps you log in to the Kite API. If you are starting off a new conversation call this tool before hand. Call this if you get a session error. Returns a link that the user should click to authorize access, present as markdown if your client supports so that they can click it easily when rendered."),
	)
}

func (*LoginTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Track login tool usage with session context
		handler := NewToolHandler(manager)
		handler.trackToolCall(ctx, "login")

		// Get MCP client session from context
		mcpClientSession := server.ClientSessionFromContext(ctx)

		// Extract MCP session ID and OAuth email
		mcpSessionID := mcpClientSession.SessionID()
		email := oauth.EmailFromContext(ctx)
		manager.Logger.Info("Login tool called", "session_id", mcpSessionID, "email", email)

		// Check if credentials are configured
		if !manager.HasGlobalCredentials() {
			manager.Logger.Info("No credentials configured for login")
			handler.trackToolError(ctx, "login", "no_credentials")
			return mcp.NewToolResultError("No Kite API credentials configured. Set KITE_API_KEY and KITE_API_SECRET environment variables."), nil
		}

		// Get or create a Kite session for this MCP session (email-aware)
		kiteSession, isNew, err := manager.GetOrCreateSessionWithEmail(mcpSessionID, email)
		if err != nil {
			manager.Logger.Error("Failed to get or create Kite session", "session_id", mcpSessionID, "error", err)
			handler.trackToolError(ctx, "login", "session_error")
			return mcp.NewToolResultError("Failed to get or create Kite session"), nil
		}

		// Ensure email is set on session for callback lookup
		if email != "" {
			kiteSession.Email = email
		}

		// Check cached token (per-email, Fly.io multi-user flow)
		if isNew && email != "" && manager.HasCachedToken(email) {
			profile, err := kiteSession.Kite.Client.GetUserProfile()
			if err == nil {
				manager.Logger.Info("Cached token valid", "session_id", mcpSessionID, "email", email, "user", profile.UserName)
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.TextContent{
							Type: "text",
							Text: fmt.Sprintf("You are already logged in as %s (auto-authenticated)%s", profile.UserName, dashboardLink(manager)),
						},
					},
				}, nil
			}
			// Cached token expired, remove it
			manager.Logger.Warn("Cached token expired, clearing", "email", email, "error", err)
			manager.TokenStore().Delete(email)
		}

		if isNew && manager.HasPreAuth() {
			// Pre-auth session — verify the token works
			profile, err := kiteSession.Kite.Client.GetUserProfile()
			if err == nil {
				manager.Logger.Info("Pre-auth token valid", "session_id", mcpSessionID, "user", profile.UserName)
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.TextContent{
							Type: "text",
							Text: fmt.Sprintf("You are already logged in as %s (pre-authenticated)%s", profile.UserName, dashboardLink(manager)),
						},
					},
				}, nil
			}
			manager.Logger.Warn("Pre-auth token invalid, falling through to login", "session_id", mcpSessionID, "error", err)
		}

		if !isNew {
			// We have an existing session, verify it works by getting the profile
			manager.Logger.Debug("Found existing Kite session, verifying with profile check", "session_id", mcpSessionID)
			profile, err := kiteSession.Kite.Client.GetUserProfile()
			if err != nil {
				manager.Logger.Warn("Kite profile check failed, clearing session data", "session_id", mcpSessionID, "error", err)
				// If we are still getting an error, lets clear session data and recreate
				if clearErr := manager.ClearSessionData(mcpSessionID); clearErr != nil {
					manager.Logger.Error("Failed to clear session data", "session_id", mcpSessionID, "error", clearErr)
					return mcp.NewToolResultError("Failed to clear session data"), nil
				}

				// Clear cached token too if it exists
				if email != "" {
					manager.TokenStore().Delete(email)
				}

				// Create a new session
				_, _, err = manager.GetOrCreateSessionWithEmail(mcpSessionID, email)
				if err != nil {
					manager.Logger.Error("Failed to create new Kite session", "session_id", mcpSessionID, "error", err)
					return mcp.NewToolResultError("Failed to create new Kite session"), nil
				}
			} else {
				manager.Logger.Info("Kite profile check successful", "session_id", mcpSessionID, "user", profile.UserName)
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.TextContent{
							Type: "text",
							Text: fmt.Sprintf("You are already logged in as %s%s", profile.UserName, dashboardLink(manager)),
						},
					},
				}, nil
			}
		}

		// Proceed with Kite login URL generation using the MCP session
		url, err := manager.SessionLoginURL(mcpSessionID)
		if err != nil {
			manager.Logger.Error("Error generating Kite login URL", "session_id", mcpSessionID, "error", err)
			return mcp.NewToolResultError("Failed to generate Kite login URL"), nil
		}

		manager.Logger.Info("Successfully generated Kite login URL", "session_id", mcpSessionID)

		// Auto-open browser in local/STDIO mode
		if err := manager.OpenBrowser(url); err != nil {
			manager.Logger.Warn("Failed to auto-open browser", "error", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("IMPORTANT: Please display this warning to the user before proceeding:\n\n⚠️ **WARNING: AI systems are unpredictable and non-deterministic. By continuing, you agree to interact with your Zerodha account via AI at your own risk.**\n\nAfter showing the warning above, provide the user with this login link: [Login to Kite](%s)\n\nIf your client supports clickable links, you can render and present it and ask them to click the link above. Otherwise, display the URL and ask them to copy and paste it into their browser: %s\n\nAfter completing the login in your browser, let me know and I'll continue with your request.", url, url),
				},
			},
		}, nil
	}
}

type OpenDashboardTool struct{}

func (*OpenDashboardTool) Tool() mcp.Tool {
	return mcp.NewTool("open_dashboard",
		mcp.WithDescription("Open the ops dashboard in the user's browser. Shows server health: active sessions, ticker connections, price alerts, and real-time logs. In local mode, automatically opens the browser. In remote mode, returns a clickable link."),
	)
}

func (*OpenDashboardTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler := NewToolHandler(manager)
		handler.trackToolCall(ctx, "open_dashboard")

		// Build dashboard URL
		var baseURL string
		if manager.IsLocalMode() {
			baseURL = "http://127.0.0.1:8080"
		} else {
			baseURL = manager.ExternalURL()
			if baseURL == "" {
				return mcp.NewToolResultError("External URL not configured"), nil
			}
		}
		dashURL := baseURL + "/admin/ops"

		// Auto-open browser in local mode
		if err := manager.OpenBrowser(dashURL); err != nil {
			manager.Logger.Warn("Failed to auto-open dashboard", "error", err)
		}

		if manager.IsLocalMode() {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{Type: "text", Text: fmt.Sprintf("Ops dashboard opened in your browser: %s", dashURL)},
				},
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{Type: "text", Text: fmt.Sprintf("Open the ops dashboard: [Ops Dashboard](%s)", dashURL)},
			},
		}, nil
	}
}
