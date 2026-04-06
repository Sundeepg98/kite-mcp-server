package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// isAlphanumeric returns true if s is non-empty and contains only ASCII letters and digits.
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

// dashboardBaseURL returns the validated base URL for the dashboard, or empty string.
func dashboardBaseURL(manager *kc.Manager) string {
	var base string
	if manager.IsLocalMode() {
		base = "http://127.0.0.1:8080"
	} else {
		base = manager.ExternalURL()
	}
	if base == "" {
		return ""
	}
	// Validate that the base URL is well-formed with an http(s) scheme and non-empty host.
	parsed, err := url.Parse(base)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Host == "" {
		return ""
	}
	return base
}

// dashboardLink returns a markdown dashboard link suffix, or empty string if not configured.
func dashboardLink(manager *kc.Manager) string {
	base := dashboardBaseURL(manager)
	if base == "" {
		return ""
	}
	return fmt.Sprintf("\n\nOps dashboard: [Open Dashboard](%s/admin/ops)", base)
}

// dashboardPageURL returns the full dashboard URL for a specific page path (e.g. "/dashboard", "/dashboard/activity").
func dashboardPageURL(manager *kc.Manager, pagePath string) string {
	base := dashboardBaseURL(manager)
	if base == "" {
		return ""
	}
	return base + pagePath
}

// pageRoutes maps page names to URL paths for the open_dashboard tool.
var pageRoutes = map[string]string{
	"portfolio": "/dashboard",
	"activity":  "/dashboard/activity",
	"orders":    "/dashboard/orders",
	"alerts":    "/dashboard/alerts",
	"paper":     "/dashboard/paper",
	"safety":    "/dashboard/safety",
	"watchlist": "/dashboard/watchlist",
	"options":   "/dashboard/options",
}

// toolDashboardPage maps tool names to the dashboard page path that is most
// relevant for viewing the data returned by that tool.  Used by
// DashboardURLMiddleware to auto-append a dashboard link to successful tool
// responses.
var toolDashboardPage = map[string]string{
	// Portfolio / overview page
	"get_holdings":             "/dashboard",
	"get_positions":            "/dashboard",
	"get_margins":              "/dashboard",
	"get_profile":              "/dashboard",
	"portfolio_summary":        "/dashboard",
	"portfolio_concentration":  "/dashboard",
	"position_analysis":        "/dashboard",
	"trading_context":          "/dashboard",
	"pre_trade_check":          "/dashboard",
	"get_pnl_journal":          "/dashboard",
	"get_mf_holdings":          "/dashboard",
	"tax_harvest_analysis":     "/dashboard",
	"portfolio_rebalance":      "/dashboard",

	// Orders page
	"get_orders":               "/dashboard/orders",
	"get_order_history":        "/dashboard/orders",
	"get_order_trades":         "/dashboard/orders",
	"get_trades":               "/dashboard/orders",
	"place_order":              "/dashboard/orders",
	"modify_order":             "/dashboard/orders",
	"cancel_order":             "/dashboard/orders",
	"close_position":           "/dashboard/orders",
	"close_all_positions":      "/dashboard/orders",
	"get_gtts":                 "/dashboard/orders",
	"place_gtt_order":          "/dashboard/orders",
	"modify_gtt_order":         "/dashboard/orders",
	"delete_gtt_order":         "/dashboard/orders",

	// Alerts page
	"list_alerts":              "/dashboard/alerts",
	"set_alert":                "/dashboard/alerts",
	"delete_alert":             "/dashboard/alerts",
	"set_trailing_stop":        "/dashboard/alerts",
	"list_trailing_stops":      "/dashboard/alerts",
	"cancel_trailing_stop":     "/dashboard/alerts",

	// Derivatives / options tools → options chain page
	"get_option_chain":         "/dashboard/options",
	"options_greeks":           "/dashboard/options",
	"options_strategy":         "/dashboard/options",

	// Analytics tools → portfolio page
	"technical_indicators":     "/dashboard",
	"backtest_strategy":        "/dashboard",

	// Paper trading page
	"paper_trading_toggle":     "/dashboard/paper",
	"paper_trading_status":     "/dashboard/paper",
	"paper_trading_reset":      "/dashboard/paper",

	// Native alerts page
	"place_native_alert":       "/dashboard/alerts",
	"list_native_alerts":       "/dashboard/alerts",
	"modify_native_alert":      "/dashboard/alerts",
	"delete_native_alert":      "/dashboard/alerts",
	"get_native_alert_history": "/dashboard/alerts",

	// Analytics (portfolio page)
	"dividend_calendar":        "/dashboard",
	"sector_exposure":          "/dashboard",

	// Safety page
	"sebi_compliance_status":   "/dashboard/safety",

	// Margins / orders page
	"get_order_margins":        "/dashboard/orders",
	"get_basket_margins":       "/dashboard/orders",
	"get_order_charges":        "/dashboard/orders",
	"convert_position":         "/dashboard/orders",

	// Mutual funds (portfolio page)
	"get_mf_orders":            "/dashboard",
	"get_mf_sips":              "/dashboard",

	// Watchlist page
	"list_watchlists":       "/dashboard/watchlist",
	"get_watchlist":         "/dashboard/watchlist",
	"create_watchlist":      "/dashboard/watchlist",
	"delete_watchlist":      "/dashboard/watchlist",
	"add_to_watchlist":      "/dashboard/watchlist",
	"remove_from_watchlist": "/dashboard/watchlist",
}

// DashboardURLForTool returns the full dashboard URL for a given tool name,
// or empty string if the tool has no associated dashboard page.
func DashboardURLForTool(manager *kc.Manager, toolName string) string {
	pagePath, ok := toolDashboardPage[toolName]
	if !ok {
		return ""
	}
	return dashboardPageURL(manager, pagePath)
}

// DashboardURLMiddleware returns server-level middleware that auto-appends a
// dashboard_url hint as a second TextContent block on successful tool responses
// when the tool has a relevant dashboard page.
func DashboardURLMiddleware(manager *kc.Manager) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			result, err := next(ctx, request)
			if err != nil || result == nil || result.IsError {
				return result, err
			}

			toolName := request.Params.Name
			dashURL := DashboardURLForTool(manager, toolName)
			if dashURL == "" {
				return result, err
			}

			result.Content = append(result.Content, mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf(`{"dashboard_url":"%s"}`, dashURL),
			})
			return result, err
		}
	}
}

type LoginTool struct{}

func (*LoginTool) Tool() mcp.Tool {
	return mcp.NewTool("login",
		mcp.WithDescription("Login to Kite API. This tool helps you log in to the Kite API. If you are starting off a new conversation call this tool before hand. Call this if you get a session error. Returns a link that the user should click to authorize access, present as markdown if your client supports so that they can click it easily when rendered. Optionally provide your own Kite developer app credentials (api_key + api_secret) for per-user isolation — get them from https://developers.kite.trade/apps"),
		mcp.WithTitleAnnotation("Login to Kite"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("api_key",
			mcp.Description("Optional: Your Kite developer app API key from https://developers.kite.trade/apps"),
		),
		mcp.WithString("api_secret",
			mcp.Description("Optional: Your Kite developer app API secret"),
		),
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

		// If user provided their own credentials, store them for per-user isolation
		args := request.GetArguments()
		apiKey := SafeAssertString(args["api_key"], "")
		apiSecret := SafeAssertString(args["api_secret"], "")

		// Validate that api_key and api_secret contain only alphanumeric characters
		if apiKey != "" && !isAlphanumeric(apiKey) {
			return mcp.NewToolResultError("Invalid api_key: must contain only alphanumeric characters (letters and digits)."), nil
		}
		if apiSecret != "" && !isAlphanumeric(apiSecret) {
			return mcp.NewToolResultError("Invalid api_secret: must contain only alphanumeric characters (letters and digits)."), nil
		}

		if apiKey != "" && apiSecret != "" {
			if email == "" {
				return mcp.NewToolResultError("OAuth authentication required to register per-user credentials. Please connect via an OAuth-enabled client first."), nil
			}
			manager.CredentialStore().Set(email, &kc.KiteCredentialEntry{
				APIKey:    apiKey,
				APISecret: apiSecret,
			})
			// Clear old cached token — it was generated with different credentials
			manager.TokenStore().Delete(email)
			// Clear session data so next GetOrCreateSession uses the new API key
			if err := manager.ClearSessionData(mcpSessionID); err != nil {
				manager.Logger.Warn("Failed to clear session data after credential registration", "error", err)
			}
			manager.Logger.Info("Stored per-user Kite credentials via login tool", "email", email)
		} else if apiKey != "" || apiSecret != "" {
			return mcp.NewToolResultError("Both api_key and api_secret are required. Provide both or neither."), nil
		}

		// Check if credentials are configured (global or per-user)
		if !manager.HasGlobalCredentials() && !manager.HasUserCredentials(email) {
			manager.Logger.Info("No credentials configured for login")
			handler.trackToolError(ctx, "login", "no_credentials")
			return mcp.NewToolResultError("No Kite API credentials configured. Either set KITE_API_KEY and KITE_API_SECRET environment variables, or provide api_key and api_secret parameters to register your own credentials."), nil
		}

		// Get or create a Kite session for this MCP session (email-aware)
		kiteSession, isNew, err := manager.GetOrCreateSessionWithEmail(mcpSessionID, email)
		if err != nil {
			manager.Logger.Error("Failed to get or create Kite session", "session_id", mcpSessionID, "error", err)
			handler.trackToolError(ctx, "login", "session_error")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get or create Kite session: %s", err.Error())), nil
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
					return mcp.NewToolResultError(fmt.Sprintf("Failed to clear session data: %s", clearErr.Error())), nil
				}

				// Clear cached token too if it exists
				if email != "" {
					manager.TokenStore().Delete(email)
				}

				// Create a new session
				_, _, err = manager.GetOrCreateSessionWithEmail(mcpSessionID, email)
				if err != nil {
					manager.Logger.Error("Failed to create new Kite session", "session_id", mcpSessionID, "error", err)
					return mcp.NewToolResultError(fmt.Sprintf("Failed to create new Kite session: %s", err.Error())), nil
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
			return mcp.NewToolResultError(fmt.Sprintf("Failed to generate Kite login URL: %s", err.Error())), nil
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
		mcp.WithDescription("Open a specific dashboard page in the user's browser. Use this when the user asks to see their portfolio, orders, alerts, or activity visually. Supports deep-linking with filters. In local mode, auto-opens the browser. In remote mode, returns a clickable link. Pages: portfolio (default), orders, alerts, activity, paper, safety, ops."),
		mcp.WithTitleAnnotation("Open Dashboard"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("page",
			mcp.Description("Dashboard page to open: portfolio, activity, orders, alerts, paper, safety, ops"),
			mcp.DefaultString("portfolio"),
		),
		mcp.WithString("category",
			mcp.Description("Filter by category (activity page only): order, query, market_data, alert, notification, ticker, setup"),
		),
		mcp.WithNumber("days",
			mcp.Description("Time range in days (activity/orders pages): e.g. 1, 7, 30"),
		),
		mcp.WithBoolean("errors",
			mcp.Description("Show only errors (activity page only)"),
		),
	)
}

func (*OpenDashboardTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler := NewToolHandler(manager)
		handler.trackToolCall(ctx, "open_dashboard")

		// Build base URL
		var baseURL string
		if manager.IsLocalMode() {
			baseURL = "http://127.0.0.1:8080"
		} else {
			baseURL = manager.ExternalURL()
			if baseURL == "" {
				return mcp.NewToolResultError("External URL not configured"), nil
			}
		}

		// Parse page parameter
		args := request.GetArguments()
		page := SafeAssertString(args["page"], "portfolio")
		pagePath, ok := pageRoutes[page]
		if !ok {
			pagePath = pageRoutes["portfolio"]
			page = "portfolio"
		}

		// Build query parameters for deep-linking
		queryParams := url.Values{}
		if category := SafeAssertString(args["category"], ""); category != "" && page == "activity" {
			queryParams.Set("category", category)
		}
		if days, ok := args["days"].(float64); ok && days > 0 && (page == "activity" || page == "orders") {
			queryParams.Set("days", strconv.Itoa(int(days)))
		}
		if errorsOnly, ok := args["errors"].(bool); ok && errorsOnly && page == "activity" {
			queryParams.Set("errors", "true")
		}

		// Construct the full path with query string
		fullPath := pagePath
		if len(queryParams) > 0 {
			fullPath += "?" + queryParams.Encode()
		}

		// Include email in dashboard login URL for seamless browser auth
		email := oauth.EmailFromContext(ctx)
		var dashURL string
		if email != "" {
			dashURL = baseURL + "/auth/browser-login?email=" + url.QueryEscape(email) + "&redirect=" + url.QueryEscape(fullPath)
		} else {
			dashURL = baseURL + fullPath
		}

		// Auto-open browser in local mode
		if err := manager.OpenBrowser(dashURL); err != nil {
			manager.Logger.Warn("Failed to auto-open dashboard", "error", err)
		}

		// Page title for display
		pageTitle := strings.ToUpper(page[:1]) + page[1:]

		if manager.IsLocalMode() {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{Type: "text", Text: fmt.Sprintf("%s dashboard opened in your browser: %s", pageTitle, dashURL)},
				},
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{Type: "text", Text: fmt.Sprintf("Open the %s dashboard: [%s Dashboard](%s)", page, pageTitle, dashURL)},
			},
		}, nil
	}
}
