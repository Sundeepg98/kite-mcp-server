package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// setupStaticEgressIP is the server's static egress IP which users must
// whitelist in their Kite developer console (SEBI April 2026 mandate).
// Kept in sync with the value reported by sebi_compliance_status.
const setupStaticEgressIP = "209.71.68.157"

// Setup status codes returned by the test_ip_whitelist tool.
const (
	setupStatusPass               = "pass"
	setupStatusCredentialsInvalid = "credentials_invalid"
	setupStatusIPNotWhitelisted   = "ip_not_whitelisted"
	setupStatusTokenExpired       = "token_expired"
	setupStatusOtherError         = "other_error"
)

// TestIPWhitelistTool verifies the user's Kite API credentials and IP
// whitelist by making a lightweight test call (GetProfile) to Kite.
type TestIPWhitelistTool struct{}

func (*TestIPWhitelistTool) Tool() mcp.Tool {
	return mcp.NewTool("test_ip_whitelist",
		mcp.WithDescription("Verify your Kite API credentials and IP whitelist by making a lightweight test call to Kite."),
		mcp.WithTitleAnnotation("Test IP Whitelist"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

// testIPWhitelistResponse is the structured response returned by the tool.
type testIPWhitelistResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	EgressIP  string `json:"egress_ip"`
	Timestamp string `json:"timestamp"`
}

func (*TestIPWhitelistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "test_ip_whitelist")

		return handler.WithSession(ctx, "test_ip_whitelist", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp := &testIPWhitelistResponse{
				EgressIP:  setupStaticEgressIP,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}

			// GetProfile is the cheapest read-only Kite call and exercises the
			// whole auth + network path: credentials, IP whitelist, and token.
			_, err := session.Broker.GetProfile()
			if err == nil {
				resp.Status = setupStatusPass
				resp.Message = "Kite API reachable. Credentials valid, IP whitelist OK."
				return handler.MarshalResponse(resp, "test_ip_whitelist")
			}

			// Map the error onto a user-friendly status. The Kite API returns
			// typed errors (TokenException, InputException, etc.) along with
			// descriptive messages; match the descriptive text defensively so
			// we degrade gracefully if upstream wording shifts.
			rawErr := err.Error()
			lowered := strings.ToLower(rawErr)
			switch {
			case strings.Contains(lowered, "ip_address"),
				strings.Contains(lowered, "whitelist"),
				strings.Contains(lowered, " ip "),
				strings.HasPrefix(lowered, "ip "),
				strings.HasSuffix(lowered, " ip"):
				resp.Status = setupStatusIPNotWhitelisted
				resp.Message = fmt.Sprintf("IP %s is not whitelisted in your Kite developer console. Add it at https://developers.kite.trade/apps. Kite said: %s", setupStaticEgressIP, rawErr)
			case strings.Contains(lowered, "api_key"),
				strings.Contains(lowered, "invalid_key"),
				strings.Contains(lowered, "credentials"):
				resp.Status = setupStatusCredentialsInvalid
				resp.Message = fmt.Sprintf("Kite rejected your credentials. Re-register them via the login tool. Kite said: %s", rawErr)
			case strings.Contains(lowered, "token"),
				strings.Contains(lowered, "expired"):
				resp.Status = setupStatusTokenExpired
				resp.Message = fmt.Sprintf("Your Kite session has expired (tokens refresh ~6 AM IST daily). Re-run the login tool. Kite said: %s", rawErr)
			default:
				resp.Status = setupStatusOtherError
				resp.Message = fmt.Sprintf("Unexpected error calling Kite: %s", rawErr)
			}
			return handler.MarshalResponse(resp, "test_ip_whitelist")
		})
	}
}
