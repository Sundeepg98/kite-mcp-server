package portfolio

import (
	"context"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/mcp/common"
	"github.com/zerodha/kite-mcp-server/mcp/plugin"
)

// DeleteMyAccountTool permanently deletes the authenticated user's account and all data.
type DeleteMyAccountTool struct{}

func (*DeleteMyAccountTool) Tool() gomcp.Tool {
	return gomcp.NewTool("delete_my_account",
		gomcp.WithDescription("Permanently delete your account and all associated data (credentials, tokens, alerts, watchlists, trailing stops, paper trading). This action cannot be undone."),
		gomcp.WithTitleAnnotation("Delete My Account"),
		gomcp.WithDestructiveHintAnnotation(true),
		gomcp.WithIdempotentHintAnnotation(false),
		gomcp.WithOpenWorldHintAnnotation(false),
		gomcp.WithBoolean("confirm",
			gomcp.Description("Must be true to confirm deletion. This permanently removes all your data."),
			gomcp.Required(),
		),
	)
}

func (*DeleteMyAccountTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := common.NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.TrackToolCall(ctx, "delete_my_account")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		confirm := common.NewArgParser(args).Bool("confirm", false)
		if !confirm {
			return gomcp.NewToolResultError("This permanently deletes ALL your data (credentials, tokens, alerts, watchlists, trailing stops, paper trading). Set confirm: true to proceed."), nil
		}

		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.DeleteMyAccountCommand{Email: email}); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		return gomcp.NewToolResultText("Account deleted. All your data (credentials, tokens, alerts, watchlists, trailing stops, paper trading) has been permanently removed."), nil
	}
}

// UpdateMyCredentialsTool updates the authenticated user's Kite API credentials.
type UpdateMyCredentialsTool struct{}

func (*UpdateMyCredentialsTool) Tool() gomcp.Tool {
	return gomcp.NewTool("update_my_credentials",
		gomcp.WithDescription("Update your Kite API credentials (api_key and api_secret). The old cached Kite token will be invalidated and you will need to re-authenticate."),
		gomcp.WithTitleAnnotation("Update My Credentials"),
		gomcp.WithDestructiveHintAnnotation(false),
		gomcp.WithIdempotentHintAnnotation(true),
		gomcp.WithOpenWorldHintAnnotation(false),
		gomcp.WithString("api_key",
			gomcp.Description("Your Kite developer app API key"),
			gomcp.Required(),
		),
		gomcp.WithString("api_secret",
			gomcp.Description("Your Kite developer app API secret"),
			gomcp.Required(),
		),
	)
}

func (*UpdateMyCredentialsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := common.NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.TrackToolCall(ctx, "update_my_credentials")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := common.ValidateRequired(args, "api_key", "api_secret"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		p := common.NewArgParser(args)
		apiKey := strings.TrimSpace(p.String("api_key", ""))
		apiSecret := strings.TrimSpace(p.String("api_secret", ""))

		if apiKey == "" || apiSecret == "" {
			return gomcp.NewToolResultError("Both api_key and api_secret must be non-empty"), nil
		}

		// Round-5 Phase B: dispatch owns persistence. The command handler calls
		// UpdateMyCredentialsUseCase which persists via CredentialUpdater and
		// invalidates the cached token. No direct .Set/.Delete on stores here —
		// the bus is the single write entry point for credentials.
		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.UpdateMyCredentialsCommand{Email: email, APIKey: apiKey, APISecret: apiSecret}); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		return gomcp.NewToolResultText("Credentials updated successfully. Your cached Kite token has been cleared. Please use the login tool to re-authenticate with the new credentials."), nil
	}
}

func init() {
	plugin.RegisterInternalTool(&DeleteMyAccountTool{})
	plugin.RegisterInternalTool(&UpdateMyCredentialsTool{})
}
