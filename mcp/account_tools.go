package mcp

import (
	"context"
	"fmt"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
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
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "delete_my_account")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		confirm := SafeAssertBool(args["confirm"], false)
		if !confirm {
			return gomcp.NewToolResultError("This permanently deletes ALL your data (credentials, tokens, alerts, watchlists, trailing stops, paper trading). Set confirm: true to proceed."), nil
		}

		// Delete all user data across stores
		manager.CredentialStore().Delete(email)
		manager.TokenStore().Delete(email)

		if sm := manager.SessionManager(); sm != nil {
			sm.TerminateByEmail(email)
		}

		manager.AlertStore().DeleteByEmail(email)

		if ws := manager.WatchlistStore(); ws != nil {
			ws.DeleteByEmail(email)
		}

		if tsm := manager.TrailingStopManager(); tsm != nil {
			tsm.CancelByEmail(email)
		}

		if pe := manager.PaperEngine(); pe != nil {
			if err := pe.Reset(email); err != nil {
				manager.Logger.Error("Failed to reset paper trading during account delete", "email", email, "error", err)
			}
			if err := pe.Disable(email); err != nil {
				manager.Logger.Error("Failed to disable paper trading during account delete", "email", email, "error", err)
			}
		}

		if us := manager.UserStore(); us != nil {
			if err := us.UpdateStatus(email, "offboarded"); err != nil {
				manager.Logger.Error("Failed to update user status during account delete", "email", email, "error", err)
			}
		}

		manager.Logger.Info("User self-deleted account via MCP", "email", email)

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
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "update_my_credentials")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "api_key", "api_secret"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		apiKey := strings.TrimSpace(SafeAssertString(args["api_key"], ""))
		apiSecret := strings.TrimSpace(SafeAssertString(args["api_secret"], ""))

		if apiKey == "" || apiSecret == "" {
			return gomcp.NewToolResultError("Both api_key and api_secret must be non-empty"), nil
		}

		manager.CredentialStore().Set(email, &kc.KiteCredentialEntry{
			APIKey:    apiKey,
			APISecret: apiSecret,
		})

		manager.Logger.Info("User updated credentials via MCP", "email", email)

		return gomcp.NewToolResultText(fmt.Sprintf("Credentials updated successfully. Your cached Kite token has been cleared. Please use the login tool to re-authenticate with the new credentials.")), nil
	}
}
