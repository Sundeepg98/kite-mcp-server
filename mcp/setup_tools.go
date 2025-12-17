package mcp

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zerodha/kite-mcp-server/kc"
)

type LoginTool struct{}

func (*LoginTool) Definition() *mcp.Tool {
	return NewTool("login",
		"Login to Kite or refresh an expired 24-hour Kite session. Returns a link that the user should click to authorize access. Present this as a markdown link for easy clicking.",
		nil,
	)
}

func (*LoginTool) Handler(manager *kc.Manager) ToolHandler {
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		sessionID := request.Session.ID()
		manager.Logger.Info("Login tool called", "session_id", sessionID)

		// Check if the user is already logged in and has a valid token.
		if client, err := manager.GetAuthenticatedClient(sessionID); err == nil {
			profile, err := client.GetUserProfile()
			if err == nil {
				manager.Logger.Info("User is already logged in with a valid Kite session.", "session_id", sessionID, "user", profile.UserName)
				return NewToolResultText(fmt.Sprintf("You are already logged in as %s. There is no need to log in again.", profile.UserName)), nil
			}
		}

		// If not, generate a login URL for them. This works for both first-time login and re-login.
		url, err := manager.GenerateLoginURL(sessionID)
		if err != nil {
			manager.Logger.Error("Error generating Kite login URL", "session_id", sessionID, "error", err)
			return NewToolResultError("Failed to generate Kite login URL"), nil
		}

		manager.Logger.Info("Successfully generated Kite login URL", "session_id", sessionID)
		return NewToolResultText(fmt.Sprintf("Please log in to Kite by clicking this link: [Login to Kite](%s)\n\nAfter completing the login in your browser, you can continue with your request.", url)), nil
	}
}
