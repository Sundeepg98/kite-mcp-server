// Package example demonstrates how to create an external MCP tool plugin.
// Import this package in main.go to register the tool at startup.
package example

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kitemcp "github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/kc"
)

func init() {
	kitemcp.RegisterPlugin(&ServerTimeTool{})
}

// ServerTimeTool is a sample plugin that returns the current server time.
type ServerTimeTool struct{}

func (*ServerTimeTool) Tool() mcp.Tool {
	return mcp.NewTool("server_time",
		mcp.WithDescription("Returns current server time and timezone. Example plugin tool."),
		mcp.WithTitleAnnotation("Server Time (Plugin)"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

func (*ServerTimeTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		now := time.Now()
		return mcp.NewToolResultText(fmt.Sprintf(
			"Server time: %s\nTimezone: %s\nUnix: %d",
			now.Format(time.RFC3339), now.Location().String(), now.Unix(),
		)), nil
	}
}
