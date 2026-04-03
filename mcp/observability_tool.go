package mcp

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Server Metrics Tool ---

// ServerMetricsTool exposes server observability metrics — tool call counts,
// latency, error rates, active sessions, and uptime. Admin-only.
type ServerMetricsTool struct{}

func (*ServerMetricsTool) Tool() mcp.Tool {
	return mcp.NewTool("server_metrics",
		mcp.WithDescription("Get server observability metrics — tool call counts, latency, error rates, active sessions, uptime. Admin-only."),
		mcp.WithTitleAnnotation("Server Metrics"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("period",
			mcp.Description("Time range for metrics: '1h' (last hour), '24h' (last 24 hours), '7d' (last 7 days), '30d' (last 30 days). Defaults to '24h'."),
			mcp.Enum("1h", "24h", "7d", "30d"),
		),
	)
}

// serverMetricsResponse is the structured response for the server_metrics tool.
type serverMetricsResponse struct {
	// Server info
	Uptime    string `json:"uptime"`
	GoVersion string `json:"go_version"`
	ToolCount int    `json:"tool_count"`

	// Session info
	ActiveSessions int `json:"active_sessions"`

	// Aggregate stats for the requested period
	Period       string  `json:"period"`
	TotalCalls   int     `json:"total_calls"`
	ErrorCount   int     `json:"error_count"`
	ErrorRate    string  `json:"error_rate"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`

	// Top tool
	TopTool      string `json:"top_tool"`
	TopToolCount int    `json:"top_tool_count"`

	// Per-tool breakdown (top 50 by call count)
	ToolMetrics []audit.ToolMetric `json:"tool_metrics"`
}

// serverStartTime is set once at package init to track uptime.
var serverStartTime = time.Now()

func (*ServerMetricsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "server_metrics")

		// Admin check: require authenticated email with admin role.
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Authentication required. Please log in first."), nil
		}
		if uStore := manager.UserStore(); uStore != nil {
			if !uStore.IsAdmin(email) {
				return mcp.NewToolResultError("Admin access required. This tool is restricted to server administrators."), nil
			}
		}

		// Parse period.
		args := request.GetArguments()
		period := SafeAssertString(args["period"], "24h")
		var since time.Time
		now := time.Now()
		switch period {
		case "1h":
			since = now.Add(-1 * time.Hour)
		case "24h":
			since = now.Add(-24 * time.Hour)
		case "7d":
			since = now.AddDate(0, 0, -7)
		case "30d":
			since = now.AddDate(0, 0, -30)
		default:
			since = now.Add(-24 * time.Hour)
			period = "24h"
		}

		auditStore := manager.AuditStore()
		if auditStore == nil {
			return mcp.NewToolResultError("Audit store not available (requires database persistence)"), nil
		}

		// Fetch global aggregate stats.
		stats, err := auditStore.GetGlobalStats(since)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get global stats: %s", err.Error())), nil
		}

		// Fetch per-tool metrics.
		toolMetrics, err := auditStore.GetToolMetrics(since)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get tool metrics: %s", err.Error())), nil
		}

		// Compute error rate.
		var errorRate string
		if stats.TotalCalls > 0 {
			pct := float64(stats.ErrorCount) / float64(stats.TotalCalls) * 100
			errorRate = fmt.Sprintf("%.1f%%", pct)
		} else {
			errorRate = "0.0%"
		}

		resp := &serverMetricsResponse{
			Uptime:         time.Since(serverStartTime).Truncate(time.Second).String(),
			GoVersion:      runtime.Version(),
			ToolCount:      len(GetAllTools()),
			ActiveSessions: manager.GetActiveSessionCount(),
			Period:         period,
			TotalCalls:     stats.TotalCalls,
			ErrorCount:     stats.ErrorCount,
			ErrorRate:      errorRate,
			AvgLatencyMs:   stats.AvgLatencyMs,
			TopTool:        stats.TopTool,
			TopToolCount:   stats.TopToolCount,
			ToolMetrics:    toolMetrics,
		}

		return handler.MarshalResponse(resp, "server_metrics")
	}
}
