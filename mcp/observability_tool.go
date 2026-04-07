package mcp

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
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

	// Runtime metrics
	HeapAllocMB float64 `json:"heap_alloc_mb"`
	Goroutines  int     `json:"goroutines"`
	GCPauseMs   float64 `json:"gc_pause_ms"`
	DBSizeMB    float64 `json:"db_size_mb"`

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

	// Per-user error breakdown (top 5 users with most errors)
	TopErrorUsers []UserErrorCount `json:"top_error_users,omitempty"`
}

// UserErrorCount holds a per-user error count for the metrics response.
type UserErrorCount struct {
	Email      string `json:"email"`
	ErrorCount int    `json:"error_count"`
}

// serverStartTime is set once at package init to track uptime.
var serverStartTime = time.Now()

func (*ServerMetricsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "server_metrics")

		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		// Parse period.
		args := request.GetArguments()
		period := NewArgParser(args).String("period", "24h")
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

		// Runtime metrics: memory, goroutines, GC pause.
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		heapAllocMB := float64(memStats.HeapAlloc) / 1024 / 1024
		goroutines := runtime.NumGoroutine()
		var gcPauseMs float64
		if memStats.NumGC > 0 {
			// Last GC pause in milliseconds.
			gcPauseMs = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6
		}

		// SQLite DB file size.
		var dbSizeMB float64
		if dbPath := os.Getenv("ALERT_DB_PATH"); dbPath != "" {
			if info, err := os.Stat(dbPath); err == nil { // #nosec G703 — server-side config, not user input
				dbSizeMB = float64(info.Size()) / 1024 / 1024
			}
		}

		// Per-user error breakdown (top 5).
		topErrorUsers, _ := auditStore.GetTopErrorUsers(since, 5)
		var userErrors []UserErrorCount
		for _, ue := range topErrorUsers {
			userErrors = append(userErrors, UserErrorCount{Email: ue.Email, ErrorCount: ue.ErrorCount})
		}

		resp := &serverMetricsResponse{
			Uptime:         time.Since(serverStartTime).Truncate(time.Second).String(),
			GoVersion:      runtime.Version(),
			ToolCount:      len(GetAllTools()),
			HeapAllocMB:    heapAllocMB,
			Goroutines:     goroutines,
			GCPauseMs:      gcPauseMs,
			DBSizeMB:       dbSizeMB,
			ActiveSessions: manager.GetActiveSessionCount(),
			Period:         period,
			TotalCalls:     stats.TotalCalls,
			ErrorCount:     stats.ErrorCount,
			ErrorRate:      errorRate,
			AvgLatencyMs:   stats.AvgLatencyMs,
			TopTool:        stats.TopTool,
			TopToolCount:   stats.TopToolCount,
			ToolMetrics:    toolMetrics,
			TopErrorUsers:  userErrors,
		}

		return handler.MarshalResponse(resp, "server_metrics")
	}
}
