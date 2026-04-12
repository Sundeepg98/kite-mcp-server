package mcp

import (
	"context"
	"runtime"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_server_status (read-only)
// ─────────────────────────────────────────────────────────────────────────────

type AdminServerStatusTool struct{}

func (*AdminServerStatusTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_server_status",
		mcp.WithDescription("Get server health overview — global freeze status, active sessions, user count, uptime, and memory usage. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Server Status"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

type adminServerStatusResponse struct {
	GlobalFreeze   riskguard.GlobalFreezeStatus `json:"global_freeze"`
	ActiveSessions int                          `json:"active_sessions"`
	TotalUsers     int                          `json:"total_users"`
	Uptime         string                       `json:"uptime"`
	GoVersion      string                       `json:"go_version"`
	HeapAllocMB    float64                      `json:"heap_alloc_mb"`
	Goroutines     int                          `json:"goroutines"`
	GCPauseMs      float64                      `json:"gc_pause_ms"`
}

func (*AdminServerStatusTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_server_status")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		resp := &adminServerStatusResponse{
			ActiveSessions: manager.GetActiveSessionCount(),
			Uptime:         time.Since(serverStartTime).Truncate(time.Second).String(),
			GoVersion:      runtime.Version(),
			Goroutines:     runtime.NumGoroutine(),
		}

		if uStore := manager.UserStore(); uStore != nil {
			resp.TotalUsers = uStore.Count()
		}
		if rg := manager.RiskGuard(); rg != nil {
			resp.GlobalFreeze = rg.GetGlobalFreezeStatus()
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		resp.HeapAllocMB = float64(memStats.HeapAlloc) / 1024 / 1024
		if memStats.NumGC > 0 {
			resp.GCPauseMs = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6
		}

		return handler.MarshalResponse(resp, "admin_server_status")
	}
}
