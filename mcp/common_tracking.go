package mcp

import (
	"context"
	"fmt"
)

// trackToolCall increments the daily tool usage counter with optional context for session type
func (h *ToolHandler) trackToolCall(ctx context.Context, toolName string) {
	if h.deps.Metrics.HasMetrics() {
		sessionType := SessionTypeFromContext(ctx)
		metricName := fmt.Sprintf("tool_calls_%s_%s", toolName, sessionType)
		h.deps.Metrics.IncrementDailyMetric(metricName)
	}
}

// trackToolError increments the daily tool error counter with error type and optional context for session type
func (h *ToolHandler) trackToolError(ctx context.Context, toolName, errorType string) {
	if h.deps.Metrics.HasMetrics() {
		sessionType := SessionTypeFromContext(ctx)
		metricName := fmt.Sprintf("tool_errors_%s_%s_%s", toolName, errorType, sessionType)
		h.deps.Metrics.IncrementDailyMetric(metricName)
	}
}
