package common

import (
	"context"
	"fmt"
)

// trackToolCall is the lowercase alias preserved for in-package callers
// in handler_methods.go and handler_response.go that were written before
// the PR 1.1 capitalisation. New code outside this package should call
// h.TrackToolCall directly.
func (h *ToolHandler) trackToolCall(ctx context.Context, toolName string) {
	h.TrackToolCall(ctx, toolName)
}

// trackToolError is the lowercase alias preserved for in-package callers.
// New code outside this package should call h.TrackToolError directly.
func (h *ToolHandler) trackToolError(ctx context.Context, toolName, errorType string) {
	h.TrackToolError(ctx, toolName, errorType)
}

// TrackToolCall increments the daily tool usage counter with optional context for session type.
//
// Anchor 1 PR 1.1: capitalised from `trackToolCall` so cross-package
// (mcp/, mcp/admin/, etc.) callers can invoke it. Internal common
// callers continue to use the lowercase alias `trackToolCall` declared
// below for source-code stability inside this package.
func (h *ToolHandler) TrackToolCall(ctx context.Context, toolName string) {
	if h.Deps.Metrics.HasMetrics() {
		sessionType := SessionTypeFromContext(ctx)
		metricName := fmt.Sprintf("tool_calls_%s_%s", toolName, sessionType)
		h.Deps.Metrics.IncrementDailyMetric(metricName)
	}
}

// TrackToolError increments the daily tool error counter with error type and optional context for session type.
//
// Anchor 1 PR 1.1: capitalised from `trackToolError`.
func (h *ToolHandler) TrackToolError(ctx context.Context, toolName, errorType string) {
	if h.Deps.Metrics.HasMetrics() {
		sessionType := SessionTypeFromContext(ctx)
		metricName := fmt.Sprintf("tool_errors_%s_%s_%s", toolName, errorType, sessionType)
		h.Deps.Metrics.IncrementDailyMetric(metricName)
	}
}
