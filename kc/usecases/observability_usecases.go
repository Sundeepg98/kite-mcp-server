package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Wave D Phase 3 Package 5f (Logger sweep): observability/pnl/
// pretrade/ticker/watchlist/telegram/context/saga use cases type
// their logger field as the kc/logger.Logger port; constructors
// retain *slog.Logger and convert via logport.NewSlog.

// AuditReader provides read-only query access for audit records (ISP-narrowed).
type AuditReader interface {
	GetGlobalStats(since time.Time) (*audit.Stats, error)
	GetToolMetrics(since time.Time) ([]audit.ToolMetric, error)
	GetTopErrorUsers(since time.Time, limit int) ([]audit.UserErrorCount, error)
}

// AuditWriter provides audit record write operations (ISP-narrowed).
// Retained here so use cases which write can depend on a narrow contract.
type AuditWriter interface {
	Enqueue(entry *audit.ToolCall)
	Record(entry *audit.ToolCall) error
}

// AuditStore is the composite interface; prefer AuditReader / AuditWriter directly.
type AuditStore interface {
	AuditReader
	AuditWriter
}

// ServerMetricsResult holds the structured result of a server metrics query.
type ServerMetricsResult struct {
	Period       string             `json:"period"`
	Stats        *audit.Stats `json:"stats"`
	ToolMetrics  []audit.ToolMetric `json:"tool_metrics"`
	TopErrorUsers []audit.UserErrorCount `json:"top_error_users,omitempty"`
}

// --- Server Metrics ---

// ServerMetricsUseCase retrieves server observability metrics.
type ServerMetricsUseCase struct {
	auditStore AuditReader
	logger     logport.Logger
}

// NewServerMetricsUseCase creates a ServerMetricsUseCase with dependencies injected.
func NewServerMetricsUseCase(store AuditReader, logger *slog.Logger) *ServerMetricsUseCase {
	return &ServerMetricsUseCase{auditStore: store, logger: logport.NewSlog(logger)}
}

// Execute retrieves server metrics for the given period.
func (uc *ServerMetricsUseCase) Execute(ctx context.Context, query cqrs.ServerMetricsQuery) (*ServerMetricsResult, error) {
	if query.AdminEmail == "" {
		return nil, fmt.Errorf("usecases: admin_email is required")
	}

	period := query.Period
	if period == "" {
		period = "24h"
	}

	now := time.Now()
	var since time.Time
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

	stats, err := uc.auditStore.GetGlobalStats(since)
	if err != nil {
		uc.logger.Error(ctx, "Failed to get global stats", err)
		return nil, fmt.Errorf("usecases: get global stats: %w", err)
	}

	toolMetrics, err := uc.auditStore.GetToolMetrics(since)
	if err != nil {
		uc.logger.Error(ctx, "Failed to get tool metrics", err)
		return nil, fmt.Errorf("usecases: get tool metrics: %w", err)
	}

	topErrorUsers, _ := uc.auditStore.GetTopErrorUsers(since, 5)

	return &ServerMetricsResult{
		Period:        period,
		Stats:         stats,
		ToolMetrics:   toolMetrics,
		TopErrorUsers: topErrorUsers,
	}, nil
}
