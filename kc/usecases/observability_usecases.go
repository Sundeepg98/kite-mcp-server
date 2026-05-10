package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/algo2go/kite-mcp-cqrs"
	logport "github.com/algo2go/kite-mcp-logger"
)

// Wave D Phase 3 Package 5f (Logger sweep): observability/pnl/
// pretrade/ticker/watchlist/telegram/context/saga use cases type
// their logger field as the kc/logger.Logger port; constructors
// retain *slog.Logger and convert via logport.NewSlog.

// MetricsAuditReader provides read-only query access for audit metrics
// (ISP-narrowed for observability use cases).
//
// F2 close-out (Phase B/D): renamed from usecases.AuditReader to
// disambiguate from kc.AuditReader (9-method canonical including
// per-user List/ListOrders/GetOrderAttribution/GetStats/GetToolCounts/
// VerifyChain). The usecases version surfaces only the global-metrics
// subset that ServerMetricsUseCase actually queries — narrowing keeps
// the use case's port surface to exactly what it needs.
//
// AuditWriter and AuditStore (the composite) were deleted as part of
// F2 — both were declared but never referenced as field types or
// function parameters anywhere in kc/usecases. Pure dead code from
// an earlier ISP cleanup that didn't follow through to consumers.
//
// *kc.audit.Store satisfies this narrow port structurally — see
// kc/interfaces.go:127-133 for the wider canonical's matching
// methods.
type MetricsAuditReader interface {
	GetGlobalStats(since time.Time) (*audit.Stats, error)
	GetToolMetrics(since time.Time) ([]audit.ToolMetric, error)
	GetTopErrorUsers(since time.Time, limit int) ([]audit.UserErrorCount, error)
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
	auditStore MetricsAuditReader
	logger     logport.Logger
}

// NewServerMetricsUseCase creates a ServerMetricsUseCase with dependencies injected.
func NewServerMetricsUseCase(store MetricsAuditReader, logger *slog.Logger) *ServerMetricsUseCase {
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
