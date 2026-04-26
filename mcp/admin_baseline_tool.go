package mcp

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_get_user_baseline (read-only, admin-only)
//
// Returns a specific user's order-value baseline stats (mean, stdev, count)
// over the last 30 days, along with the computed μ+3σ anomaly-block threshold
// and the off-hours window. This is the operator forensics tool: when a user's
// order is flagged or blocked by the rolling anomaly detector, the admin can
// pull this to see exactly why (small baseline? tight stdev? history window?).
//
// Thresholds are reported alongside the raw stats so operators do not have to
// reimplement the riskguard math in their head. The soft multiplier (10× mean)
// and off-hours window are constants on the riskguard side but are surfaced
// here as plain JSON so support staff without Go access can still reason about
// the guard's behaviour.
// ─────────────────────────────────────────────────────────────────────────────

// Constants mirrored from kc/riskguard/guard.go. Keeping them local (rather
// than importing the riskguard package) avoids pulling the full guard wiring
// into a read-only reporting tool and preserves the single-responsibility of
// this file — it reads stats, it doesn't run checks. If the riskguard tunables
// change, the mirror must be updated here (there is one check: a focused unit
// test pins the numeric output shape, which will fail if the constants drift
// and the tests haven't been updated).
const (
	adminBaselineAnomalySigmaMultiplier = 3.0
	adminBaselineAnomalyMeanMultiplier  = 10.0
	adminBaselineDays                   = 30
	adminBaselineOffHoursWindowIST      = "02:00-06:00"
)

type AdminGetUserBaselineTool struct{}

func (*AdminGetUserBaselineTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_get_user_baseline",
		mcp.WithDescription(
			"Inspect a user's rolling order-value baseline (30-day mean, stdev, count) plus the computed "+
				"μ+3σ anomaly-block threshold. Use for operator forensics: explain why an order was flagged, "+
				"debug false positives, audit anomaly-detector coverage. Admin-only.",
		),
		mcp.WithTitleAnnotation("Admin: Get User Baseline"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("email",
			mcp.Description("Email of the user whose baseline stats to fetch."),
			mcp.Required(),
		),
	)
}

// adminUserBaselineThresholds surfaces the riskguard tunables so operators
// can see the exact cutoffs being applied without cross-referencing the
// source. AnomalyBlockAtINR is computed per-user as mean + 3*stdev.
type adminUserBaselineThresholds struct {
	// AnomalyBlockAtINR is the per-user μ+3σ INR cutoff. Orders at or above
	// this value, AND above 10× the mean, are rejected by riskguard.
	AnomalyBlockAtINR float64 `json:"anomaly_block_at_inr"`
	// AnomalySoftMultiplier is the multiplicative cap on top of the σ cutoff.
	AnomalySoftMultiplier float64 `json:"anomaly_soft_multiplier"`
	// OffHoursWindowIST is the [start, end) block window in IST, e.g. "02:00-06:00".
	OffHoursWindowIST string `json:"off_hours_window_ist"`
}

// adminUserBaselineResponse is the structured payload returned by the tool.
type adminUserBaselineResponse struct {
	Email             string                      `json:"email"`
	BaselineMeanINR   float64                     `json:"baseline_mean_inr"`
	BaselineStdevINR  float64                     `json:"baseline_stdev_inr"`
	BaselineCount     int                         `json:"baseline_count"`
	BaselineDays      int                         `json:"baseline_days"`
	IsSufficient      bool                        `json:"is_sufficient"`
	StatsCacheHitRate float64                     `json:"stats_cache_hit_rate"`
	Thresholds        adminUserBaselineThresholds `json:"thresholds"`
}

// minBaselineCountForSufficiency mirrors kc/audit.minBaselineOrders. Kept local
// because audit does not export the constant and we want the tool to be
// self-contained. If the audit floor changes, this value must follow.
const minBaselineCountForSufficiency = 5

func (*AdminGetUserBaselineTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, _ string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_get_user_baseline")

		args := request.GetArguments()
		email := strings.ToLower(strings.TrimSpace(NewArgParser(args).String("email", "")))
		if email == "" {
			return mcp.NewToolResultError("email is required."), nil
		}

		// Route directly through the concrete audit store because UserOrderStats
		// and StatsCacheHitRate are not part of the AuditStoreInterface surface.
		// Admin forensics tools are the one legitimate place to reach for the
		// concrete type: the underlying rolling-stats method has no meaningful
		// abstraction above it.
		auditStore := manager.AuditStoreConcrete()
		if auditStore == nil {
			return mcp.NewToolResultError("Audit store not available (requires database persistence)."), nil
		}

		mean, stdev, countF := auditStore.UserOrderStats(email, adminBaselineDays)
		count := int(countF)

		resp := adminUserBaselineResponse{
			Email:             email,
			BaselineMeanINR:   mean,
			BaselineStdevINR:  stdev,
			BaselineCount:     count,
			BaselineDays:      adminBaselineDays,
			IsSufficient:      count >= minBaselineCountForSufficiency,
			StatsCacheHitRate: auditStore.StatsCacheHitRate(),
			Thresholds: adminUserBaselineThresholds{
				AnomalyBlockAtINR:     mean + adminBaselineAnomalySigmaMultiplier*stdev,
				AnomalySoftMultiplier: adminBaselineAnomalyMeanMultiplier,
				OffHoursWindowIST:     adminBaselineOffHoursWindowIST,
			},
		}

		return handler.MarshalResponse(&resp, "admin_get_user_baseline")
	})
}

func init() { RegisterInternalTool(&AdminGetUserBaselineTool{}) }
