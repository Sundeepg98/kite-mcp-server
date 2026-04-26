package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_get_risk_status (read-only)
// ─────────────────────────────────────────────────────────────────────────────

type AdminGetRiskStatusTool struct{}

func (*AdminGetRiskStatusTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_get_risk_status",
		mcp.WithDescription("Get a user's current risk status — freeze state, daily order counts, cumulative placed value, and effective trading limits. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Get Risk Status"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to inspect."), mcp.Required()),
	)
}

type adminGetRiskStatusResponse struct {
	TargetEmail     string                `json:"target_email"`
	GloballyFrozen  bool                  `json:"globally_frozen"`
	UserStatus      riskguard.UserStatus  `json:"user_status"`
	EffectiveLimits adminEffectiveLimits  `json:"effective_limits"`
	OrderHeadroom   float64               `json:"order_headroom"`
}

func (*AdminGetRiskStatusTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_get_risk_status")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		args := request.GetArguments()
		targetEmail := NewArgParser(args).String("target_email", "")
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}

		rg := handler.deps.RiskGuard.RiskGuard()
		if rg == nil {
			return mcp.NewToolResultError(ErrRiskGuardNA), nil
		}

		raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.AdminGetRiskStatusQuery{TargetEmail: targetEmail})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminGetRiskStatusResult)

		return handler.MarshalResponse(&adminGetRiskStatusResponse{
			TargetEmail:    result.TargetEmail,
			GloballyFrozen: result.GloballyFrozen,
			UserStatus:     result.UserStatus,
			EffectiveLimits: adminEffectiveLimits{
				MaxSingleOrderINR:   result.EffectiveLimits.MaxSingleOrderINR,
				MaxOrdersPerDay:     result.EffectiveLimits.MaxOrdersPerDay,
				MaxOrdersPerMinute:  result.EffectiveLimits.MaxOrdersPerMinute,
				DuplicateWindowSecs: result.EffectiveLimits.DuplicateWindowSecs,
				MaxDailyValueINR:    result.EffectiveLimits.MaxDailyValueINR,
			},
			OrderHeadroom: result.OrderHeadroom,
		}, "admin_get_risk_status")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_freeze_user (write, elicitation + confirm)
// ─────────────────────────────────────────────────────────────────────────────

type AdminFreezeUserTool struct{}

func (*AdminFreezeUserTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_freeze_user",
		mcp.WithDescription("Freeze trading for a specific user (prevent order placement). Admin-only. Requires confirmation."),
		mcp.WithTitleAnnotation("Admin: Freeze User Trading"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to freeze."), mcp.Required()),
		mcp.WithString("reason", mcp.Description("Reason for the freeze (shown to user)."), mcp.Required()),
		mcp.WithBoolean("confirm", mcp.Description("Must be true to execute. Safety check."), mcp.Required()),
	)
}

func (*AdminFreezeUserTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_freeze_user")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		targetEmail := p.String("target_email", "")
		reason := p.String("reason", "")
		confirmed := p.Bool("confirm", false)

		if targetEmail == "" || reason == "" {
			return mcp.NewToolResultError("target_email and reason are required."), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true to freeze trading."), nil
		}
		if strings.EqualFold(targetEmail, adminEmail) {
			return mcp.NewToolResultError(ErrSelfAction), nil
		}

		guard := handler.deps.RiskGuard.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError(ErrRiskGuardNA), nil
		}

		// Elicitation confirmation (transport concern — stays in handler).
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Freeze trading for %s? Reason: %s", targetEmail, reason)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Freeze cancelled: %s", err.Error())), nil
			}
		}

		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminFreezeUserCommand{
			AdminEmail:  adminEmail,
			TargetEmail: targetEmail,
			Reason:      reason,
		}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Dispatch domain event (transport concern — stays in handler).
		if ed := handler.deps.Events.EventDispatcher(); ed != nil {
			ed.Dispatch(domain.UserFrozenEvent{
				Email:    targetEmail,
				FrozenBy: "admin",
				Reason:   reason,
				Timestamp: time.Now(),
			})
		}

		return handler.MarshalResponse(map[string]string{
			"status": "frozen",
			"email":  targetEmail,
			"reason": reason,
		}, "admin_freeze_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_unfreeze_user (write, no confirmation — restorative)
// ─────────────────────────────────────────────────────────────────────────────

type AdminUnfreezeUserTool struct{}

func (*AdminUnfreezeUserTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_unfreeze_user",
		mcp.WithDescription("Unfreeze trading for a specific user (restore order placement). Admin-only. No confirmation required (restorative action)."),
		mcp.WithTitleAnnotation("Admin: Unfreeze User Trading"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to unfreeze."), mcp.Required()),
	)
}

func (*AdminUnfreezeUserTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, _ string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_unfreeze_user")

		args := request.GetArguments()
		targetEmail := NewArgParser(args).String("target_email", "")
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}

		guard := handler.deps.RiskGuard.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError(ErrRiskGuardNA), nil
		}

		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminUnfreezeUserCommand{
			TargetEmail: targetEmail,
		}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return handler.MarshalResponse(map[string]string{
			"status": "unfrozen",
			"email":  targetEmail,
		}, "admin_unfreeze_user")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_freeze_global (write, double elicitation + confirm)
// ─────────────────────────────────────────────────────────────────────────────

type AdminFreezeGlobalTool struct{}

func (*AdminFreezeGlobalTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_freeze_global",
		mcp.WithDescription("Activate server-wide emergency trading freeze — blocks ALL users from placing orders. Admin-only. Requires double confirmation."),
		mcp.WithTitleAnnotation("Admin: Emergency Global Freeze"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("reason", mcp.Description("Reason for the global freeze (logged in audit trail)."), mcp.Required()),
		mcp.WithBoolean("confirm", mcp.Description("Must be true to execute. This blocks ALL users."), mcp.Required()),
	)
}

func (*AdminFreezeGlobalTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_freeze_global")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		// Solo Pro users (max_users=1) shouldn't use global freeze — it only
		// affects themselves. Require a Family (Pro) or Premium plan.
		if bs := handler.deps.Billing.BillingStore(); bs != nil {
			if sub := bs.GetSubscription(adminEmail); sub != nil && sub.MaxUsers <= 1 {
				return mcp.NewToolResultError("Global freeze requires a Family or Premium plan."), nil
			}
		}

		p := NewArgParser(request.GetArguments())
		reason := p.String("reason", "")
		confirmed := p.Bool("confirm", false)

		if reason == "" {
			return mcp.NewToolResultError("reason is required."), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. This action blocks ALL users from placing orders."), nil
		}

		guard := handler.deps.RiskGuard.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError(ErrRiskGuardNA), nil
		}

		// Double elicitation: two sequential confirmations.
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg1 := fmt.Sprintf("WARNING: Freeze trading for ALL users on the server? Reason: %s", reason)
			if err := requestConfirmation(ctx, srv, msg1); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Global freeze cancelled: %s", err.Error())), nil
			}
			msg2 := fmt.Sprintf("FINAL CONFIRMATION: This will block ALL users from placing orders immediately. Reason: %s", reason)
			if err := requestConfirmation(ctx, srv, msg2); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Global freeze cancelled at final confirmation: %s", err.Error())), nil
			}
		}

		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminFreezeGlobalCommand{
			AdminEmail: adminEmail,
			Reason:     reason,
		}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		if ed := handler.deps.Events.EventDispatcher(); ed != nil {
			ed.Dispatch(domain.GlobalFreezeEvent{
				By:        adminEmail,
				Reason:    reason,
				Timestamp: time.Now(),
			})
		}

		return handler.MarshalResponse(map[string]string{
			"status":    "global_freeze_active",
			"frozen_by": adminEmail,
			"reason":    reason,
		}, "admin_freeze_global")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_unfreeze_global (write, no confirmation — restorative)
// ─────────────────────────────────────────────────────────────────────────────

type AdminUnfreezeGlobalTool struct{}

func (*AdminUnfreezeGlobalTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_unfreeze_global",
		mcp.WithDescription("Lift the server-wide trading freeze. Restores order placement for all users. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Lift Global Freeze"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

func (*AdminUnfreezeGlobalTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_unfreeze_global")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}
		guard := handler.deps.RiskGuard.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError(ErrRiskGuardNA), nil
		}
		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminUnfreezeGlobalCommand{}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return handler.MarshalResponse(map[string]string{
			"status": "global_freeze_lifted",
		}, "admin_unfreeze_global")
	}
}

func init() {
	RegisterInternalTool(&AdminFreezeGlobalTool{})
	RegisterInternalTool(&AdminFreezeUserTool{})
	RegisterInternalTool(&AdminGetRiskStatusTool{})
	RegisterInternalTool(&AdminUnfreezeGlobalTool{})
	RegisterInternalTool(&AdminUnfreezeUserTool{})
}
