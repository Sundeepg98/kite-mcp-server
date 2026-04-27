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
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_list_users (read-only)
// ─────────────────────────────────────────────────────────────────────────────

type AdminListUsersTool struct{}

func (*AdminListUsersTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_list_users",
		mcp.WithDescription("List all registered users with email, role, status, and last login. Admin-only."),
		mcp.WithTitleAnnotation("Admin: List Users"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithNumber("from", mcp.Description("Pagination offset (default: 0).")),
		mcp.WithNumber("limit", mcp.Description("Maximum users to return (default: 100, max: 500).")),
	)
}

type adminListUsersResponse struct {
	Total int              `json:"total"`
	From  int              `json:"from"`
	Limit int              `json:"limit"`
	Users []adminUserEntry `json:"users"`
}

type adminUserEntry struct {
	Email       string `json:"email"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	LastLogin   string `json:"last_login,omitempty"`
	OnboardedBy string `json:"onboarded_by"`
}

func (*AdminListUsersTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, adminEmail string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_list_users")

		args := request.GetArguments()
		p := NewArgParser(args)
		from := p.Int("from", 0)
		limit := p.Int("limit", 100)

		uStore := handler.deps.Users.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.AdminListUsersQuery{AdminEmail: adminEmail, From: from, Limit: limit})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminListUsersResult)

		entries := make([]adminUserEntry, 0, len(result.Users))
		for _, u := range result.Users {
			var lastLogin string
			if !u.LastLogin.IsZero() {
				lastLogin = u.LastLogin.Format(time.RFC3339)
			}
			entries = append(entries, adminUserEntry{
				Email:       u.Email,
				Role:        u.Role,
				Status:      u.Status,
				CreatedAt:   u.CreatedAt.Format(time.RFC3339),
				LastLogin:   lastLogin,
				OnboardedBy: u.OnboardedBy,
			})
		}

		return handler.MarshalResponse(&adminListUsersResponse{
			Total: result.Total,
			From:  result.From,
			Limit: result.Limit,
			Users: entries,
		}, "admin_list_users")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_get_user (read-only)
// ─────────────────────────────────────────────────────────────────────────────

type AdminGetUserTool struct{}

func (*AdminGetUserTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_get_user",
		mcp.WithDescription("Get detailed user profile including risk status, freeze state, daily order counts, and effective limits. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Get User Details"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to look up."), mcp.Required()),
	)
}

type adminGetUserResponse struct {
	Email       string `json:"email"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	LastLogin   string `json:"last_login,omitempty"`
	OnboardedBy string `json:"onboarded_by"`

	RiskStatus      *riskguard.UserStatus  `json:"risk_status,omitempty"`
	EffectiveLimits *adminEffectiveLimits  `json:"effective_limits,omitempty"`
}

type adminEffectiveLimits struct {
	MaxSingleOrderINR   float64 `json:"max_single_order_inr"`
	MaxOrdersPerDay     int     `json:"max_orders_per_day"`
	MaxOrdersPerMinute  int     `json:"max_orders_per_minute"`
	DuplicateWindowSecs int     `json:"duplicate_window_secs"`
	MaxDailyValueINR    float64 `json:"max_daily_value_inr"`
}

func (*AdminGetUserTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_get_user")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		args := request.GetArguments()
		targetEmail := NewArgParser(args).String("target_email", "")
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}

		uStore := handler.deps.Users.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.AdminGetUserQuery{TargetEmail: targetEmail})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminGetUserResult)

		user := result.User
		var lastLogin string
		if !user.LastLogin.IsZero() {
			lastLogin = user.LastLogin.Format(time.RFC3339)
		}
		resp := &adminGetUserResponse{
			Email:       user.Email,
			Role:        user.Role,
			Status:      user.Status,
			CreatedAt:   user.CreatedAt.Format(time.RFC3339),
			LastLogin:   lastLogin,
			OnboardedBy: user.OnboardedBy,
		}

		if result.RiskStatus != nil {
			resp.RiskStatus = result.RiskStatus
		}
		if result.EffectiveLimits != nil {
			resp.EffectiveLimits = &adminEffectiveLimits{
				MaxSingleOrderINR:   result.EffectiveLimits.MaxSingleOrderINR.Float64(),
				MaxOrdersPerDay:     result.EffectiveLimits.MaxOrdersPerDay,
				MaxOrdersPerMinute:  result.EffectiveLimits.MaxOrdersPerMinute,
				DuplicateWindowSecs: result.EffectiveLimits.DuplicateWindowSecs,
				MaxDailyValueINR:    result.EffectiveLimits.MaxDailyValueINR.Float64(),
			}
		}

		return handler.MarshalResponse(resp, "admin_get_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_suspend_user (write, elicitation + confirm)
// ─────────────────────────────────────────────────────────────────────────────

type AdminSuspendUserTool struct{}

func (*AdminSuspendUserTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_suspend_user",
		mcp.WithDescription("Suspend a user account: freeze trading, update status to suspended, terminate all sessions. Admin-only. Requires confirmation."),
		mcp.WithTitleAnnotation("Admin: Suspend User"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to suspend."), mcp.Required()),
		mcp.WithString("reason", mcp.Description("Reason for suspension (stored in audit trail).")),
		mcp.WithBoolean("confirm", mcp.Description("Must be true to execute. Safety check."), mcp.Required()),
	)
}

func (*AdminSuspendUserTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_suspend_user")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		targetEmail := p.String("target_email", "")
		reason := p.String("reason", "")
		confirmed := p.Bool("confirm", false)

		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. This action suspends the user, freezes trading, and terminates sessions."), nil
		}
		if strings.EqualFold(targetEmail, adminEmail) {
			return mcp.NewToolResultError(ErrSelfAction), nil
		}

		uStore := handler.deps.Users.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		// Elicitation confirmation (transport concern — stays in handler).
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Suspend user %s? This will freeze trading, mark as suspended, and terminate all active sessions.", targetEmail)
			if reason != "" {
				msg += fmt.Sprintf(" Reason: %s", reason)
			}
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Suspension cancelled: %s", err.Error())), nil
			}
		}

		raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminSuspendUserCommand{
			AdminEmail:  adminEmail,
			TargetEmail: targetEmail,
			Reason:      reason,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminSuspendUserResult)

		return handler.MarshalResponse(map[string]any{
			"status":               result.Status,
			"email":                result.Email,
			"sessions_terminated":  result.SessionsTerminated,
		}, "admin_suspend_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_activate_user (write, no confirmation — restorative)
// ─────────────────────────────────────────────────────────────────────────────

type AdminActivateUserTool struct{}

func (*AdminActivateUserTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_activate_user",
		mcp.WithDescription("Reactivate a suspended or offboarded user account. Admin-only. No confirmation required (restorative action)."),
		mcp.WithTitleAnnotation("Admin: Activate User"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user to activate."), mcp.Required()),
	)
}

func (*AdminActivateUserTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, _ string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_activate_user")

		args := request.GetArguments()
		targetEmail := NewArgParser(args).String("target_email", "")
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}

		uStore := handler.deps.Users.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminActivateUserCommand{
			TargetEmail: targetEmail,
		}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return handler.MarshalResponse(map[string]string{
			"status": "active",
			"email":  targetEmail,
		}, "admin_activate_user")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_change_role (write, elicitation)
// ─────────────────────────────────────────────────────────────────────────────

type AdminChangeRoleTool struct{}

func (*AdminChangeRoleTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_change_role",
		mcp.WithDescription("Change a user's role (admin/trader/viewer). Prevents demoting the last active admin. Admin-only. Requires confirmation."),
		mcp.WithTitleAnnotation("Admin: Change User Role"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the user whose role to change."), mcp.Required()),
		mcp.WithString("role", mcp.Description("New role."), mcp.Enum("admin", "trader", "viewer"), mcp.Required()),
	)
}

func (*AdminChangeRoleTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_change_role")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		targetEmail := p.String("target_email", "")
		newRole := p.String("role", "")
		if targetEmail == "" || newRole == "" {
			return mcp.NewToolResultError("target_email and role are required."), nil
		}

		uStore := handler.deps.Users.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		// Fetch current role for elicitation message.
		target, ok := uStore.Get(targetEmail)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("User not found: %s", targetEmail)), nil
		}

		// Elicitation confirmation (transport concern — stays in handler).
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Change %s role from %s to %s?", targetEmail, target.Role, newRole)
			if strings.EqualFold(targetEmail, adminEmail) {
				msg += " WARNING: You are changing your own role."
			}
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Role change cancelled: %s", err.Error())), nil
			}
		}

		raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.AdminChangeRoleCommand{
			TargetEmail: targetEmail,
			NewRole:     newRole,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminChangeRoleResult)

		return handler.MarshalResponse(map[string]string{
			"email":     result.Email,
			"old_role":  result.OldRole,
			"new_role":  result.NewRole,
		}, "admin_change_role")
	}
}

func init() {
	RegisterInternalTool(&AdminActivateUserTool{})
	RegisterInternalTool(&AdminChangeRoleTool{})
	RegisterInternalTool(&AdminGetUserTool{})
	RegisterInternalTool(&AdminListUsersTool{})
	RegisterInternalTool(&AdminSuspendUserTool{})
}
