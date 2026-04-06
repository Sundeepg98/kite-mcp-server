package mcp

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// adminCheck validates that the caller is an authenticated admin.
// Returns email on success, or an error result on failure.
func adminCheck(ctx context.Context, manager *kc.Manager) (string, *mcp.CallToolResult) {
	email := oauth.EmailFromContext(ctx)
	if email == "" {
		return "", mcp.NewToolResultError("Authentication required. Please log in first.")
	}
	if uStore := manager.UserStore(); uStore != nil {
		if !uStore.IsAdmin(email) {
			return "", mcp.NewToolResultError("Admin access required. This tool is restricted to server administrators.")
		}
	}
	return email, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 1: admin_list_users (read-only)
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
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_list_users")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		args := request.GetArguments()
		from := SafeAssertInt(args["from"], 0)
		limit := SafeAssertInt(args["limit"], 100)
		if from < 0 {
			from = 0
		}
		if limit <= 0 || limit > 500 {
			limit = 100
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError("User store not available."), nil
		}
		allUsers := uStore.List()

		// Apply pagination.
		end := from + limit
		if from > len(allUsers) {
			from = len(allUsers)
		}
		if end > len(allUsers) {
			end = len(allUsers)
		}

		entries := make([]adminUserEntry, 0, end-from)
		for _, u := range allUsers[from:end] {
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
			Total: len(allUsers),
			From:  from,
			Limit: limit,
			Users: entries,
		}, "admin_list_users")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 2: admin_get_user (read-only)
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
		targetEmail := SafeAssertString(args["target_email"], "")
		if targetEmail == "" {
			return mcp.NewToolResultError("target_email is required."), nil
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError("User store not available."), nil
		}
		user, found := uStore.Get(targetEmail)
		if !found {
			return mcp.NewToolResultError(fmt.Sprintf("User not found: %s", targetEmail)), nil
		}

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

		if rg := manager.RiskGuard(); rg != nil {
			status := rg.GetUserStatus(targetEmail)
			resp.RiskStatus = &status
			limits := rg.GetEffectiveLimits(targetEmail)
			resp.EffectiveLimits = &adminEffectiveLimits{
				MaxSingleOrderINR:   limits.MaxSingleOrderINR,
				MaxOrdersPerDay:     limits.MaxOrdersPerDay,
				MaxOrdersPerMinute:  limits.MaxOrdersPerMinute,
				DuplicateWindowSecs: limits.DuplicateWindowSecs,
				MaxDailyValueINR:    limits.MaxDailyValueINR,
			}
		}

		return handler.MarshalResponse(resp, "admin_get_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 3: admin_server_status (read-only)
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

// ─────────────────────────────────────────────────────────────────────────────
// Tool 4: admin_get_risk_status (read-only)
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
		targetEmail := SafeAssertString(args["target_email"], "")
		if targetEmail == "" {
			return mcp.NewToolResultError("target_email is required."), nil
		}

		rg := manager.RiskGuard()
		if rg == nil {
			return mcp.NewToolResultError("RiskGuard not available on this server."), nil
		}

		status := rg.GetUserStatus(targetEmail)
		limits := rg.GetEffectiveLimits(targetEmail)
		headroom := limits.MaxDailyValueINR - status.DailyPlacedValue
		if headroom < 0 {
			headroom = 0
		}

		return handler.MarshalResponse(&adminGetRiskStatusResponse{
			TargetEmail:    targetEmail,
			GloballyFrozen: rg.IsGloballyFrozen(),
			UserStatus:     status,
			EffectiveLimits: adminEffectiveLimits{
				MaxSingleOrderINR:   limits.MaxSingleOrderINR,
				MaxOrdersPerDay:     limits.MaxOrdersPerDay,
				MaxOrdersPerMinute:  limits.MaxOrdersPerMinute,
				DuplicateWindowSecs: limits.DuplicateWindowSecs,
				MaxDailyValueINR:    limits.MaxDailyValueINR,
			},
			OrderHeadroom: headroom,
		}, "admin_get_risk_status")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 5: admin_suspend_user (write, elicitation + confirm)
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

		args := request.GetArguments()
		targetEmail := SafeAssertString(args["target_email"], "")
		reason := SafeAssertString(args["reason"], "")
		confirmed := SafeAssertBool(args["confirm"], false)

		if targetEmail == "" {
			return mcp.NewToolResultError("target_email is required."), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. This action suspends the user, freezes trading, and terminates sessions."), nil
		}
		if strings.EqualFold(targetEmail, adminEmail) {
			return mcp.NewToolResultError("Cannot suspend yourself."), nil
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError("User store not available."), nil
		}

		// Last-admin guard: don't suspend the last active admin.
		target, ok := uStore.Get(targetEmail)
		if ok && target.Role == users.RoleAdmin && target.Status == users.StatusActive {
			activeAdmins := 0
			for _, u := range uStore.List() {
				if u.Role == users.RoleAdmin && u.Status == users.StatusActive {
					activeAdmins++
				}
			}
			if activeAdmins <= 1 {
				return mcp.NewToolResultError("Cannot suspend the last active admin."), nil
			}
		}

		// Elicitation confirmation.
		if srv := manager.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Suspend user %s? This will freeze trading, mark as suspended, and terminate all active sessions.", targetEmail)
			if reason != "" {
				msg += fmt.Sprintf(" Reason: %s", reason)
			}
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Suspension cancelled: %s", err.Error())), nil
			}
		}

		// Execute: Freeze → UpdateStatus → TerminateByEmail.
		if guard := manager.RiskGuard(); guard != nil {
			guard.Freeze(targetEmail, adminEmail, reason)
		}
		if err := uStore.UpdateStatus(targetEmail, users.StatusSuspended); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to suspend user: %s", err.Error())), nil
		}
		terminated := manager.SessionManager().TerminateByEmail(targetEmail)

		return handler.MarshalResponse(map[string]any{
			"status":               "suspended",
			"email":                targetEmail,
			"sessions_terminated":  terminated,
		}, "admin_suspend_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 6: admin_activate_user (write, no confirmation — restorative)
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
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_activate_user")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		args := request.GetArguments()
		targetEmail := SafeAssertString(args["target_email"], "")
		if targetEmail == "" {
			return mcp.NewToolResultError("target_email is required."), nil
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError("User store not available."), nil
		}
		if err := uStore.UpdateStatus(targetEmail, users.StatusActive); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to activate user: %s", err.Error())), nil
		}

		return handler.MarshalResponse(map[string]string{
			"status": "active",
			"email":  targetEmail,
		}, "admin_activate_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 7: admin_change_role (write, elicitation)
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

		args := request.GetArguments()
		targetEmail := SafeAssertString(args["target_email"], "")
		newRole := SafeAssertString(args["role"], "")
		if targetEmail == "" || newRole == "" {
			return mcp.NewToolResultError("target_email and role are required."), nil
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError("User store not available."), nil
		}

		// Last-admin guard.
		target, ok := uStore.Get(targetEmail)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("User not found: %s", targetEmail)), nil
		}
		if target.Role == users.RoleAdmin && newRole != users.RoleAdmin {
			activeAdmins := 0
			for _, u := range uStore.List() {
				if u.Role == users.RoleAdmin && u.Status == users.StatusActive {
					activeAdmins++
				}
			}
			if activeAdmins <= 1 {
				return mcp.NewToolResultError("Cannot demote the last active admin."), nil
			}
		}

		// Elicitation confirmation.
		if srv := manager.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Change %s role from %s to %s?", targetEmail, target.Role, newRole)
			if strings.EqualFold(targetEmail, adminEmail) {
				msg += " WARNING: You are changing your own role."
			}
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Role change cancelled: %s", err.Error())), nil
			}
		}

		if err := uStore.UpdateRole(targetEmail, newRole); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to change role: %s", err.Error())), nil
		}

		return handler.MarshalResponse(map[string]string{
			"email":     targetEmail,
			"old_role":  target.Role,
			"new_role":  newRole,
		}, "admin_change_role")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 8: admin_freeze_user (write, elicitation + confirm)
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

		args := request.GetArguments()
		targetEmail := SafeAssertString(args["target_email"], "")
		reason := SafeAssertString(args["reason"], "")
		confirmed := SafeAssertBool(args["confirm"], false)

		if targetEmail == "" || reason == "" {
			return mcp.NewToolResultError("target_email and reason are required."), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true to freeze trading."), nil
		}
		if strings.EqualFold(targetEmail, adminEmail) {
			return mcp.NewToolResultError("Cannot freeze yourself."), nil
		}

		guard := manager.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError("RiskGuard not available on this server."), nil
		}

		// Elicitation confirmation.
		if srv := manager.MCPServer(); srv != nil {
			msg := fmt.Sprintf("Freeze trading for %s? Reason: %s", targetEmail, reason)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Freeze cancelled: %s", err.Error())), nil
			}
		}

		guard.Freeze(targetEmail, adminEmail, reason)

		return handler.MarshalResponse(map[string]string{
			"status": "frozen",
			"email":  targetEmail,
			"reason": reason,
		}, "admin_freeze_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 9: admin_unfreeze_user (write, no confirmation — restorative)
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
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_unfreeze_user")
		if _, errResult := adminCheck(ctx, manager); errResult != nil {
			return errResult, nil
		}

		args := request.GetArguments()
		targetEmail := SafeAssertString(args["target_email"], "")
		if targetEmail == "" {
			return mcp.NewToolResultError("target_email is required."), nil
		}

		guard := manager.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError("RiskGuard not available on this server."), nil
		}

		guard.Unfreeze(targetEmail)

		return handler.MarshalResponse(map[string]string{
			"status": "unfrozen",
			"email":  targetEmail,
		}, "admin_unfreeze_user")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 10: admin_freeze_global (write, double elicitation + confirm)
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

		args := request.GetArguments()
		reason := SafeAssertString(args["reason"], "")
		confirmed := SafeAssertBool(args["confirm"], false)

		if reason == "" {
			return mcp.NewToolResultError("reason is required."), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. This action blocks ALL users from placing orders."), nil
		}

		guard := manager.RiskGuard()
		if guard == nil {
			return mcp.NewToolResultError("RiskGuard not available on this server."), nil
		}

		// Double elicitation: two sequential confirmations.
		if srv := manager.MCPServer(); srv != nil {
			msg1 := fmt.Sprintf("WARNING: Freeze trading for ALL users on the server? Reason: %s", reason)
			if err := requestConfirmation(ctx, srv, msg1); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Global freeze cancelled: %s", err.Error())), nil
			}
			msg2 := fmt.Sprintf("FINAL CONFIRMATION: This will block ALL users from placing orders immediately. Reason: %s", reason)
			if err := requestConfirmation(ctx, srv, msg2); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Global freeze cancelled at final confirmation: %s", err.Error())), nil
			}
		}

		guard.FreezeGlobal(adminEmail, reason)

		return handler.MarshalResponse(map[string]string{
			"status":    "global_freeze_active",
			"frozen_by": adminEmail,
			"reason":    reason,
		}, "admin_freeze_global")
	}
}
