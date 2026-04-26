package mcp

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_invite_family_member (write)
// ─────────────────────────────────────────────────────────────────────────────

type AdminInviteFamilyMemberTool struct{}

func (*AdminInviteFamilyMemberTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_invite_family_member",
		mcp.WithDescription("Invite a family member to share your billing plan. They'll inherit your Pro/Premium tier. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Invite Family Member"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("invited_email", mcp.Description("Email of the family member to invite."), mcp.Required()),
	)
}

func (*AdminInviteFamilyMemberTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_invite_family_member")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		invitedEmail := strings.ToLower(p.String("invited_email", ""))
		if invitedEmail == "" {
			return mcp.NewToolResultError("invited_email is required."), nil
		}

		bus := handler.CommandBus()
		if bus == nil {
			return mcp.NewToolResultError("command bus not available"), nil
		}
		raw, err := bus.DispatchWithResult(ctx, cqrs.AdminInviteFamilyMemberCommand{
			AdminEmail:   adminEmail,
			InvitedEmail: invitedEmail,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminInviteFamilyMemberResult)

		acceptURL := ""
		if extURL := os.Getenv("EXTERNAL_URL"); extURL != "" {
			acceptURL = extURL + "/auth/accept-invite?token=" + result.InvitationID
		}

		return handler.MarshalResponse(map[string]any{
			"status":         "invited",
			"invitation_id":  result.InvitationID,
			"invited_email":  result.InvitedEmail,
			"acceptance_url": acceptURL,
			"expires_at":     result.ExpiresAt.Format(time.RFC3339),
			"slots_used":     result.SlotsUsed,
			"slots_max":      result.SlotsMax,
		}, "admin_invite_family_member")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_list_family (read-only)
// ─────────────────────────────────────────────────────────────────────────────

type AdminListFamilyTool struct{}

func (*AdminListFamilyTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_list_family",
		mcp.WithDescription("List your family members and pending invitations. Shows who shares your billing plan. Admin-only."),
		mcp.WithTitleAnnotation("Admin: List Family"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithNumber("from", mcp.Description("Pagination offset (default: 0).")),
		mcp.WithNumber("limit", mcp.Description("Max members to return (default: 50).")),
	)
}

func (*AdminListFamilyTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_list_family")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		from := p.Int("from", 0)
		limit := p.Int("limit", 50)

		bus := handler.QueryBus()
		if bus == nil {
			return mcp.NewToolResultError("query bus not available"), nil
		}
		raw, err := bus.DispatchWithResult(ctx, cqrs.AdminListFamilyQuery{
			AdminEmail: adminEmail,
			From:       from,
			Limit:      limit,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminListFamilyResult)

		type memberEntry struct {
			Email     string `json:"email"`
			Role      string `json:"role"`
			Status    string `json:"status"`
			LastLogin string `json:"last_login,omitempty"`
		}
		entries := make([]memberEntry, 0, len(result.Members))
		for _, m := range result.Members {
			var ll string
			if !m.LastLogin.IsZero() {
				ll = m.LastLogin.Format(time.RFC3339)
			}
			entries = append(entries, memberEntry{
				Email: m.Email, Role: m.Role, Status: m.Status, LastLogin: ll,
			})
		}

		type invEntry struct {
			ID           string `json:"id"`
			InvitedEmail string `json:"invited_email"`
			Status       string `json:"status"`
			ExpiresAt    string `json:"expires_at"`
		}
		pending := make([]invEntry, 0, len(result.Pending))
		for _, inv := range result.Pending {
			pending = append(pending, invEntry{
				ID:           inv.ID,
				InvitedEmail: inv.InvitedEmail,
				Status:       inv.Status,
				ExpiresAt:    inv.ExpiresAt.Format(time.RFC3339),
			})
		}

		return handler.MarshalResponse(map[string]any{
			"admin_email":  result.AdminEmail,
			"max_users":    result.MaxUsers,
			"total":        result.Total,
			"from":         result.From,
			"limit":        result.Limit,
			"member_count": result.MemberCount,
			"members":      entries,
			"pending":      pending,
		}, "admin_list_family")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_remove_family_member (write, destructive)
// ─────────────────────────────────────────────────────────────────────────────

type AdminRemoveFamilyMemberTool struct{}

func (*AdminRemoveFamilyMemberTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_remove_family_member",
		mcp.WithDescription("Remove a family member from your billing plan. They'll lose inherited tier access. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Remove Family Member"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email", mcp.Description("Email of the family member to remove."), mcp.Required()),
		mcp.WithBoolean("confirm", mcp.Description("Must be true. Member loses tier access."), mcp.Required()),
	)
}

func (*AdminRemoveFamilyMemberTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_remove_family_member")
		adminEmail, errResult := adminCheck(ctx, manager)
		if errResult != nil {
			return errResult, nil
		}

		p := NewArgParser(request.GetArguments())
		targetEmail := strings.ToLower(p.String("target_email", ""))
		confirmed := p.Bool("confirm", false)
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. Member will lose tier access."), nil
		}

		bus := handler.CommandBus()
		if bus == nil {
			return mcp.NewToolResultError("command bus not available"), nil
		}
		raw, err := bus.DispatchWithResult(ctx, cqrs.AdminRemoveFamilyMemberCommand{
			AdminEmail:  adminEmail,
			TargetEmail: targetEmail,
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.(*usecases.AdminRemoveFamilyMemberResult)

		return handler.MarshalResponse(map[string]string{
			"status": "removed",
			"email":  result.RemovedEmail,
		}, "admin_remove_family_member")
	}
}

func init() {
	RegisterInternalTool(&AdminInviteFamilyMemberTool{})
	RegisterInternalTool(&AdminListFamilyTool{})
	RegisterInternalTool(&AdminRemoveFamilyMemberTool{})
}
