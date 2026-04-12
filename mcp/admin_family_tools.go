package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/users"
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
		if strings.EqualFold(invitedEmail, adminEmail) {
			return mcp.NewToolResultError(ErrSelfAction), nil
		}

		// Check max_users
		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}
		currentFamily := uStore.ListByAdminEmail(adminEmail)

		bs := manager.BillingStore()
		maxUsers := 1
		if bs != nil {
			if sub := bs.GetSubscription(adminEmail); sub != nil {
				maxUsers = sub.MaxUsers
				if maxUsers < 1 {
					maxUsers = 1
				}
			}
		}
		if len(currentFamily) >= maxUsers {
			return mcp.NewToolResultError(fmt.Sprintf("You already have %d family members (max %d for your plan). Upgrade or remove someone first.", len(currentFamily), maxUsers)), nil
		}

		// Check if already linked
		for _, u := range currentFamily {
			if strings.EqualFold(u.Email, invitedEmail) {
				return mcp.NewToolResultError(fmt.Sprintf("%s is already in your family.", invitedEmail)), nil
			}
		}

		// Create invitation
		invStore := manager.InvitationStore()
		if invStore == nil {
			return mcp.NewToolResultError(ErrInvitationStoreNA), nil
		}

		invID := fmt.Sprintf("inv_%d", time.Now().UnixNano())
		inv := &users.FamilyInvitation{
			ID:           invID,
			AdminEmail:   adminEmail,
			InvitedEmail: invitedEmail,
			Status:       "pending",
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		}
		if err := invStore.Create(inv); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create invitation: %s", err.Error())), nil
		}

		if ed := manager.EventDispatcher(); ed != nil {
			ed.Dispatch(domain.FamilyInvitedEvent{
				AdminEmail:   adminEmail,
				InvitedEmail: invitedEmail,
				Timestamp:    time.Now(),
			})
		}

		acceptURL := ""
		if extURL := os.Getenv("EXTERNAL_URL"); extURL != "" {
			acceptURL = extURL + "/auth/accept-invite?token=" + invID
		}

		return handler.MarshalResponse(map[string]any{
			"status":         "invited",
			"invitation_id":  invID,
			"invited_email":  invitedEmail,
			"acceptance_url": acceptURL,
			"expires_at":     inv.ExpiresAt.Format(time.RFC3339),
			"slots_used":     len(currentFamily) + 1,
			"slots_max":      maxUsers,
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

		args := request.GetArguments()
		p := NewArgParser(args)
		from := p.Int("from", 0)
		limit := p.Int("limit", 50)
		if from < 0 {
			from = 0
		}
		if limit <= 0 || limit > 500 {
			limit = 50
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		members := uStore.ListByAdminEmail(adminEmail)

		type memberEntry struct {
			Email     string `json:"email"`
			Role      string `json:"role"`
			Status    string `json:"status"`
			LastLogin string `json:"last_login,omitempty"`
		}
		entries := make([]memberEntry, 0, len(members))
		for _, u := range members {
			var ll string
			if !u.LastLogin.IsZero() {
				ll = u.LastLogin.Format(time.RFC3339)
			}
			entries = append(entries, memberEntry{
				Email: u.Email, Role: u.Role, Status: u.Status, LastLogin: ll,
			})
		}

		// Apply pagination to members.
		total := len(entries)
		end := from + limit
		if from > total {
			from = total
		}
		if end > total {
			end = total
		}
		entries = entries[from:end]

		// Pending invitations
		type invEntry struct {
			ID           string `json:"id"`
			InvitedEmail string `json:"invited_email"`
			Status       string `json:"status"`
			ExpiresAt    string `json:"expires_at"`
		}
		var pending []invEntry
		if invStore := manager.InvitationStore(); invStore != nil {
			for _, inv := range invStore.ListByAdmin(adminEmail) {
				if inv.Status == "pending" && time.Now().Before(inv.ExpiresAt) {
					pending = append(pending, invEntry{
						ID: inv.ID, InvitedEmail: inv.InvitedEmail,
						Status: inv.Status, ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
					})
				}
			}
		}

		maxUsers := 1
		if bs := manager.BillingStore(); bs != nil {
			if sub := bs.GetSubscription(adminEmail); sub != nil {
				maxUsers = sub.MaxUsers
			}
		}

		return handler.MarshalResponse(map[string]any{
			"admin_email":  adminEmail,
			"max_users":    maxUsers,
			"total":        total,
			"from":         from,
			"limit":        limit,
			"member_count": len(entries),
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

		args := request.GetArguments()
		p := NewArgParser(args)
		targetEmail := strings.ToLower(p.String("target_email", ""))
		confirmed := p.Bool("confirm", false)
		if targetEmail == "" {
			return mcp.NewToolResultError(ErrTargetEmailRequired), nil
		}
		if !confirmed {
			return mcp.NewToolResultError("confirm must be true. Member will lose tier access."), nil
		}
		if strings.EqualFold(targetEmail, adminEmail) {
			return mcp.NewToolResultError(ErrSelfAction), nil
		}

		uStore := manager.UserStore()
		if uStore == nil {
			return mcp.NewToolResultError(ErrUserStoreNA), nil
		}

		u, ok := uStore.Get(targetEmail)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("User not found: %s", targetEmail)), nil
		}
		if !strings.EqualFold(u.AdminEmail, adminEmail) {
			return mcp.NewToolResultError(fmt.Sprintf("%s is not in your family.", targetEmail)), nil
		}

		if err := uStore.SetAdminEmail(targetEmail, ""); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to remove: %s", err.Error())), nil
		}

		return handler.MarshalResponse(map[string]string{
			"status": "removed",
			"email":  targetEmail,
		}, "admin_remove_family_member")
	}
}
