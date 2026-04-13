package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/billing"
)

// admin_set_billing_tier lets an admin of a self-hosted deployment grant or
// revoke tiers without going through Stripe. Without it, the sole admin of a
// fresh deployment is gated out of ~40% of their own tools until they either
// fake a webhook event or hand-edit SQLite and restart the server (the
// in-memory Store.subs cache only loads at boot).
//
// Writes go through billing.Store.SetSubscription so the DB row AND the
// in-memory cache update atomically — no restart required.

type AdminSetBillingTierTool struct{}

func (*AdminSetBillingTierTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_set_billing_tier",
		mcp.WithDescription("Grant or revoke a billing tier for a user. Updates both the database and in-memory cache atomically. Self-hosted admin escape hatch — does NOT talk to Stripe. Admin-only."),
		mcp.WithTitleAnnotation("Admin: Set Billing Tier"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("target_email",
			mcp.Description("Email of the user whose tier to set."),
			mcp.Required(),
		),
		mcp.WithString("tier",
			mcp.Description("Target tier: free, pro, premium, solo_pro."),
			mcp.Required(),
			mcp.Enum("free", "pro", "premium", "solo_pro"),
		),
		mcp.WithNumber("max_users",
			mcp.Description("Max users on the plan (family billing). Default 1."),
		),
	)
}

func (*AdminSetBillingTierTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, adminEmail string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_set_billing_tier")

		args := request.GetArguments()
		p := NewArgParser(args)
		if err := p.Required("target_email", "tier"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		targetEmail := strings.ToLower(strings.TrimSpace(p.String("target_email", "")))
		tierStr := strings.ToLower(strings.TrimSpace(p.String("tier", "")))
		maxUsers := p.Int("max_users", 1)

		var tier billing.Tier
		switch tierStr {
		case "free":
			tier = billing.TierFree
		case "pro":
			tier = billing.TierPro
		case "premium":
			tier = billing.TierPremium
		case "solo_pro":
			tier = billing.TierSoloPro
		default:
			return mcp.NewToolResultError(fmt.Sprintf("invalid tier %q (expected free|pro|premium|solo_pro)", tierStr)), nil
		}
		if maxUsers < 1 {
			maxUsers = 1
		}

		bs := manager.BillingStore()
		if bs == nil {
			return mcp.NewToolResultError("billing store not configured"), nil
		}

		sub := &billing.Subscription{
			AdminEmail: targetEmail,
			Tier:       tier,
			Status:     billing.StatusActive,
			UpdatedAt:  time.Now().UTC(),
			MaxUsers:   maxUsers,
		}
		if err := bs.SetSubscription(sub); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("set subscription: %s", err.Error())), nil
		}

		return handler.MarshalResponse(map[string]interface{}{
			"target_email": targetEmail,
			"tier":         tierStr,
			"max_users":    maxUsers,
			"status":       "active",
			"granted_by":   adminEmail,
			"updated_at":   sub.UpdatedAt.Format(time.RFC3339),
		}, "admin_set_billing_tier")
	})
}
