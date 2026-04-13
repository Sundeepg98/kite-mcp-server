// Package telegramnotify provides a Kite MCP plugin that sends a Telegram
// DM to the family admin whenever a family member successfully executes a
// trade-affecting tool (place_order, modify_order, cancel_order, place_gtt_*,
// etc.).
//
// This is the second production consumer of the plugin framework, after
// rolegate. Where rolegate uses OnBeforeToolExecution to block, telegramnotify
// uses OnAfterToolExecution to observe and side-effect. Together they
// demonstrate both sides of the hook API.
//
// Wire via app/wire.go after the telegram bot + user store + alert store
// are all constructed:
//
//   mcp.OnAfterToolExecution(telegramnotify.Hook(telegramnotify.Deps{
//       Users:    kcManager.UserStoreConcrete(),
//       ChatIDs:  kcManager.AlertStoreConcrete(),
//       Sender:   kcManager.TelegramNotifier(),
//       Logger:   logger,
//   }))
//
// Any nil dependency disables the hook (fail-open — no side effect).
package telegramnotify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// notifyToolPrefixes is the set of tool-name prefixes whose successful
// execution triggers a family-admin DM. Intentionally narrower than
// rolegate's writeToolPrefixes — we only notify on trade-money-moving
// actions, not every write (e.g. update_my_credentials is a write but
// doesn't need an admin ping).
var notifyToolPrefixes = []string{
	"place_order",      // regular orders
	"modify_order",     // order modifications
	"cancel_order",     // cancellations
	"place_gtt_order",  // good-till-triggered
	"modify_gtt_order",
	"delete_gtt_order",
	"convert_position", // product conversion (MIS↔CNC)
	"close_position",   // explicit close
	"close_all_positions",
	"place_mf_order",   // mutual fund purchases
	"cancel_mf_order",
}

// UserLookup is the narrow interface the hook needs from UserStore.
type UserLookup interface {
	Get(email string) (*users.User, bool)
}

// ChatIDLookup resolves a user's Telegram chat ID, if they've configured one.
type ChatIDLookup interface {
	GetTelegramChatID(email string) (int64, bool)
}

// Sender abstracts the Telegram-send side so tests can inject a recorder.
// Matches the signature of *alerts.TelegramNotifier.SendMessage.
type Sender interface {
	SendMessage(chatID int64, text string) error
}

// Deps bundles the plugin dependencies. Any nil field disables the plugin
// (fail-open — same as not registering it at all).
type Deps struct {
	Users   UserLookup
	ChatIDs ChatIDLookup
	Sender  Sender
	Logger  *slog.Logger
}

// Hook returns an after-hook that notifies family admins on trade actions.
// The hook is fire-and-forget: Telegram-send errors are logged but never
// propagated (after-hooks can't cancel an already-completed tool call).
func Hook(d Deps) mcp.ToolHook {
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		if d.Users == nil || d.ChatIDs == nil || d.Sender == nil {
			return nil
		}
		if !isNotifyTool(toolName) {
			return nil
		}
		callerEmail := oauth.EmailFromContext(ctx)
		if callerEmail == "" {
			return nil
		}
		caller, ok := d.Users.Get(callerEmail)
		if !ok || !caller.IsFamilyMember() {
			// Not in our user store, or not a family member (no admin to notify)
			return nil
		}
		adminEmail := caller.AdminEmail
		if adminEmail == "" || adminEmail == callerEmail {
			// Admin themselves calling the tool — don't self-notify.
			return nil
		}
		chatID, ok := d.ChatIDs.GetTelegramChatID(adminEmail)
		if !ok {
			// Admin hasn't connected their Telegram — nothing to notify.
			return nil
		}

		text := buildMessage(caller, toolName, args)
		if err := d.Sender.SendMessage(chatID, text); err != nil {
			if d.Logger != nil {
				d.Logger.Warn("telegramnotify: send failed",
					"admin_email", adminEmail,
					"caller_email", callerEmail,
					"tool", toolName,
					"error", err,
				)
			}
		}
		return nil
	}
}

// isNotifyTool reports whether the tool name matches any notify prefix.
// Uses prefix matching so place_order, place_order_market, etc. all qualify
// without listing every variant.
func isNotifyTool(toolName string) bool {
	for _, prefix := range notifyToolPrefixes {
		if toolName == prefix || strings.HasPrefix(toolName, prefix+"_") {
			return true
		}
	}
	return false
}

// buildMessage composes the admin notification text. Kept simple — the
// point is visibility, not a full trade confirmation. MarkdownV2-escaped
// symbols (*, _, `) that might appear in symbols or args are stripped so
// the Telegram API doesn't reject the payload.
func buildMessage(caller *users.User, toolName string, args map[string]interface{}) string {
	who := caller.DisplayName
	if who == "" {
		who = caller.Email
	}
	var b strings.Builder
	// Tool names are hardcoded identifiers from our own codebase, never user
	// input, so they don't need MarkdownV2 sanitization. The display name and
	// trading symbol do — both can come from user/broker data.
	fmt.Fprintf(&b, "👪 Family member %s ran %s", sanitize(who), toolName)

	// Surface the most useful args if present. Safe lookups — the map
	// shape depends on the tool, and we never want a bad value to panic
	// the hook.
	if sym, ok := args["tradingsymbol"].(string); ok && sym != "" {
		fmt.Fprintf(&b, " on %s", sanitize(sym))
	}
	if txn, ok := args["transaction_type"].(string); ok && txn != "" {
		fmt.Fprintf(&b, " (%s)", sanitize(txn))
	}
	if qty, ok := args["quantity"].(float64); ok && qty > 0 {
		fmt.Fprintf(&b, " qty=%.0f", qty)
	}
	if px, ok := args["price"].(float64); ok && px > 0 {
		fmt.Fprintf(&b, " @ %.2f", px)
	}
	return b.String()
}

// sanitize strips characters that would break Telegram MarkdownV2 formatting
// so the send never fails on a weirdly-named symbol. Not exhaustive — just
// the ones we actually see in trading data.
func sanitize(s string) string {
	replacer := strings.NewReplacer("*", "", "_", "", "`", "", "[", "(", "]", ")")
	return replacer.Replace(s)
}
