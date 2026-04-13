// Package rolegate provides a Kite MCP plugin that enforces per-user
// role-based tool access. It closes a real gap in family mode: today
// nothing prevents a viewer-role family member from calling write tools
// like place_order, modify_order, or cancel_order. Riskguard only checks
// order params; billing only checks tier. Neither knows about roles.
//
// This plugin is the first production consumer of mcp.OnBeforeToolExecution.
// It registers a single before-hook that:
//  1. Pulls the caller's email from the request context (via oauth.EmailFromContext)
//  2. Looks up the user in the UserStore (family-aware)
//  3. If the user's role is Viewer, blocks any tool whose name matches a
//     write pattern (place_*, modify_*, cancel_*, delete_*, toggle_*, freeze_*,
//     unfreeze_*, exit_*, reset_*)
//  4. Otherwise lets the call through to the next middleware
//
// Wire this via `mcp.OnBeforeToolExecution(rolegate.Hook(userStore))`.
// See app/wire.go.
package rolegate

import (
	"context"
	"fmt"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// writeToolPrefixes is the set of tool-name prefixes that mutate state or
// place trades. Viewers are blocked from any tool whose name starts with
// one of these. Read tools (get_*, list_*, search_*) pass through.
var writeToolPrefixes = []string{
	"place_",      // place_order, place_gtt_order, place_mf_order, place_native_alert
	"modify_",     // modify_order, modify_gtt_order, modify_trailing_stop, modify_native_alert, modify_mf_sip
	"cancel_",     // cancel_order, cancel_trailing_stop, cancel_mf_order, cancel_mf_sip
	"delete_",     // delete_gtt_order, delete_alert, delete_native_alert, delete_my_account
	"toggle_",     // toggle_paper_trading
	"freeze_",     // freeze user tools (admin-only but viewers shouldn't even try)
	"unfreeze_",
	"reset_",      // reset_paper_trading, reset_daily_count
	"convert_",    // convert_position
	"exit_",       // exit_position, exit_all_positions if any
	"set_",        // set_trailing_stop, setup_telegram, etc.
	"setup_",
	"create_",     // create_alert, create_watchlist
	"add_",        // add_to_watchlist
	"remove_",     // remove_from_watchlist
	"close_",      // close_position, close_all_positions
	"update_",     // update_my_credentials
	"start_",      // start_ticker
	"stop_",       // stop_ticker
	"subscribe_",  // subscribe_instruments
	"unsubscribe_",
	"admin_",      // all admin_* tools (suspend, activate, change_role, etc.)
}

// UserLookup is the narrow interface the hook needs from UserStore.
// Matches *users.Store structurally but kept narrow so the plugin can be
// tested with a fake.
type UserLookup interface {
	Get(email string) (*users.User, bool)
}

// Hook returns a before-hook that enforces role-gated tool access.
// Pass the concrete user store from the Manager. A nil lookup disables
// enforcement (fail-open — same as having no plugin registered at all).
func Hook(lookup UserLookup) mcp.ToolHook {
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		if lookup == nil {
			return nil
		}
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			// No session context — middleware runs before auth for some paths.
			// Let it through; if auth is required, later middleware will reject.
			return nil
		}
		u, ok := lookup.Get(email)
		if !ok {
			// Unknown user — let it through. Auth middleware handles unknowns.
			return nil
		}
		if u.Role != users.RoleViewer {
			return nil
		}
		// Viewer role: block writes.
		if isWriteTool(toolName) {
			return fmt.Errorf("rolegate: viewer role cannot call write tool %q (ask your family admin to change your role)", toolName)
		}
		return nil
	}
}

// isWriteTool reports whether toolName matches any of the write-tool
// prefixes. Exported-through-unexported for easier testing if needed.
func isWriteTool(toolName string) bool {
	for _, prefix := range writeToolPrefixes {
		if strings.HasPrefix(toolName, prefix) {
			return true
		}
	}
	return false
}
