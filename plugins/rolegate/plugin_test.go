package rolegate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// fakeLookup implements UserLookup for tests without touching the real SQLite-backed store.
type fakeLookup struct {
	byEmail map[string]*users.User
}

func (f *fakeLookup) Get(email string) (*users.User, bool) {
	u, ok := f.byEmail[email]
	return u, ok
}

func makeUser(email, role string) *users.User {
	return &users.User{
		Email:  email,
		Role:   role,
		Status: users.StatusActive,
	}
}

func TestRolegate_ViewerBlocksWriteTool(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{byEmail: map[string]*users.User{
		"viewer@family.test": makeUser("viewer@family.test", users.RoleViewer),
	}}
	hook := Hook(lookup)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@family.test")

	cases := []string{
		"place_order",
		"modify_order",
		"cancel_order",
		"place_gtt_order",
		"delete_my_account",
		"close_position",
		"toggle_paper_trading",
		"admin_suspend_user",
	}
	for _, tool := range cases {
		t.Run(tool, func(t *testing.T) {
			err := hook(ctx, tool, nil)
			require.Error(t, err, "viewer must be blocked from %s", tool)
			assert.Contains(t, err.Error(), "viewer role")
			assert.Contains(t, err.Error(), tool)
		})
	}
}

func TestRolegate_ViewerAllowsReadTool(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{byEmail: map[string]*users.User{
		"viewer@family.test": makeUser("viewer@family.test", users.RoleViewer),
	}}
	hook := Hook(lookup)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@family.test")

	cases := []string{
		"get_holdings",
		"get_positions",
		"get_orders",
		"list_alerts",
		"get_profile",
		"server_metrics",
		"get_ltp",
	}
	for _, tool := range cases {
		t.Run(tool, func(t *testing.T) {
			err := hook(ctx, tool, nil)
			assert.NoError(t, err, "viewer must be allowed to call %s", tool)
		})
	}
}

func TestRolegate_TraderPassesThroughWriteTool(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{byEmail: map[string]*users.User{
		"trader@family.test": makeUser("trader@family.test", users.RoleTrader),
	}}
	hook := Hook(lookup)
	ctx := oauth.ContextWithEmail(context.Background(), "trader@family.test")

	err := hook(ctx, "place_order", nil)
	assert.NoError(t, err, "trader role must not be blocked on write tools")
}

func TestRolegate_AdminPassesThroughWriteTool(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{byEmail: map[string]*users.User{
		"admin@family.test": makeUser("admin@family.test", users.RoleAdmin),
	}}
	hook := Hook(lookup)
	ctx := oauth.ContextWithEmail(context.Background(), "admin@family.test")

	err := hook(ctx, "admin_freeze_user", nil)
	assert.NoError(t, err, "admin role must pass through")
}

func TestRolegate_UnknownUserFailsOpen(t *testing.T) {
	t.Parallel()
	// Unknown user — lookup returns (nil, false). Hook must fail-open so
	// legitimate first-time auth flows don't break. Downstream auth
	// middleware handles rejection of unknowns.
	lookup := &fakeLookup{byEmail: map[string]*users.User{}}
	hook := Hook(lookup)
	ctx := oauth.ContextWithEmail(context.Background(), "stranger@example.com")

	err := hook(ctx, "place_order", nil)
	assert.NoError(t, err)
}

func TestRolegate_NoEmailInContextFailsOpen(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{byEmail: map[string]*users.User{}}
	hook := Hook(lookup)
	// No email in ctx — hook should pass through so auth middleware can
	// reject the request properly instead of a misleading rolegate error.
	err := hook(context.Background(), "place_order", nil)
	assert.NoError(t, err)
}

func TestRolegate_NilLookupFailsOpen(t *testing.T) {
	t.Parallel()
	hook := Hook(nil)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@family.test")
	err := hook(ctx, "place_order", nil)
	assert.NoError(t, err, "nil lookup must disable enforcement (fail-open)")
}

func TestIsWriteTool(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"place_order":          true,
		"modify_order":         true,
		"cancel_order":         true,
		"delete_my_account":    true,
		"toggle_paper_trading": true,
		"admin_suspend_user":   true,
		"create_alert":         true,
		"close_position":       true,
		"start_ticker":         true,
		"stop_ticker":          true,

		// reads
		"get_holdings":   false,
		"get_positions":  false,
		"list_alerts":    false,
		"search_instruments": false,
		"server_metrics": false,
	}
	for tool, want := range cases {
		t.Run(tool, func(t *testing.T) {
			assert.Equal(t, want, isWriteTool(tool))
		})
	}
}

// ensure we don't accidentally use errors unused
var _ = errors.New
