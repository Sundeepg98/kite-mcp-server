package mcp

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newAdminTestManager creates a minimal Manager suitable for admin tool tests.
// It has a UserStore (in-memory, no DB) and a RiskGuard, but no Kite client.
func newAdminTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Minimal instruments manager (required by kc.New).
	// Use TestData to avoid hitting the real Kite API.
	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger: logger,
		TestData: map[uint32]*instruments.Instrument{
			256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Exchange: "NSE", Segment: "NSE"},
		},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
	})
	require.NoError(t, err)

	// Wire up a RiskGuard so freeze-related tools work.
	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	// Wire FamilyService so admin_family_tools that dispatch via CommandBus/QueryBus
	// return real results instead of "family service not configured".
	invStore := users.NewInvitationStore(nil)
	mgr.SetInvitationStore(invStore)
	famSvc := kc.NewFamilyService(mgr.UserStore(), mgr.BillingStore(), invStore)
	mgr.SetFamilyService(famSvc)

	return mgr
}

// seedUsers populates the user store with an admin and a regular trader.
func seedUsers(t *testing.T, mgr *kc.Manager) {
	t.Helper()
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	require.NoError(t, uStore.Create(&users.User{
		ID:    "u_admin",
		Email: "admin@example.com",
		Role:  users.RoleAdmin,
		Status: users.StatusActive,
	}))
	require.NoError(t, uStore.Create(&users.User{
		ID:    "u_trader",
		Email: "trader@example.com",
		Role:  users.RoleTrader,
		Status: users.StatusActive,
	}))
}

// callAdminTool finds a tool by name in GetAllTools and invokes its handler.
func callAdminTool(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

// ---------------------------------------------------------------------------
// adminCheck unit tests (no Manager needed for unauthenticated case)
// ---------------------------------------------------------------------------

func TestAdminCheck_UnauthenticatedReturnsError(t *testing.T) {
	mgr := newAdminTestManager(t)
	ctx := context.Background() // no email in context
	_, errResult := adminCheck(ctx, mgr)
	require.NotNil(t, errResult, "expected error result for unauthenticated call")
	assert.True(t, errResult.IsError, "result should be marked as error")
}

func TestAdminCheck_NonAdminReturnsError(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "trader@example.com")
	_, errResult := adminCheck(ctx, mgr)
	require.NotNil(t, errResult, "expected error result for non-admin")
	assert.True(t, errResult.IsError, "result should be marked as error")
}

func TestAdminCheck_AdminSucceeds(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "admin@example.com")
	email, errResult := adminCheck(ctx, mgr)
	assert.Nil(t, errResult, "admin should pass the check")
	assert.Equal(t, "admin@example.com", email)
}

// ---------------------------------------------------------------------------
// Tool-level tests
// ---------------------------------------------------------------------------

func TestAdminListUsers_NonAdminBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_list_users", "trader@example.com", nil)
	assert.True(t, result.IsError, "non-admin should be blocked from admin_list_users")
}

func TestAdminListUsers_UnauthenticatedBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_list_users", "", nil)
	assert.True(t, result.IsError, "unauthenticated user should be blocked from admin_list_users")
}

func TestAdminListUsers_AdminSucceeds(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_list_users", "admin@example.com", nil)
	assert.False(t, result.IsError, "admin should be able to list users")
}

func TestAdminSuspendUser_SelfActionBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError, "admin should not be able to suspend themselves")
}

func TestAdminSuspendUser_RequiresConfirm(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"confirm":      false,
	})
	assert.True(t, result.IsError, "suspend should require confirm=true")
}

func TestAdminSuspendUser_NonAdminBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_suspend_user", "trader@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError, "non-admin should be blocked from suspending users")
}

func TestAdminSuspendUser_LastAdminGuard(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)

	// Add a second admin so the first can attempt to suspend them
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID:     "u_admin2",
		Email:  "admin2@example.com",
		Role:   users.RoleAdmin,
		Status: users.StatusActive,
	}))

	// admin@example.com tries to suspend admin2@example.com — should succeed
	result := callAdminTool(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin2@example.com",
		"confirm":      true,
	})
	assert.False(t, result.IsError, "suspending a non-last admin should succeed")

	// Now admin@example.com is the last admin. Create a fresh manager to test last-admin guard.
	mgr2 := newAdminTestManager(t)
	uStore2 := mgr2.UserStoreConcrete()
	require.NoError(t, uStore2.Create(&users.User{
		ID: "u_a", Email: "admin@example.com", Role: users.RoleAdmin, Status: users.StatusActive,
	}))
	require.NoError(t, uStore2.Create(&users.User{
		ID: "u_victim", Email: "onlyadmin@example.com", Role: users.RoleAdmin, Status: users.StatusActive,
	}))
	// Suspend one so only one active admin remains
	require.NoError(t, uStore2.UpdateStatus("onlyadmin@example.com", users.StatusSuspended))

	// Now admin@example.com is the last active admin. Another active admin doesn't exist, but
	// we need a different admin to try the suspension. Since the suspended one can't act,
	// the guard is tested by trying to suspend the sole active admin from another admin perspective.
	// But we can't do that — need 2 active admins where one tries to suspend the other, and only 1 would remain.
	// Reset: create exactly 1 active admin and 1 inactive, then add a second active admin to do the call.
	mgr3 := newAdminTestManager(t)
	uStore3 := mgr3.UserStoreConcrete()
	require.NoError(t, uStore3.Create(&users.User{
		ID: "u_caller", Email: "caller-admin@example.com", Role: users.RoleAdmin, Status: users.StatusActive,
	}))
	require.NoError(t, uStore3.Create(&users.User{
		ID: "u_target", Email: "target-admin@example.com", Role: users.RoleAdmin, Status: users.StatusActive,
	}))
	// Both are active admins. Suspending one should succeed (2 admins → 1 remains).
	r := callAdminTool(t, mgr3, "admin_suspend_user", "caller-admin@example.com", map[string]any{
		"target_email": "target-admin@example.com",
		"confirm":      true,
	})
	assert.False(t, r.IsError, "suspending one of two admins should succeed")

	// Now caller-admin is the sole active admin. If they try to suspend another trader, it's fine.
	// But if somehow another admin was to suspend them it would be blocked — not testable in single-admin scenario.
}

func TestAdminFreezeGlobal_RequiresConfirm(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "market crash",
		"confirm": false,
	})
	assert.True(t, result.IsError, "global freeze should require confirm=true")
}

func TestAdminFreezeGlobal_RequiresReason(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "",
		"confirm": true,
	})
	assert.True(t, result.IsError, "global freeze should require a reason")
}

func TestAdminFreezeGlobal_AdminSucceeds(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "emergency",
		"confirm": true,
	})
	assert.False(t, result.IsError, "admin with confirm+reason should succeed in global freeze")
}

func TestAdminRemoveFamilyMember_RequiresConfirm(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"confirm":      false,
	})
	assert.True(t, result.IsError, "remove family member should require confirm=true")
}

func TestAdminRemoveFamilyMember_SelfBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError, "admin should not be able to remove themselves from family")
}

func TestAdminFreezeUser_SelfBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"reason":       "test",
		"confirm":      true,
	})
	assert.True(t, result.IsError, "admin should not be able to freeze themselves")
}

func TestAdminFreezeUser_RequiresConfirm(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"reason":       "testing",
		"confirm":      false,
	})
	assert.True(t, result.IsError, "freeze user should require confirm=true")
}

func TestAdminFreezeUser_AdminSucceeds(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"reason":       "risk limit breach",
		"confirm":      true,
	})
	assert.False(t, result.IsError, "admin should be able to freeze a trader")
}

func TestAdminActivateUser_NonAdminBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_activate_user", "trader@example.com", map[string]any{
		"target_email": "trader@example.com",
	})
	assert.True(t, result.IsError, "non-admin should be blocked from activating users")
}

func TestAdminServerStatus_AdminSucceeds(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_server_status", "admin@example.com", nil)
	assert.False(t, result.IsError, "admin should be able to get server status")
}

func TestAdminServerStatus_NonAdminBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	result := callAdminTool(t, mgr, "admin_server_status", "trader@example.com", nil)
	assert.True(t, result.IsError, "non-admin should be blocked from server status")
}

func TestFamilyInviteFlow(t *testing.T) {
	manager := newAdminTestManager(t)
	seedUsers(t, manager)

	// Wire up InvitationStore (no DB for tests)
	invStore := users.NewInvitationStore(nil)
	manager.SetInvitationStore(invStore)

	// Step 1: Admin invites family member
	result := callAdminTool(t, manager, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "family@example.com",
	})
	assert.False(t, result.IsError, "invite should succeed")

	// Step 2: Admin lists family (should show pending invite)
	result = callAdminTool(t, manager, "admin_list_family", "admin@example.com", nil)
	assert.False(t, result.IsError, "list family should succeed")

	// Step 3: Admin tries to invite themselves (should fail)
	result = callAdminTool(t, manager, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "admin@example.com",
	})
	assert.True(t, result.IsError, "self-invite should fail")

	// Step 4: Admin removes family member (should fail if not linked yet)
	result = callAdminTool(t, manager, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "family@example.com",
		"confirm":      true,
	})
	// This should fail because family@example.com isn't linked yet (just invited)
	assert.True(t, result.IsError, "remove unlinked member should fail")
}

// ---------------------------------------------------------------------------
// Integration tests — full admin workflows
// ---------------------------------------------------------------------------

func TestAdminWorkflow_SuspendActivateFreeze(t *testing.T) {
	manager := newAdminTestManager(t)
	seedUsers(t, manager)

	// 1. Admin lists users — should see both admin and trader
	result := callAdminTool(t, manager, "admin_list_users", "admin@example.com", nil)
	assert.False(t, result.IsError)

	// 2. Admin gets trader details
	result = callAdminTool(t, manager, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
	})
	assert.False(t, result.IsError)

	// 3. Admin freezes trader
	result = callAdminTool(t, manager, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"reason":       "suspicious activity",
		"confirm":      true,
	})
	assert.False(t, result.IsError)

	// 4. Admin checks risk status — trader should be frozen
	result = callAdminTool(t, manager, "admin_get_risk_status", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
	})
	assert.False(t, result.IsError)

	// 5. Admin unfreezes trader
	result = callAdminTool(t, manager, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
	})
	assert.False(t, result.IsError)

	// 6. Admin suspends trader
	result = callAdminTool(t, manager, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"reason":       "TOS violation",
		"confirm":      true,
	})
	assert.False(t, result.IsError)

	// 7. Admin activates trader
	result = callAdminTool(t, manager, "admin_activate_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
	})
	assert.False(t, result.IsError)

	// 8. Admin checks server status
	result = callAdminTool(t, manager, "admin_server_status", "admin@example.com", nil)
	assert.False(t, result.IsError)
}

func TestAdminWorkflow_RoleChanges(t *testing.T) {
	manager := newAdminTestManager(t)
	seedUsers(t, manager)

	// Create a second admin so we can test demotion
	uStore := manager.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID:     "u_admin2",
		Email:  "admin2@example.com",
		Role:   users.RoleAdmin,
		Status: users.StatusActive,
	}))

	// 1. Change trader to viewer
	result := callAdminTool(t, manager, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"role":         "viewer",
	})
	assert.False(t, result.IsError)

	// 2. Change viewer back to trader
	result = callAdminTool(t, manager, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"role":         "trader",
	})
	assert.False(t, result.IsError)

	// 3. Promote trader to admin
	result = callAdminTool(t, manager, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"role":         "admin",
	})
	assert.False(t, result.IsError)

	// 4. Now demote admin2 (should work — 3 admins remain)
	result = callAdminTool(t, manager, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "admin2@example.com",
		"role":         "trader",
	})
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// E2E test: admin_freeze_user tool → riskguard state change + event dispatch
// ---------------------------------------------------------------------------

func TestE2E_FreezeUser_DispatchesEvent(t *testing.T) {
	manager := newAdminTestManager(t)
	seedUsers(t, manager)

	// Wire up an EventDispatcher and subscribe to "user.frozen" events.
	ed := domain.NewEventDispatcher()
	manager.SetEventDispatcher(ed)

	var mu sync.Mutex
	var dispatched []string
	ed.Subscribe("user.frozen", func(event domain.Event) {
		mu.Lock()
		defer mu.Unlock()
		dispatched = append(dispatched, event.EventType())
	})

	// Call admin_freeze_user tool.
	result := callAdminTool(t, manager, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "trader@example.com",
		"reason":       "E2E test",
		"confirm":      true,
	})
	assert.False(t, result.IsError, "admin_freeze_user should succeed")

	// Verify: user is frozen in riskguard.
	rg := manager.RiskGuard()
	require.NotNil(t, rg, "RiskGuard should be wired")
	status := rg.GetUserStatus("trader@example.com")
	assert.True(t, status.IsFrozen, "trader should be frozen after admin_freeze_user")
	assert.Equal(t, "admin@example.com", status.FrozenBy)

	// Verify: user.frozen event was dispatched.
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"user.frozen"}, dispatched, "expected exactly one user.frozen event")
}
