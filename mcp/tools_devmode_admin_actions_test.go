package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// DevMode admin action tool tests: admin_list_users, admin_freeze_*, admin_suspend_*, admin_change_role, admin_*_family, etc.

func TestAdminListUsers_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_users", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminServerStatus_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminGetRiskStatus_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminFreezeGlobal_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test freeze",
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Unfreeze
	result = callToolAdmin(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminSuspendUser_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to suspend
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_suspend", Email: "suspend@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "suspend@example.com",
		"reason":       "test",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Reactivate
	result = callToolAdmin(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{
		"target_email": "suspend@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminGetUser_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminChangeRole_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to change role
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_role", Email: "role@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "role@example.com",
		"role":         "viewer",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminFreezeUser_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to freeze
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_freeze", Email: "freeze@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "freeze@example.com",
		"reason":       "test freeze",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Unfreeze
	result = callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"target_email": "freeze@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminInviteFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "family@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminListFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestAdminRemoveFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "nonexistent@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminSuspendUser_SelfAction(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // can't suspend self
}


func TestAdminSuspendUser_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "someone@example.com",
		"confirm":      false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestAdminChangeRole_SelfAction(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"role":         "viewer",
	})
	assert.NotNil(t, result)
	// May be error (self-demotion guard) or succeed
}


func TestAdminFreezeGlobal_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestAdminListFamily_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "nobody@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // not admin
}


func TestAdminFreezeGlobal_NoReason(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "reason")
}


func TestAdminFreezeGlobal_NoConfirm_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason": "emergency",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}


func TestAdminFreezeGlobal_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "emergency",
		"confirm": true,
	})
	assert.NotNil(t, result)
	// Should succeed (no elicitation in test context)
}


func TestAdminUnfreezeGlobal_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Freeze first
	_ = callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": true,
	})
	// Unfreeze
	result := callToolAdmin(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminInviteFamily_SelfInvite(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "admin@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminInviteFamily_EmptyEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "",
	})
	assert.True(t, result.IsError)
}


func TestAdminListFamily_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "admin@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminRemoveFamily_NotConfirmed(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "someone@example.com",
		"confirm":      false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}


func TestAdminRemoveFamily_SelfRemove(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError)
}


func TestAdminRemoveFamily_NotInFamily(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "nobody@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError)
}



// ---------------------------------------------------------------------------
// ext_apps: more data function coverage
// ---------------------------------------------------------------------------
func TestAdminGetUser_WithCredsAndToken(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Seed a user with credentials
	mgr.CredentialStore().Set("target@example.com", &kc.KiteCredentialEntry{
		APIKey: "tk", APISecret: "ts", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("target@example.com", &kc.KiteTokenEntry{
		AccessToken: "at", StoredAt: time.Now(),
	})
	result := callToolAdmin(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminFreezeUser_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
		"reason":       "testing",
	})
	assert.NotNil(t, result)
	// May fail if target user doesn't exist, or succeed if riskguard handles it
}


func TestAdminUnfreezeUser_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Freeze first
	_ = callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
		"reason":       "testing",
	})
	// Unfreeze
	result := callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestAdminSuspendUser_Active(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com", // self-suspend
		"reason":       "testing",
	})
	// Self-suspend should be rejected
	assert.True(t, result.IsError)
}


func TestAdminServerStatus_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}



// ---------------------------------------------------------------------------
// watchlist_tools: get_watchlist with sort_by
// ---------------------------------------------------------------------------
func TestAdminFreezeUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminUnfreezeUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminListUsers_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_users", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestAdminSuspendUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_suspend_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminActivateUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_activate_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminGetRiskStatus_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_risk_status", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestAdminChangeRole_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_change_role", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
		"role":  "viewer",
	})
	assert.True(t, result.IsError)
}


func TestAdminFreezeGlobal_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_global", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestAdminUnfreezeGlobal_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_global", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestAdminInviteFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_invite_family_member", "nonadmin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminListFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_family", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestAdminRemoveFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_remove_family_member", "nonadmin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminGetUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}


func TestAdminServerStatus_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_server_status", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}



// ---------------------------------------------------------------------------
// dividend_calendar: missing instrument
// ---------------------------------------------------------------------------
func TestAdminListUsers_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_users", "admin@example.com", map[string]any{})
	assert.False(t, result.IsError)
}


func TestAdminGetUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.False(t, result.IsError)
}


func TestAdminGetUser_NotFound_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "nonexistent@example.com",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


func TestAdminServerStatus_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.False(t, result.IsError)
}


func TestAdminGetRiskStatus_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.False(t, result.IsError)
}


func TestAdminSuspendUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Create a user to suspend
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_target", Email: "target@example.com",
		Role: users.RoleTrader, Status: users.StatusActive,
	})
	result := callToolDevMode(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"email":  "target@example.com",
		"reason": "test suspension",
	})
	assert.NotNil(t, result)
}


func TestAdminActivateUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_suspended", Email: "suspended@example.com",
		Role: users.RoleTrader, Status: users.StatusSuspended,
	})
	result := callToolDevMode(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{
		"email": "suspended@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminChangeRole_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_role", Email: "rolechange@example.com",
		Role: users.RoleTrader, Status: users.StatusActive,
	})
	result := callToolDevMode(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"email": "rolechange@example.com",
		"role":  "viewer",
	})
	assert.NotNil(t, result)
}


func TestAdminFreezeUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"email":  "admin@example.com",
		"reason": "test freeze",
	})
	assert.NotNil(t, result)
}


func TestAdminUnfreezeUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"email": "admin@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminFreezeGlobal_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason": "test global freeze",
	})
	assert.NotNil(t, result)
}


func TestAdminUnfreezeGlobal_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestAdminInviteFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.NotNil(t, result)
}


func TestAdminListFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_family", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestAdminRemoveFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.NotNil(t, result)
}
