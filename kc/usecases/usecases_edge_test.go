package usecases

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// --- Mock user store ---

type mockUserStore struct {
	usersList      []*users.User
	usersMap       map[string]*users.User
	createErr      error
	updateStatusErr error
	updateRoleErr  error
}

func newMockUserStore(uu ...*users.User) *mockUserStore {
	m := &mockUserStore{usersMap: make(map[string]*users.User)}
	for _, u := range uu {
		m.usersList = append(m.usersList, u)
		m.usersMap[u.Email] = u
	}
	return m
}

func (m *mockUserStore) List() []*users.User                    { return m.usersList }
func (m *mockUserStore) Get(email string) (*users.User, bool)   { u, ok := m.usersMap[email]; return u, ok }
func (m *mockUserStore) Count() int                             { return len(m.usersList) }
func (m *mockUserStore) IsAdmin(email string) bool              { u, ok := m.usersMap[email]; return ok && u.Role == users.RoleAdmin }
func (m *mockUserStore) UpdateStatus(email, status string) error {
	if m.updateStatusErr != nil {
		return m.updateStatusErr
	}
	if u, ok := m.usersMap[email]; ok {
		u.Status = status
	}
	return nil
}
func (m *mockUserStore) UpdateRole(email, role string) error {
	if m.updateRoleErr != nil {
		return m.updateRoleErr
	}
	if u, ok := m.usersMap[email]; ok {
		u.Role = role
	}
	return nil
}
func (m *mockUserStore) Create(u *users.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.usersList = append(m.usersList, u)
	m.usersMap[u.Email] = u
	return nil
}

// --- Mock riskguard ---

type mockRiskGuard struct {
	userStatus    riskguard.UserStatus
	userLimits    riskguard.UserLimits
	globalFrozen  bool
	frozenEmail   string
	unfrozenEmail string
	globalFrozeCalled bool
	globalUnfrozeCalled bool
}

func (m *mockRiskGuard) GetUserStatus(email string) riskguard.UserStatus   { return m.userStatus }
func (m *mockRiskGuard) GetEffectiveLimits(email string) riskguard.UserLimits { return m.userLimits }
func (m *mockRiskGuard) GetGlobalFreezeStatus() riskguard.GlobalFreezeStatus {
	return riskguard.GlobalFreezeStatus{}
}
func (m *mockRiskGuard) IsGloballyFrozen() bool { return m.globalFrozen }
func (m *mockRiskGuard) Freeze(email, by, reason string) { m.frozenEmail = email }
func (m *mockRiskGuard) Unfreeze(email string)           { m.unfrozenEmail = email }
func (m *mockRiskGuard) FreezeGlobal(by, reason string)  { m.globalFrozeCalled = true }
func (m *mockRiskGuard) UnfreezeGlobal()                 { m.globalUnfrozeCalled = true }

// --- Mock session terminator ---

type mockSessionTerminator struct {
	terminated int
}

func (m *mockSessionTerminator) TerminateByEmail(email string) int { return m.terminated }

// Credential/token/alert-deleter mocks live in mocks_test.go.

// ===========================================================================
// Admin List Users
// ===========================================================================

func TestAdminListUsers_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "a@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
		&users.User{Email: "b@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	uc := NewAdminListUsersUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Users, 2)
}

func TestAdminListUsers_Pagination(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "a@test.com"}, &users.User{Email: "b@test.com"}, &users.User{Email: "c@test.com"},
	)
	uc := NewAdminListUsersUseCase(store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{From: 1, Limit: 1})
	require.NoError(t, err)
	assert.Len(t, result.Users, 1)
	assert.Equal(t, "b@test.com", result.Users[0].Email)
}

func TestAdminListUsers_NegativeFrom(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com"})
	uc := NewAdminListUsersUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{From: -1})
	require.NoError(t, err)
	assert.Equal(t, 0, result.From)
}

func TestAdminListUsers_LimitZeroDefaultsTo100(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	uc := NewAdminListUsersUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{Limit: 0})
	require.NoError(t, err)
	assert.Equal(t, 100, result.Limit)
}

func TestAdminListUsers_LimitOver500(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	uc := NewAdminListUsersUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{Limit: 999})
	require.NoError(t, err)
	assert.Equal(t, 100, result.Limit)
}

func TestAdminListUsers_FromBeyondEnd(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com"})
	uc := NewAdminListUsersUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListUsersQuery{From: 100})
	require.NoError(t, err)
	assert.Len(t, result.Users, 0)
}

// ===========================================================================
// Admin Get User
// ===========================================================================

func TestAdminGetUser_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Role: users.RoleAdmin})
	rg := &mockRiskGuard{userStatus: riskguard.UserStatus{IsFrozen: false}}
	uc := NewAdminGetUserUseCase(store, rg, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminGetUserQuery{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Equal(t, "a@test.com", result.User.Email)
	assert.NotNil(t, result.RiskStatus)
}

func TestAdminGetUser_NoRiskguard(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com"})
	uc := NewAdminGetUserUseCase(store, nil, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminGetUserQuery{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Nil(t, result.RiskStatus)
}

func TestAdminGetUser_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminGetUserUseCase(newMockUserStore(), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminGetUserQuery{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminGetUser_NotFound(t *testing.T) {
	t.Parallel()
	uc := NewAdminGetUserUseCase(newMockUserStore(), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminGetUserQuery{TargetEmail: "no@test.com"})
	assert.ErrorContains(t, err, "user not found")
}

// ===========================================================================
// Admin Get Risk Status
// ===========================================================================

func TestAdminGetRiskStatus_Success(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{
		userStatus: riskguard.UserStatus{DailyPlacedValue: 50000},
		userLimits: riskguard.UserLimits{MaxDailyValueINR: 1000000},
	}
	uc := NewAdminGetRiskStatusUseCase(rg, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminGetRiskStatusQuery{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Equal(t, float64(950000), result.OrderHeadroom)
}

func TestAdminGetRiskStatus_NegativeHeadroom(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{
		userStatus: riskguard.UserStatus{DailyPlacedValue: 2000000},
		userLimits: riskguard.UserLimits{MaxDailyValueINR: 1000000},
	}
	uc := NewAdminGetRiskStatusUseCase(rg, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminGetRiskStatusQuery{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Equal(t, float64(0), result.OrderHeadroom)
}

func TestAdminGetRiskStatus_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminGetRiskStatusUseCase(&mockRiskGuard{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminGetRiskStatusQuery{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminGetRiskStatus_NilRiskguard(t *testing.T) {
	t.Parallel()
	uc := NewAdminGetRiskStatusUseCase(nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminGetRiskStatusQuery{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "riskguard not available")
}

// ===========================================================================
// Admin Suspend User
// ===========================================================================

func TestAdminSuspendUser_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "admin@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
		&users.User{Email: "trader@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	rg := &mockRiskGuard{}
	sess := &mockSessionTerminator{terminated: 2}
	uc := NewAdminSuspendUserUseCase(store, rg, sess, nil, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "trader@test.com", Reason: "test",
	})
	require.NoError(t, err)
	assert.Equal(t, "suspended", result.Status)
	assert.Equal(t, 2, result.SessionsTerminated)
}

func TestAdminSuspendUser_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminSuspendUserUseCase(newMockUserStore(), nil, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminSuspendUser_SelfSuspend(t *testing.T) {
	t.Parallel()
	uc := NewAdminSuspendUserUseCase(newMockUserStore(), nil, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "cannot suspend yourself")
}

func TestAdminSuspendUser_LastAdmin(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "admin@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
	)
	uc := NewAdminSuspendUserUseCase(store, nil, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "other@test.com", TargetEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "last active admin")
}

func TestAdminSuspendUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "trader@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	store.updateStatusErr = errors.New("db fail")
	uc := NewAdminSuspendUserUseCase(store, nil, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "trader@test.com",
	})
	assert.ErrorContains(t, err, "suspend user")
}

func TestAdminSuspendUser_NilOptionalDeps(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "trader@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	uc := NewAdminSuspendUserUseCase(store, nil, nil, nil, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "trader@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.SessionsTerminated)
}

// ===========================================================================
// Admin Activate User
// ===========================================================================

func TestAdminActivateUser_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Status: users.StatusSuspended})
	uc := NewAdminActivateUserUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminActivateUserCommand{TargetEmail: "a@test.com"})
	require.NoError(t, err)
}

func TestAdminActivateUser_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminActivateUserUseCase(newMockUserStore(), testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminActivateUserCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminActivateUser_Error(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	store.updateStatusErr = errors.New("db fail")
	uc := NewAdminActivateUserUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminActivateUserCommand{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "activate user")
}

// ===========================================================================
// Admin Change Role
// ===========================================================================

func TestAdminChangeRole_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Role: users.RoleTrader, Status: users.StatusActive})
	uc := NewAdminChangeRoleUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{
		TargetEmail: "a@test.com", NewRole: users.RoleAdmin,
	})
	require.NoError(t, err)
	assert.Equal(t, users.RoleTrader, result.OldRole)
	assert.Equal(t, users.RoleAdmin, result.NewRole)
}

func TestAdminChangeRole_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminChangeRoleUseCase(newMockUserStore(), testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminChangeRole_EmptyRole(t *testing.T) {
	t.Parallel()
	uc := NewAdminChangeRoleUseCase(newMockUserStore(), testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "new_role is required")
}

func TestAdminChangeRole_NotFound(t *testing.T) {
	t.Parallel()
	uc := NewAdminChangeRoleUseCase(newMockUserStore(), testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{
		TargetEmail: "no@test.com", NewRole: users.RoleAdmin,
	})
	assert.ErrorContains(t, err, "user not found")
}

func TestAdminChangeRole_LastAdmin(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "a@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
	)
	uc := NewAdminChangeRoleUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{
		TargetEmail: "a@test.com", NewRole: users.RoleTrader,
	})
	assert.ErrorContains(t, err, "last active admin")
}

func TestAdminChangeRole_UpdateRoleError(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Role: users.RoleTrader})
	store.updateRoleErr = errors.New("db fail")
	uc := NewAdminChangeRoleUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminChangeRoleCommand{
		TargetEmail: "a@test.com", NewRole: users.RoleAdmin,
	})
	assert.ErrorContains(t, err, "change role")
}

// ===========================================================================
// Admin Freeze User
// ===========================================================================

func TestAdminFreezeUser_Success(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{}
	uc := NewAdminFreezeUserUseCase(rg, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminFreezeUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "a@test.com", Reason: "test",
	})
	require.NoError(t, err)
	assert.Equal(t, "a@test.com", rg.frozenEmail)
}

func TestAdminFreezeUser_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminFreezeUserUseCase(&mockRiskGuard{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminFreezeUserCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminFreezeUser_NilRiskguard(t *testing.T) {
	t.Parallel()
	uc := NewAdminFreezeUserUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminFreezeUserCommand{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "riskguard not available")
}

// ===========================================================================
// Admin Unfreeze User
// ===========================================================================

func TestAdminUnfreezeUser_Success(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{}
	uc := NewAdminUnfreezeUserUseCase(rg, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUnfreezeUserCommand{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Equal(t, "a@test.com", rg.unfrozenEmail)
}

func TestAdminUnfreezeUser_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminUnfreezeUserUseCase(&mockRiskGuard{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUnfreezeUserCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminUnfreezeUser_NilRiskguard(t *testing.T) {
	t.Parallel()
	uc := NewAdminUnfreezeUserUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUnfreezeUserCommand{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "riskguard not available")
}

// ===========================================================================
// Admin Freeze Global
// ===========================================================================

func TestAdminFreezeGlobal_Success(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{}
	uc := NewAdminFreezeGlobalUseCase(rg, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminFreezeGlobalCommand{AdminEmail: "admin@test.com"})
	require.NoError(t, err)
	assert.True(t, rg.globalFrozeCalled)
}

func TestAdminFreezeGlobal_NilRiskguard(t *testing.T) {
	t.Parallel()
	uc := NewAdminFreezeGlobalUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminFreezeGlobalCommand{})
	assert.ErrorContains(t, err, "riskguard not available")
}

// ===========================================================================
// Admin Unfreeze Global
// ===========================================================================

func TestAdminUnfreezeGlobal_Success(t *testing.T) {
	t.Parallel()
	rg := &mockRiskGuard{}
	uc := NewAdminUnfreezeGlobalUseCase(rg, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUnfreezeGlobalCommand{})
	require.NoError(t, err)
	assert.True(t, rg.globalUnfrozeCalled)
}

func TestAdminUnfreezeGlobal_NilRiskguard(t *testing.T) {
	t.Parallel()
	uc := NewAdminUnfreezeGlobalUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUnfreezeGlobalCommand{})
	assert.ErrorContains(t, err, "riskguard not available")
}

// ===========================================================================
// Delete My Account
// ===========================================================================

func TestDeleteMyAccount_Success(t *testing.T) {
	t.Parallel()
	cred := &mockCredentialStore{}
	tok := &mockTokenStore{}
	al := &mockAlertDeleterStore{}
	wl := &mockWatchlistStore{}
	ts := &mockTrailingStopManager{}
	pe := &mockPaperEngine{}
	us := newMockUserStore(&users.User{Email: "a@test.com", Status: users.StatusActive})
	sess := &mockSessionTerminator{}

	uc := NewDeleteMyAccountUseCase(AccountDependencies{
		CredentialStore: cred, TokenStore: tok, AlertDeleter: al,
		WatchlistStore: wl, TrailingStops: ts, PaperEngine: pe,
		UserStore: us, Sessions: sess,
	}, testLogger())

	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{Email: "a@test.com"})
	require.NoError(t, err)
	assert.True(t, cred.deleted)
	assert.True(t, tok.deleted)
	assert.True(t, al.deleted)
}

func TestDeleteMyAccount_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteMyAccountUseCase(AccountDependencies{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteMyAccount_NilDeps(t *testing.T) {
	t.Parallel()
	uc := NewDeleteMyAccountUseCase(AccountDependencies{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{Email: "a@test.com"})
	require.NoError(t, err) // All nil deps gracefully skipped
}

func TestDeleteMyAccount_PaperResetError(t *testing.T) {
	t.Parallel()
	pe := &mockPaperEngine{resetErr: errors.New("fail")}
	uc := NewDeleteMyAccountUseCase(AccountDependencies{PaperEngine: pe}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{Email: "a@test.com"})
	require.NoError(t, err) // Error is logged but not returned
}

func TestDeleteMyAccount_PaperDisableError(t *testing.T) {
	t.Parallel()
	pe := &mockPaperEngine{disableErr: errors.New("fail")}
	uc := NewDeleteMyAccountUseCase(AccountDependencies{PaperEngine: pe}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{Email: "a@test.com"})
	require.NoError(t, err) // Error is logged but not returned
}

func TestDeleteMyAccount_UserStoreError(t *testing.T) {
	t.Parallel()
	us := newMockUserStore()
	us.updateStatusErr = errors.New("fail")
	uc := NewDeleteMyAccountUseCase(AccountDependencies{UserStore: us}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteMyAccountCommand{Email: "a@test.com"})
	require.NoError(t, err) // Error is logged but not returned
}

// ===========================================================================
// Coverage push: tests for ALL remaining 0% use case functions.
// Only includes tests that don't already exist in other test files.
// ===========================================================================

// ---------------------------------------------------------------------------
// alert_usecases.go — ListAlerts, DeleteAlert
// ---------------------------------------------------------------------------

type mockAlertReader struct {
	alerts    []*alerts.Alert
	deleteErr error
}

func (m *mockAlertReader) List(email string) []*alerts.Alert { return m.alerts }
func (m *mockAlertReader) Delete(email, alertID string) error { return m.deleteErr }

func TestListAlerts_Success(t *testing.T) {
	t.Parallel()
	store := &mockAlertReader{alerts: []*alerts.Alert{{Email: "u@t.com"}}}
	uc := NewListAlertsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetAlertsQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListAlerts_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListAlertsUseCase(&mockAlertReader{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetAlertsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteAlert_Success(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com", AlertID: "a1"})
	assert.NoError(t, err)
}

func TestDeleteAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{AlertID: "a1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteAlert_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "alert_id is required")
}

func TestDeleteAlert_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockAlertReader{deleteErr: errors.New("db fail")}
	uc := NewDeleteAlertUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com", AlertID: "a1"})
	assert.ErrorContains(t, err, "delete alert")
}

// ---------------------------------------------------------------------------
// native_alert_usecases.go — Place, List, Modify, Delete, History
// ---------------------------------------------------------------------------

type mockNativeAlertClient struct {
	createResult any
	createErr    error
	modifyResult any
	modifyErr    error
	deleteErr    error
	alerts       any
	alertsErr    error
	history      any
	historyErr   error
}

func (m *mockNativeAlertClient) CreateAlert(params any) (any, error) {
	return m.createResult, m.createErr
}
func (m *mockNativeAlertClient) ModifyAlert(uuid string, params any) (any, error) {
	return m.modifyResult, m.modifyErr
}
func (m *mockNativeAlertClient) DeleteAlerts(uuids ...string) error { return m.deleteErr }
func (m *mockNativeAlertClient) GetAlerts(filters map[string]string) (any, error) {
	return m.alerts, m.alertsErr
}
func (m *mockNativeAlertClient) GetAlertHistory(uuid string) (any, error) {
	return m.history, m.historyErr
}

func TestPlaceNativeAlert_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{createResult: "ok"}
	uc := NewPlaceNativeAlertUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.PlaceNativeAlertCommand{
		Email: "u@t.com", Params: map[string]any{"name": "test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", result)
}

func TestPlaceNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPlaceNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.PlaceNativeAlertCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPlaceNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{createErr: errors.New("api fail")}
	uc := NewPlaceNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.PlaceNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "create native alert")
}

func TestListNativeAlerts_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{alerts: []string{"a1"}}
	uc := NewListNativeAlertsUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.ListNativeAlertsQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestListNativeAlerts_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListNativeAlertsUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ListNativeAlertsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestListNativeAlerts_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{alertsErr: errors.New("api fail")}
	uc := NewListNativeAlertsUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.ListNativeAlertsQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "list native alerts")
}

func TestModifyNativeAlert_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{modifyResult: "updated"}
	uc := NewModifyNativeAlertUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.ModifyNativeAlertCommand{
		Email: "u@t.com", UUID: "uuid-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "updated", result)
}

func TestModifyNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ModifyNativeAlertCommand{UUID: "u1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestModifyNativeAlert_EmptyUUID(t *testing.T) {
	t.Parallel()
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ModifyNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "uuid is required")
}

func TestModifyNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{modifyErr: errors.New("api fail")}
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.ModifyNativeAlertCommand{Email: "u@t.com", UUID: "u1"})
	assert.ErrorContains(t, err, "modify native alert")
}

func TestDeleteNativeAlert_Success(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{
		Email: "u@t.com", UUIDs: []string{"u1", "u2"},
	})
	assert.NoError(t, err)
}

func TestDeleteNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{UUIDs: []string{"u1"}})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteNativeAlert_NoUUIDs(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "at least one uuid")
}

func TestDeleteNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{deleteErr: errors.New("api fail")}
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), client, cqrs.DeleteNativeAlertCommand{Email: "u@t.com", UUIDs: []string{"u1"}})
	assert.ErrorContains(t, err, "delete native alert")
}

func TestGetNativeAlertHistory_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{history: []string{"h1"}}
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com", UUID: "u1"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetNativeAlertHistory_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.GetNativeAlertHistoryQuery{UUID: "u1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetNativeAlertHistory_EmptyUUID(t *testing.T) {
	t.Parallel()
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "uuid is required")
}

func TestGetNativeAlertHistory_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{historyErr: errors.New("api fail")}
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com", UUID: "u1"})
	assert.ErrorContains(t, err, "get native alert history")
}

// ---------------------------------------------------------------------------
// setup_usecases.go — Login, OpenDashboard, isAlphanumeric
// ---------------------------------------------------------------------------

func TestLoginUseCase_Valid(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{})
	assert.NoError(t, err)
}

func TestLoginUseCase_APIKeyOnly(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

func TestLoginUseCase_APISecretOnly(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APISecret: "abc123"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

func TestLoginUseCase_InvalidAPIKey(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc!@#", APISecret: "abc123"})
	assert.ErrorContains(t, err, "invalid api_key")
}

func TestLoginUseCase_InvalidAPISecret(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123", APISecret: "abc!@#"})
	assert.ErrorContains(t, err, "invalid api_secret")
}

func TestLoginUseCase_BothValid(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(nil, testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123", APISecret: "def456"})
	assert.NoError(t, err)
}

func TestOpenDashboard_Valid(t *testing.T) {
	t.Parallel()
	uc := NewOpenDashboardUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.OpenDashboardQuery{Page: "portfolio"})
	assert.NoError(t, err)
}

func TestOpenDashboard_EmptyPage(t *testing.T) {
	t.Parallel()
	uc := NewOpenDashboardUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.OpenDashboardQuery{})
	assert.ErrorContains(t, err, "page is required")
}

// ---------------------------------------------------------------------------
// telegram_usecases.go — SetupTelegram
// ---------------------------------------------------------------------------

type mockTelegramStore struct {
	chatID int64
	email  string
}

func (m *mockTelegramStore) SetTelegramChatID(email string, chatID int64) {
	m.email = email
	m.chatID = chatID
}
func (m *mockTelegramStore) GetTelegramChatID(email string) (int64, bool) {
	if m.email == email {
		return m.chatID, true
	}
	return 0, false
}

func TestSetupTelegram_Success(t *testing.T) {
	t.Parallel()
	store := &mockTelegramStore{}
	uc := NewSetupTelegramUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 12345})
	require.NoError(t, err)
	assert.Equal(t, int64(12345), store.chatID)
}

func TestSetupTelegram_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewSetupTelegramUseCase(&mockTelegramStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{ChatID: 12345})
	assert.ErrorContains(t, err, "email is required")
}

func TestSetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	uc := NewSetupTelegramUseCase(&mockTelegramStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "chat_id is required")
}

// ---------------------------------------------------------------------------
// account_usecases.go — UpdateMyCredentials
// ---------------------------------------------------------------------------

// Duplicate mocks removed — use canonical mockCredentialStore / mockTokenStore
// / mockAlertDeleterStore from mocks_test.go.

func TestUpdateMyCredentials_Success(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredentialStore{}, &mockTokenStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{
		Email: "u@t.com", APIKey: "key", APISecret: "secret",
	})
	assert.NoError(t, err)
}

func TestUpdateMyCredentials_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredentialStore{}, &mockTokenStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{APIKey: "k", APISecret: "s"})
	assert.ErrorContains(t, err, "email is required")
}

func TestUpdateMyCredentials_MissingKeys(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredentialStore{}, &mockTokenStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

// ---------------------------------------------------------------------------
// context_usecases.go — TradingContext
// ---------------------------------------------------------------------------

func TestTradingContext_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		margins:   broker.Margins{},
		positions: broker.Positions{},
		orders:    []broker.Order{{OrderID: "o1"}},
		holdings:  []broker.Holding{{Tradingsymbol: "INFY"}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewTradingContextUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result.Margins)
	assert.NotNil(t, result.Positions)
	assert.Len(t, result.Orders, 1)
	assert.Len(t, result.Holdings, 1)
	assert.Nil(t, result.Errors)
}

func TestTradingContext_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewTradingContextUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestTradingContext_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewTradingContextUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestTradingContext_PartialErrors(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		marginsErr:   errors.New("margin fail"),
		positionsErr: errors.New("pos fail"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewTradingContextUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result.Errors)
	assert.Contains(t, result.Errors["margins"], "margin fail")
	assert.Contains(t, result.Errors["positions"], "pos fail")
}

// ---------------------------------------------------------------------------
// pretrade_usecases.go — PreTradeCheck
// ---------------------------------------------------------------------------

func TestPreTradeCheck_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{"NSE:INFY": {LastPrice: 1500}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPreTradeCheckUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{
		Email: "u@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Product: "CNC", OrderType: "LIMIT",
		Quantity: 10, Price: 1500,
	})
	require.NoError(t, err)
	assert.NotNil(t, result.LTP)
	assert.Nil(t, result.Errors)
}

func TestPreTradeCheck_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPreTradeCheckUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPreTradeCheck_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewPreTradeCheckUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

// ---------------------------------------------------------------------------
// gtt_usecases.go — new coverage: Error, EmptySymbol only
// ---------------------------------------------------------------------------

func TestGetGTTs_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{gttsErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetGTTsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "get gtts")
}

func TestPlaceGTT_EmptySymbol(t *testing.T) {
	t.Parallel()
	uc := NewPlaceGTTUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{Email: "u@t.com", Type: "single"})
	assert.ErrorContains(t, err, "tradingsymbol is required")
}

func TestPlaceGTT_CQRS_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeGTTResp: broker.GTTResponse{TriggerID: 42}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceGTTUseCase(resolver, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "u@t.com", Instrument: domain.NewInstrumentKey("", "INFY"), Type: "single", Quantity: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, 42, resp.TriggerID)
}

func TestModifyGTT_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyGTTErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{Email: "u@t.com", TriggerID: 1, Type: "two-leg", UpperQuantity: 1, LowerQuantity: 1})
	assert.ErrorContains(t, err, "modify gtt")
}

func TestDeleteGTT_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{deleteGTTErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewDeleteGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{Email: "u@t.com", TriggerID: 1})
	assert.ErrorContains(t, err, "delete gtt")
}

// ---------------------------------------------------------------------------
// cancel_order.go — new: EmptyEmail, EmptyOrderID
// ---------------------------------------------------------------------------

func TestCancelOrder_CQRS_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCancelOrderUseCase(&mockBrokerResolver{}, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{OrderID: "o1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestCancelOrder_CQRS_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewCancelOrderUseCase(&mockBrokerResolver{}, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

// ---------------------------------------------------------------------------
// modify_order.go — ModifyOrder
// ---------------------------------------------------------------------------

func TestModifyOrder_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyResp: broker.OrderResponse{OrderID: "o1"}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email: "u@t.com", OrderID: "o1", Quantity: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "o1", resp.OrderID)
}

func TestModifyOrder_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewModifyOrderUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{OrderID: "o1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestModifyOrder_UC_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewModifyOrderUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

func TestModifyOrder_UC_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{Email: "u@t.com", OrderID: "o1"})
	assert.ErrorContains(t, err, "modify order")
}

// ---------------------------------------------------------------------------
// close_position.go — ClosePosition
// ---------------------------------------------------------------------------

func TestClosePosition_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "", "NSE", "INFY", "")
	assert.ErrorContains(t, err, "email is required")
}

func TestClosePosition_UC_EmptyExchange(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "u@t.com", "", "INFY", "")
	assert.ErrorContains(t, err, "exchange and symbol")
}

func TestClosePosition_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{Net: []broker.Position{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, Product: "CNC", PnL: 100},
		}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())
	result, err := uc.Execute(context.Background(), "u@t.com", "NSE", "INFY", "")
	require.NoError(t, err)
	assert.Equal(t, "SELL", result.Direction)
	assert.Equal(t, 10, result.Quantity)
}

func TestClosePosition_UC_NoPosition(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{positions: broker.Positions{}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "u@t.com", "NSE", "UNKNOWN", "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// close_all_positions.go — CloseAllPositions
// ---------------------------------------------------------------------------

func TestCloseAllPositions_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCloseAllPositionsUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "", "")
	assert.ErrorContains(t, err, "email is required")
}

func TestCloseAllPositions_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{Net: []broker.Position{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, Product: "MIS"},
			{Tradingsymbol: "SBIN", Exchange: "NSE", Quantity: -5, Product: "MIS"},
		}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())
	result, err := uc.Execute(context.Background(), "u@t.com", "")
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
}

// ---------------------------------------------------------------------------
// queries.go — GetProfile error, GetMargins
// ---------------------------------------------------------------------------

func TestGetProfile_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{profileErr: errors.New("fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetProfileUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "get profile")
}

func TestGetMargins_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{margins: broker.Margins{}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetMarginsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "u@t.com"})
	assert.NoError(t, err)
}

func TestGetMargins_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

// ---------------------------------------------------------------------------
// PlaceOrder additional paths (resolve error, broker error)
// ---------------------------------------------------------------------------

func TestPlaceOrder_CQRS_ResolveErr(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"u@t.com", "NSE", "INFY", "BUY", "MARKET", "", 10, 0,
	))
	assert.ErrorContains(t, err, "resolve broker")
}

func TestPlaceOrder_CQRS_BrokerErr(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), testPlaceCmd(
		"u@t.com", "NSE", "INFY", "BUY", "MARKET", "", 10, 0,
	))
	assert.ErrorContains(t, err, "place order")
}

// ---------------------------------------------------------------------------
// watchlist_usecases.go — AddToWatchlist, GetWatchlist
// ---------------------------------------------------------------------------

func TestAddToWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{}
	uc := NewAddToWatchlistUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email: "u@t.com", WatchlistID: "wl1",
		Exchange: "NSE", Tradingsymbol: "INFY",
	})
	assert.NoError(t, err)
}

func TestAddToWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAddToWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{WatchlistID: "wl1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestAddToWatchlist_EmptyWatchlistID(t *testing.T) {
	t.Parallel()
	uc := NewAddToWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}

func TestAddToWatchlist_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{addItemErr: errors.New("full")}
	uc := NewAddToWatchlistUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email: "u@t.com", WatchlistID: "wl1",
	})
	assert.ErrorContains(t, err, "add to watchlist")
}

func TestGetWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		items: []*watchlist.WatchlistItem{{Tradingsymbol: "INFY"}},
	}
	uc := NewGetWatchlistUseCase(store, testLogger())
	items, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{
		Email: "u@t.com", WatchlistID: "wl1",
	})
	require.NoError(t, err)
	assert.Len(t, items, 1)
}

func TestGetWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{WatchlistID: "wl1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetWatchlist_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewGetWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}

// ---------------------------------------------------------------------------
// pretrade_usecases.go — API error path (lines 91-94)
// ---------------------------------------------------------------------------

func TestPreTradeCheck_APIErrors(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ltpErr:     errors.New("ltp fail"),
		marginsErr: errors.New("margins fail"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPreTradeCheckUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{
		Email: "u@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Product: "CNC", OrderType: "LIMIT",
		Quantity: 10, Price: 1500,
	})
	require.NoError(t, err)
	assert.NotNil(t, result.Errors)
	assert.Contains(t, result.Errors["ltp"], "ltp fail")
	assert.Contains(t, result.Errors["margins"], "margins fail")
}

// ---------------------------------------------------------------------------
// admin_usecases.go — event dispatch path (lines 273-280)
// ---------------------------------------------------------------------------

func TestAdminSuspendUser_WithEvents(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "admin@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
		&users.User{Email: "trader@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	events := domain.NewEventDispatcher()
	dispatched := false
	events.Subscribe("user.suspended", func(e domain.Event) {
		dispatched = true
	})
	uc := NewAdminSuspendUserUseCase(store, nil, nil, events, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail: "admin@test.com", TargetEmail: "trader@test.com", Reason: "policy",
	})
	require.NoError(t, err)
	assert.Equal(t, "suspended", result.Status)
	assert.True(t, dispatched, "event should have been dispatched")
}

// --- Mock audit store ---

type mockAuditStore struct {
	stats        *audit.Stats
	statsErr     error
	toolMetrics  []audit.ToolMetric
	toolErr      error
	topErrors    []audit.UserErrorCount
	topErrorsErr error
}

func (m *mockAuditStore) GetGlobalStats(since time.Time) (*audit.Stats, error) {
	return m.stats, m.statsErr
}
func (m *mockAuditStore) GetToolMetrics(since time.Time) ([]audit.ToolMetric, error) {
	return m.toolMetrics, m.toolErr
}
func (m *mockAuditStore) GetTopErrorUsers(since time.Time, limit int) ([]audit.UserErrorCount, error) {
	return m.topErrors, m.topErrorsErr
}

func TestServerMetrics_Success_24h(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{
		stats:       &audit.Stats{TotalCalls: 100, ErrorCount: 5},
		toolMetrics: []audit.ToolMetric{{ToolName: "get_holdings", CallCount: 50}},
		topErrors:   []audit.UserErrorCount{{Email: "user@test.com", ErrorCount: 3}},
	}
	uc := NewServerMetricsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com", Period: "24h",
	})
	require.NoError(t, err)
	assert.Equal(t, "24h", result.Period)
	assert.Equal(t, 100, result.Stats.TotalCalls)
	assert.Len(t, result.ToolMetrics, 1)
	assert.Len(t, result.TopErrorUsers, 1)
}

func TestServerMetrics_Periods(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}}
	uc := NewServerMetricsUseCase(store, testLogger())

	for _, period := range []string{"1h", "24h", "7d", "30d", "unknown", ""} {
		result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
			AdminEmail: "admin@test.com", Period: period,
		})
		require.NoError(t, err, "period=%q", period)
		if period == "" || period == "unknown" {
			assert.Equal(t, "24h", result.Period, "period=%q should default to 24h", period)
		} else {
			assert.Equal(t, period, result.Period)
		}
	}
}

func TestServerMetrics_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewServerMetricsUseCase(&mockAuditStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{})
	assert.ErrorContains(t, err, "admin_email is required")
}

func TestServerMetrics_StatsError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{statsErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "get global stats")
}

func TestServerMetrics_ToolMetricsError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}, toolErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "get tool metrics")
}

func TestServerMetrics_TopErrorUsersError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}, topErrorsErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	require.NoError(t, err) // topErrorUsers error is silently ignored
	assert.Nil(t, result.TopErrorUsers)
}
