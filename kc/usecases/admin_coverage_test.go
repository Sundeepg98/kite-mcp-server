package usecases

// admin_coverage_test.go — tests for admin and account usecases.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
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

// --- Mock credential/token/alert stores ---

type mockCredentialStore struct{ deleted bool }
func (m *mockCredentialStore) Delete(email string) { m.deleted = true }

type mockTokenStore struct{ deleted bool }
func (m *mockTokenStore) Delete(email string) { m.deleted = true }

type mockAlertDeleterStore struct{ deleted bool }
func (m *mockAlertDeleterStore) DeleteByEmail(email string) { m.deleted = true }

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
// Admin List Family
// ===========================================================================

func TestAdminListFamily_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com"})
	uc := NewAdminListFamilyUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.AdminListFamilyQuery{})
	require.NoError(t, err)
	assert.Len(t, result, 1)
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
// Admin Invite Family Member
// ===========================================================================

func TestAdminInviteFamilyMember_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	uc := NewAdminInviteFamilyMemberUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail: "admin@test.com", Email: "new@test.com", Role: users.RoleViewer,
	})
	require.NoError(t, err)
	_, ok := store.Get("new@test.com")
	assert.True(t, ok)
}

func TestAdminInviteFamilyMember_DefaultRole(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	uc := NewAdminInviteFamilyMemberUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail: "admin@test.com", Email: "new@test.com",
	})
	require.NoError(t, err)
	u, _ := store.Get("new@test.com")
	assert.Equal(t, users.RoleTrader, u.Role)
}

func TestAdminInviteFamilyMember_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminInviteFamilyMemberUseCase(newMockUserStore(), testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestAdminInviteFamilyMember_AlreadyExists(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com"})
	uc := NewAdminInviteFamilyMemberUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail: "admin@test.com", Email: "a@test.com",
	})
	assert.ErrorContains(t, err, "already exists")
}

func TestAdminInviteFamilyMember_CreateError(t *testing.T) {
	t.Parallel()
	store := newMockUserStore()
	store.createErr = errors.New("db fail")
	uc := NewAdminInviteFamilyMemberUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail: "admin@test.com", Email: "new@test.com",
	})
	assert.ErrorContains(t, err, "invite family member")
}

// ===========================================================================
// Admin Remove Family Member
// ===========================================================================

func TestAdminRemoveFamilyMember_Success(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(
		&users.User{Email: "admin@test.com", Role: users.RoleAdmin, Status: users.StatusActive},
		&users.User{Email: "trader@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	)
	sess := &mockSessionTerminator{terminated: 1}
	uc := NewAdminRemoveFamilyMemberUseCase(store, sess, testLogger())
	n, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail: "admin@test.com", TargetEmail: "trader@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestAdminRemoveFamilyMember_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminRemoveFamilyMemberUseCase(newMockUserStore(), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{})
	assert.ErrorContains(t, err, "target_email is required")
}

func TestAdminRemoveFamilyMember_NotFound(t *testing.T) {
	t.Parallel()
	uc := NewAdminRemoveFamilyMemberUseCase(newMockUserStore(), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{TargetEmail: "no@test.com"})
	assert.ErrorContains(t, err, "user not found")
}

func TestAdminRemoveFamilyMember_LastAdmin(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "admin@test.com", Role: users.RoleAdmin, Status: users.StatusActive})
	uc := NewAdminRemoveFamilyMemberUseCase(store, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{TargetEmail: "admin@test.com"})
	assert.ErrorContains(t, err, "last active admin")
}

func TestAdminRemoveFamilyMember_UpdateStatusError(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Role: users.RoleTrader})
	store.updateStatusErr = errors.New("db fail")
	uc := NewAdminRemoveFamilyMemberUseCase(store, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{TargetEmail: "a@test.com"})
	assert.ErrorContains(t, err, "remove family member")
}

func TestAdminRemoveFamilyMember_NilSessions(t *testing.T) {
	t.Parallel()
	store := newMockUserStore(&users.User{Email: "a@test.com", Role: users.RoleTrader})
	uc := NewAdminRemoveFamilyMemberUseCase(store, nil, testLogger())
	n, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{TargetEmail: "a@test.com"})
	require.NoError(t, err)
	assert.Equal(t, 0, n)
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
