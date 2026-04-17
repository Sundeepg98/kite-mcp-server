package usecases

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// --- Mocks ---

type mockFamilyProvider struct {
	members      map[string][]*users.User // adminEmail -> members
	maxUsers     int
	removeErr    error
	removedPairs [][2]string // [admin, member]
}

func newMockFamilyProvider(maxUsers int) *mockFamilyProvider {
	return &mockFamilyProvider{
		members:  make(map[string][]*users.User),
		maxUsers: maxUsers,
	}
}

func (m *mockFamilyProvider) ListMembers(adminEmail string) []*users.User {
	return m.members[adminEmail]
}

func (m *mockFamilyProvider) CanInvite(adminEmail string) (bool, int, int) {
	current := len(m.members[adminEmail])
	return current < m.maxUsers, current, m.maxUsers
}

func (m *mockFamilyProvider) MaxUsers(adminEmail string) int { return m.maxUsers }

func (m *mockFamilyProvider) RemoveMember(adminEmail, memberEmail string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	list := m.members[adminEmail]
	for i, u := range list {
		if strings.EqualFold(u.Email, memberEmail) {
			m.members[adminEmail] = append(list[:i], list[i+1:]...)
			m.removedPairs = append(m.removedPairs, [2]string{adminEmail, memberEmail})
			return nil
		}
	}
	return errors.New("not a family member")
}

type mockInvitationWriter struct {
	created   []*users.FamilyInvitation
	createErr error
}

func (m *mockInvitationWriter) Create(inv *users.FamilyInvitation) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.created = append(m.created, inv)
	return nil
}

type mockInvitationReader struct {
	byAdmin map[string][]*users.FamilyInvitation
}

func newMockInvitationReader() *mockInvitationReader {
	return &mockInvitationReader{byAdmin: make(map[string][]*users.FamilyInvitation)}
}

func (m *mockInvitationReader) ListByAdmin(adminEmail string) []*users.FamilyInvitation {
	return m.byAdmin[adminEmail]
}

// ===========================================================================
// Admin List Family
// ===========================================================================

func TestAdminListFamily_Success(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	fp.members["admin@test.com"] = []*users.User{
		{Email: "m1@test.com", Role: users.RoleTrader, Status: users.StatusActive},
		{Email: "m2@test.com", Role: users.RoleTrader, Status: users.StatusActive},
	}
	uc := NewAdminListFamilyUseCase(fp, newMockInvitationReader(), testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminListFamilyQuery{
		AdminEmail: "admin@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "admin@test.com", result.AdminEmail)
	assert.Equal(t, 5, result.MaxUsers)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Members, 2)
}

func TestAdminListFamily_EmptyAdminEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminListFamilyUseCase(newMockFamilyProvider(5), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminListFamilyQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin_email is required")
}

func TestAdminListFamily_Pagination(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(10)
	fp.members["admin@test.com"] = []*users.User{
		{Email: "a@test.com"}, {Email: "b@test.com"}, {Email: "c@test.com"},
	}
	uc := NewAdminListFamilyUseCase(fp, nil, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminListFamilyQuery{
		AdminEmail: "admin@test.com",
		From:       1,
		Limit:      1,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, result.Total)
	require.Len(t, result.Members, 1)
	assert.Equal(t, "b@test.com", result.Members[0].Email)
}

func TestAdminListFamily_IncludesPendingInvitations(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	inv := newMockInvitationReader()
	inv.byAdmin["admin@test.com"] = []*users.FamilyInvitation{
		{ID: "inv_1", InvitedEmail: "new@test.com", Status: "pending", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "inv_2", InvitedEmail: "old@test.com", Status: "pending", ExpiresAt: time.Now().Add(-1 * time.Hour)}, // expired
		{ID: "inv_3", InvitedEmail: "acc@test.com", Status: "accepted", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}
	uc := NewAdminListFamilyUseCase(fp, inv, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminListFamilyQuery{AdminEmail: "admin@test.com"})
	require.NoError(t, err)
	require.Len(t, result.Pending, 1)
	assert.Equal(t, "inv_1", result.Pending[0].ID)
}

// ===========================================================================
// Admin Invite Family Member
// ===========================================================================

func TestAdminInviteFamilyMember_Success(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	inv := &mockInvitationWriter{}
	events := domain.NewEventDispatcher()
	uc := NewAdminInviteFamilyMemberUseCase(fp, inv, events, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "new@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "new@test.com", result.InvitedEmail)
	assert.Equal(t, 1, result.SlotsUsed)
	assert.Equal(t, 5, result.SlotsMax)
	require.Len(t, inv.created, 1)
	assert.Equal(t, "pending", inv.created[0].Status)
	assert.Equal(t, "admin@test.com", inv.created[0].AdminEmail)
}

func TestAdminInviteFamilyMember_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAdminInviteFamilyMemberUseCase(newMockFamilyProvider(5), &mockInvitationWriter{}, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{AdminEmail: "admin@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invited_email is required")
}

func TestAdminInviteFamilyMember_SelfInvite(t *testing.T) {
	t.Parallel()
	uc := NewAdminInviteFamilyMemberUseCase(newMockFamilyProvider(5), &mockInvitationWriter{}, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "ADMIN@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot invite yourself")
}

func TestAdminInviteFamilyMember_FamilyFull(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(2)
	fp.members["admin@test.com"] = []*users.User{
		{Email: "m1@test.com"}, {Email: "m2@test.com"},
	}
	uc := NewAdminInviteFamilyMemberUseCase(fp, &mockInvitationWriter{}, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "new@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "family is full")
}

func TestAdminInviteFamilyMember_AlreadyMember(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	fp.members["admin@test.com"] = []*users.User{{Email: "already@test.com"}}
	uc := NewAdminInviteFamilyMemberUseCase(fp, &mockInvitationWriter{}, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "already@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already in your family")
}

func TestAdminInviteFamilyMember_InvitationCreateError(t *testing.T) {
	t.Parallel()
	inv := &mockInvitationWriter{createErr: errors.New("db down")}
	uc := NewAdminInviteFamilyMemberUseCase(newMockFamilyProvider(5), inv, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "new@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create invitation")
}

func TestAdminInviteFamilyMember_DispatchesFamilyInvitedEvent(t *testing.T) {
	t.Parallel()
	events := domain.NewEventDispatcher()
	var captured domain.FamilyInvitedEvent
	seen := false
	events.Subscribe("family.invited", func(e domain.Event) {
		captured = e.(domain.FamilyInvitedEvent)
		seen = true
	})

	uc := NewAdminInviteFamilyMemberUseCase(newMockFamilyProvider(5), &mockInvitationWriter{}, events, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "new@test.com",
	})
	require.NoError(t, err)
	require.True(t, seen, "FamilyInvitedEvent should have been dispatched")
	assert.Equal(t, "admin@test.com", captured.AdminEmail)
	assert.Equal(t, "new@test.com", captured.InvitedEmail)
}

// ===========================================================================
// Admin Remove Family Member
// ===========================================================================

func TestAdminRemoveFamilyMember_Success(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	fp.members["admin@test.com"] = []*users.User{{Email: "bye@test.com"}}
	uc := NewAdminRemoveFamilyMemberUseCase(fp, nil, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail:  "admin@test.com",
		TargetEmail: "bye@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "bye@test.com", result.RemovedEmail)
	require.Len(t, fp.removedPairs, 1)
	assert.Equal(t, [2]string{"admin@test.com", "bye@test.com"}, fp.removedPairs[0])
}

func TestAdminRemoveFamilyMember_EmptyTarget(t *testing.T) {
	t.Parallel()
	uc := NewAdminRemoveFamilyMemberUseCase(newMockFamilyProvider(5), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{AdminEmail: "a@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target_email is required")
}

func TestAdminRemoveFamilyMember_SelfRemove(t *testing.T) {
	t.Parallel()
	uc := NewAdminRemoveFamilyMemberUseCase(newMockFamilyProvider(5), nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail:  "admin@test.com",
		TargetEmail: "ADMIN@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot remove yourself")
}

func TestAdminRemoveFamilyMember_ServiceError(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	fp.removeErr = errors.New("not in your family")
	uc := NewAdminRemoveFamilyMemberUseCase(fp, nil, testLogger())

	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail:  "admin@test.com",
		TargetEmail: "other@test.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove family member")
}

func TestAdminRemoveFamilyMember_DispatchesRemovedEvent(t *testing.T) {
	t.Parallel()
	fp := newMockFamilyProvider(5)
	fp.members["admin@test.com"] = []*users.User{{Email: "bye@test.com"}}
	events := domain.NewEventDispatcher()
	var captured domain.FamilyMemberRemovedEvent
	seen := false
	events.Subscribe("family.member_removed", func(e domain.Event) {
		captured = e.(domain.FamilyMemberRemovedEvent)
		seen = true
	})

	uc := NewAdminRemoveFamilyMemberUseCase(fp, events, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail:  "admin@test.com",
		TargetEmail: "bye@test.com",
	})
	require.NoError(t, err)
	require.True(t, seen, "FamilyMemberRemovedEvent should have been dispatched")
	assert.Equal(t, "admin@test.com", captured.AdminEmail)
	assert.Equal(t, "bye@test.com", captured.RemovedEmail)
}

// ===========================================================================
// Bus integration: end-to-end list → invite → remove via CommandBus/QueryBus
// ===========================================================================

func TestFamilyUseCases_BusIntegration_EndToEnd(t *testing.T) {
	t.Parallel()

	fp := newMockFamilyProvider(3)
	invWriter := &mockInvitationWriter{}
	invReader := newMockInvitationReader()
	events := domain.NewEventDispatcher()

	listUC := NewAdminListFamilyUseCase(fp, invReader, testLogger())
	inviteUC := NewAdminInviteFamilyMemberUseCase(fp, invWriter, events, testLogger())
	removeUC := NewAdminRemoveFamilyMemberUseCase(fp, events, testLogger())

	bus := cqrs.NewInMemoryBus()
	require.NoError(t, bus.Register(reflect.TypeOf(cqrs.AdminListFamilyQuery{}), func(ctx context.Context, msg any) (any, error) {
		return listUC.Execute(ctx, msg.(cqrs.AdminListFamilyQuery))
	}))
	require.NoError(t, bus.Register(reflect.TypeOf(cqrs.AdminInviteFamilyMemberCommand{}), func(ctx context.Context, msg any) (any, error) {
		return inviteUC.Execute(ctx, msg.(cqrs.AdminInviteFamilyMemberCommand))
	}))
	require.NoError(t, bus.Register(reflect.TypeOf(cqrs.AdminRemoveFamilyMemberCommand{}), func(ctx context.Context, msg any) (any, error) {
		return removeUC.Execute(ctx, msg.(cqrs.AdminRemoveFamilyMemberCommand))
	}))

	ctx := context.Background()

	// 1. List — empty family.
	listRaw, err := bus.DispatchWithResult(ctx, cqrs.AdminListFamilyQuery{AdminEmail: "admin@test.com"})
	require.NoError(t, err)
	listResult := listRaw.(*AdminListFamilyResult)
	assert.Equal(t, 0, listResult.Total)

	// 2. Invite one member.
	inviteRaw, err := bus.DispatchWithResult(ctx, cqrs.AdminInviteFamilyMemberCommand{
		AdminEmail:   "admin@test.com",
		InvitedEmail: "m1@test.com",
	})
	require.NoError(t, err)
	inviteResult := inviteRaw.(*AdminInviteFamilyMemberResult)
	assert.Equal(t, "m1@test.com", inviteResult.InvitedEmail)
	require.Len(t, invWriter.created, 1)

	// Simulate acceptance: add to the family provider's state.
	fp.members["admin@test.com"] = append(fp.members["admin@test.com"], &users.User{
		Email: "m1@test.com", Role: users.RoleTrader, Status: users.StatusActive,
	})

	// 3. List — now has one member.
	listRaw, err = bus.DispatchWithResult(ctx, cqrs.AdminListFamilyQuery{AdminEmail: "admin@test.com"})
	require.NoError(t, err)
	listResult = listRaw.(*AdminListFamilyResult)
	assert.Equal(t, 1, listResult.Total)

	// 4. Remove.
	removeRaw, err := bus.DispatchWithResult(ctx, cqrs.AdminRemoveFamilyMemberCommand{
		AdminEmail:  "admin@test.com",
		TargetEmail: "m1@test.com",
	})
	require.NoError(t, err)
	removeResult := removeRaw.(*AdminRemoveFamilyMemberResult)
	assert.Equal(t, "m1@test.com", removeResult.RemovedEmail)

	// 5. List — back to empty.
	listRaw, err = bus.DispatchWithResult(ctx, cqrs.AdminListFamilyQuery{AdminEmail: "admin@test.com"})
	require.NoError(t, err)
	listResult = listRaw.(*AdminListFamilyResult)
	assert.Equal(t, 0, listResult.Total)
}
