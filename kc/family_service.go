package kc

import (
	"fmt"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// FamilyUserStore is the narrow interface FamilyService needs from user store.
// ISP: only Get + ListByAdminEmail + SetAdminEmail.
type FamilyUserStore interface {
	Get(email string) (*users.User, bool)
	ListByAdminEmail(adminEmail string) []*users.User
	SetAdminEmail(email, adminEmail string) error
}

// FamilyService handles family billing operations — invite, remove, list, tier resolution.
// Extracts family logic from Manager to reduce god-object coupling.
type FamilyService struct {
	userStore       FamilyUserStore
	billingStore    BillingStoreInterface
	invitationStore *users.InvitationStore
}

// NewFamilyService creates a family service with the required stores.
func NewFamilyService(us FamilyUserStore, bs BillingStoreInterface, is *users.InvitationStore) *FamilyService {
	return &FamilyService{userStore: us, billingStore: bs, invitationStore: is}
}

// AdminEmailFn returns a function that resolves a user's admin email for tier inheritance.
func (f *FamilyService) AdminEmailFn() func(string) string {
	return func(email string) string {
		if f.userStore == nil {
			return ""
		}
		u, ok := f.userStore.Get(email)
		if !ok || u.AdminEmail == "" {
			return ""
		}
		return u.AdminEmail
	}
}

// ListMembers returns all users linked to this admin.
func (f *FamilyService) ListMembers(adminEmail string) []*users.User {
	if f.userStore == nil {
		return nil
	}
	return f.userStore.ListByAdminEmail(adminEmail)
}

// MemberCount returns how many family members are linked to this admin.
func (f *FamilyService) MemberCount(adminEmail string) int {
	return len(f.ListMembers(adminEmail))
}

// MaxUsers returns the max family members for this admin's plan.
func (f *FamilyService) MaxUsers(adminEmail string) int {
	if f.billingStore == nil {
		return 1
	}
	sub := f.billingStore.GetSubscription(adminEmail)
	if sub == nil || sub.MaxUsers < 1 {
		return 1
	}
	return sub.MaxUsers
}

// CanInvite checks if the admin has room for one more family member.
// Delegates the rule to domain.Family — the service is now a thin
// orchestrator that fetches counts and lifts them into the aggregate.
//
// Returns (canInvite, currentCount, maxCount). On any error constructing
// the aggregate (shouldn't happen for valid emails / non-negative counts)
// returns (false, current, max) so the caller sees a "no" answer rather
// than a misleading "yes".
func (f *FamilyService) CanInvite(adminEmail string) (bool, int, int) {
	current := f.MemberCount(adminEmail)
	max := f.MaxUsers(adminEmail)
	fam, err := domain.NewFamily(adminEmail, current, max)
	if err != nil {
		return false, current, max
	}
	return fam.CanInvite(), current, max
}

// RemoveMember unlinks a family member from the admin.
func (f *FamilyService) RemoveMember(adminEmail, memberEmail string) error {
	if f.userStore == nil {
		return fmt.Errorf("user store not available")
	}
	u, ok := f.userStore.Get(memberEmail)
	if !ok {
		return fmt.Errorf("user not found: %s", memberEmail)
	}
	if !strings.EqualFold(u.AdminEmail, adminEmail) {
		return fmt.Errorf("%s is not in your family", memberEmail)
	}
	return f.userStore.SetAdminEmail(memberEmail, "")
}
