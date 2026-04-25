package domain

// family.go — Family aggregate carrying the rules around an admin's
// family-billing plan: capacity, membership, invite eligibility.
//
// Previously these rules lived on FamilyService.CanInvite / MemberCount /
// MaxUsers as service computations. Moving them onto a value object
// means any layer (REST, MCP tool, future SDK) consults the same rule
// without service indirection.

import (
	"fmt"
	"strings"
)

// Family represents an admin's family-billing membership state at a
// specific moment. Construct via NewFamily; the value type is immutable
// after construction so it's safe to pass through layers without
// defensive copying.
//
// AdminEmail is the lower-cased identity of the plan owner. CurrentSize
// is how many family members are currently linked. MaxSize is the cap
// from the admin's billing plan (1 for free / dev / no-plan).
type Family struct {
	adminEmail  string
	currentSize int
	maxSize     int
}

// NewFamily constructs a validated Family value. adminEmail must be
// non-empty (after trim+lower); currentSize and maxSize must be
// non-negative; maxSize must be >= 1 (every plan supports at least the
// admin themselves). Returns an error rather than panicking on bad
// input so callers can fail loudly.
func NewFamily(adminEmail string, currentSize, maxSize int) (Family, error) {
	trimmed := strings.ToLower(strings.TrimSpace(adminEmail))
	if trimmed == "" {
		return Family{}, fmt.Errorf("domain: family admin email must not be empty")
	}
	if currentSize < 0 {
		return Family{}, fmt.Errorf("domain: family currentSize must be >= 0, got %d", currentSize)
	}
	if maxSize < 1 {
		return Family{}, fmt.Errorf("domain: family maxSize must be >= 1, got %d", maxSize)
	}
	return Family{adminEmail: trimmed, currentSize: currentSize, maxSize: maxSize}, nil
}

// AdminEmail returns the lower-cased plan-owner email.
func (f Family) AdminEmail() string { return f.adminEmail }

// CurrentSize returns the number of currently-linked family members.
func (f Family) CurrentSize() int { return f.currentSize }

// MaxSize returns the plan's family-member cap.
func (f Family) MaxSize() int { return f.maxSize }

// AvailableSeats returns how many more family members can be added
// without breaching the plan cap. Always >= 0.
func (f Family) AvailableSeats() int {
	if f.currentSize >= f.maxSize {
		return 0
	}
	return f.maxSize - f.currentSize
}

// CanInvite reports whether the admin has room for one more family
// member. The canonical rule for invite eligibility — call sites should
// not re-derive this from MemberCount() < MaxUsers().
func (f Family) CanInvite() bool {
	return f.AvailableSeats() > 0
}

// IsAtCapacity reports whether the family has reached the plan limit.
// Equivalent to !CanInvite(); both names exist because call sites read
// more naturally one way or the other ("can we invite?" vs "are we full?").
func (f Family) IsAtCapacity() bool {
	return !f.CanInvite()
}

// IsMemberOf reports whether memberEmail belongs to this family. Email
// matching is case-insensitive.
func (f Family) IsMemberOf(memberEmail, candidateAdminEmail string) bool {
	return strings.EqualFold(candidateAdminEmail, f.adminEmail)
}